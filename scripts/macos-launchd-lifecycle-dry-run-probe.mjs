import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);
const MACOS_HELPER_LABEL = 'de.frederikstadler.bitwarden-agent-credential-bridge.helper';
const MACOS_HELPER_ACCOUNT = '_bwagentbridge';
const MACOS_HELPER_BINARY_PATH = `/Library/PrivilegedHelperTools/${MACOS_HELPER_LABEL}`;
const PLIST_PATH = `/Library/LaunchDaemons/${MACOS_HELPER_LABEL}.plist`;
const PARENT_PATHS = ['/Library/PrivilegedHelperTools', '/Library/LaunchDaemons'];
const TOOL_ENV = Object.freeze({ PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' });
const MAX_DOMAIN_OUTPUT = 8 * 1024 * 1024;
const LABEL_ABSENT_STDERR = `Bad request.\nCould not find service "${MACOS_HELPER_LABEL}" in domain for system\n`;

if (process.argv.length !== 2 || process.platform !== 'darwin') process.exit(1);

try {
  const accountNameAbsent = await dsclSearchEmpty('RecordName', MACOS_HELPER_ACCOUNT);
  const identity = accountNameAbsent ? await selectUnusedIdentity() : failedIdentity();
  const plistAbsent = await isAbsent(PLIST_PATH);
  const binaryAbsent = await isAbsent(MACOS_HELPER_BINARY_PATH);
  const labelUnloaded = await isLabelUnloaded();
  const machServiceUnbound = labelUnloaded && await isMachServiceUnbound();
  const parentsSecure = await parentsAreSecure();
  const result = {
    schema_version: 1,
    account_name_absent: accountNameAbsent,
    account_uniqueid_candidate_available: identity.uniqueId,
    account_generateduid_candidate_available: identity.generatedUid,
    plist_absent: plistAbsent,
    binary_absent: binaryAbsent,
    launchd_label_unloaded: labelUnloaded,
    mach_service_unbound: machServiceUnbound,
    parent_directories_secure: parentsSecure,
    run_private_identity_selectable: accountNameAbsent && identity.uniqueId && identity.generatedUid,
    mutation_performed: false,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch {
  process.exitCode = 1;
}

async function selectUnusedIdentity() {
  let uniqueId = false;
  for (let candidate = 499; candidate >= 450; candidate -= 1) {
    if (await dsclSearchEmpty('UniqueID', String(candidate))) {
      uniqueId = true;
      break;
    }
  }
  const generatedUid = await dsclSearchEmpty('GeneratedUID', randomUUID().toUpperCase());
  return { uniqueId, generatedUid };
}

function failedIdentity() {
  return { uniqueId: false, generatedUid: false };
}

async function dsclSearchEmpty(attribute, value) {
  const result = await run('/usr/bin/dscl', ['.', '-search', '/Users', attribute, value], 5000, 4096);
  return result.stdout === '' && result.stderr === '';
}

async function isAbsent(target) {
  try {
    await fs.lstat(target);
    return false;
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
}

async function isLabelUnloaded() {
  try {
    await run('/bin/launchctl', ['print', `system/${MACOS_HELPER_LABEL}`], 5000, 1024 * 1024);
    return false;
  } catch (error) {
    return error?.code === 113 && error.stdout === '' && error.stderr === LABEL_ABSENT_STDERR;
  }
}

async function isMachServiceUnbound() {
  const result = await run('/bin/launchctl', ['print', 'system'], 10000, MAX_DOMAIN_OUTPUT);
  if (result.stderr !== '') throw new Error('noisy domain output');
  return !containsExactName(result.stdout, MACOS_HELPER_LABEL);
}

function containsExactName(stdout, name) {
  if (typeof stdout !== 'string' || stdout.length === 0) throw new Error('invalid domain output');
  let index = stdout.indexOf(name);
  while (index !== -1) {
    const before = index === 0 ? '' : stdout[index - 1];
    const after = stdout[index + name.length] ?? '';
    if (!/[A-Za-z0-9._-]/.test(before) && !/[A-Za-z0-9._-]/.test(after)) return true;
    index = stdout.indexOf(name, index + name.length);
  }
  return false;
}

async function parentsAreSecure() {
  if (process.geteuid() === 0) return false;
  for (const target of PARENT_PATHS) {
    let cursor = target;
    while (true) {
      const stat = await fs.lstat(cursor);
      if (stat.isSymbolicLink() || !stat.isDirectory() || stat.uid !== 0 ||
          (stat.mode & 0o022) !== 0 || await hasExtendedAcl(cursor)) {
        return false;
      }
      try {
        await fs.access(cursor, fsConstants.W_OK);
        return false;
      } catch {
        // Expected: the ordinary caller cannot write the system directory chain.
      }
      const parent = path.dirname(cursor);
      if (parent === cursor) break;
      cursor = parent;
    }
  }
  return true;
}

async function hasExtendedAcl(target) {
  try {
    const result = await run('/bin/ls', ['-lde', '--', target], 3000, 4096);
    if (result.stderr !== '') return true;
    const firstToken = result.stdout.trimStart().split(/\s+/, 1)[0] ?? '';
    return firstToken === '' || firstToken.endsWith('+');
  } catch {
    return true;
  }
}

async function run(executable, args, timeout, maxBuffer) {
  try {
    return await execFileAsync(executable, args, {
      timeout, maxBuffer, encoding: 'utf8', env: TOOL_ENV, windowsHide: true,
    });
  } catch (error) {
    if (error?.killed || error?.signal !== undefined && error.signal !== null) throw new Error('tool failed');
    throw error;
  }
}
