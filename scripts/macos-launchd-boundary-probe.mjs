import { execFile, spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import { createHash, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import {
  digestDesignatedRequirementStdout,
  evaluateMacosLaunchdPlist,
  MACOS_HELPER_ACCOUNT,
  MACOS_HELPER_BINARY_PATH,
  MACOS_HELPER_LABEL,
} from '../src/macos-launchd-boundary-rules.mjs';

const execFileAsync = promisify(execFile);
const LABEL = MACOS_HELPER_LABEL;
const ACCOUNT = MACOS_HELPER_ACCOUNT;
const PLIST_PATH = `/Library/LaunchDaemons/${LABEL}.plist`;
const BINARY_PATH = MACOS_HELPER_BINARY_PATH;
const MAX_BINARY_BYTES = 64 * 1024 * 1024;
const MAX_PLIST_BYTES = 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES = 64 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const ABSENT = Object.freeze({
  schema_version: 1,
  service_present: false,
  account_static_helper: false,
  system_domain_plist: false,
  plist_binding_verified: false,
  demand_activation_only: false,
  mach_service_declared: false,
  binary_binding_verified: false,
  designated_requirement_path_snapshot_matches_plan: false,
  designated_requirement_verified: false,
  binary_chain_symlink_free: false,
  plist_chain_symlink_free: false,
  binary_and_plist_owner_trusted: false,
  caller_plist_and_binary_control_denied: false,
  snapshot_matches_plan: false,
  authorization_ready: false,
});
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  LANG: 'C',
  LC_ALL: 'C',
});

try {
  const [expectedSha256, rawLength, expectedRequirementSha256, expectedPlistSha256, ...extra] = process.argv.slice(2);
  const expectedLength = Number(rawLength);
  if (extra.length !== 0 || !SHA256.test(expectedSha256 ?? '') ||
      !SHA256.test(expectedRequirementSha256 ?? '') || !SHA256.test(expectedPlistSha256 ?? '') ||
      !Number.isSafeInteger(expectedLength) ||
      expectedLength < 1 || expectedLength > MAX_BINARY_BYTES) {
    throw new Error('invalid input');
  }

  const plistStat = await safeLstat(PLIST_PATH);
  if (plistStat === null) {
    process.stdout.write(`${JSON.stringify(ABSENT)}\n`);
    process.exitCode = 0;
  } else {
    if (!plistStat.isFile() || plistStat.isSymbolicLink()) throw new Error('unsafe plist');

    const plistInspection = await inspectPlist(expectedPlistSha256);
    const plist = plistInspection.value;
    const plistRules = evaluateMacosLaunchdPlist(plist);
    const systemDomainPlist = plistRules.system_domain_plist;
    const demandActivationOnly = plistRules.demand_activation_only;
    const machServiceDeclared = plistRules.mach_service_declared;
    const accountStaticHelper = await inspectAccount();

    const binaryStat = await safeLstat(BINARY_PATH);
    let binaryBindingVerified = false;
    let designatedRequirementPathSnapshotMatchesPlan = false;
    const designatedRequirementVerified = false;
    let binaryChainSymlinkFree = false;
    let binaryOwnerTrusted = false;
    let callerBinaryControlDenied = false;
    if (binaryStat !== null && binaryStat.isFile() && !binaryStat.isSymbolicLink()) {
      const binary = await inspectBinaryAndRequirement(
        expectedSha256, expectedLength, expectedRequirementSha256,
      );
      binaryBindingVerified = binary.binding;
      designatedRequirementPathSnapshotMatchesPlan = binary.requirementPathSnapshot;
      binaryChainSymlinkFree = binary.chain.symlinkFree;
      binaryOwnerTrusted = binary.chain.ownerTrusted;
      callerBinaryControlDenied = binary.chain.callerControlDenied;
    }

    const plistChain = plistInspection.chain;
    const binaryAndPlistOwnerTrusted = binaryOwnerTrusted && plistChain.ownerTrusted;
    const callerPlistAndBinaryControlDenied = callerBinaryControlDenied &&
      plistChain.callerControlDenied;
    const result = {
      schema_version: 1,
      service_present: true,
      account_static_helper: accountStaticHelper,
      system_domain_plist: systemDomainPlist,
      plist_binding_verified: plistInspection.binding,
      demand_activation_only: demandActivationOnly,
      mach_service_declared: machServiceDeclared,
      binary_binding_verified: binaryBindingVerified,
      designated_requirement_path_snapshot_matches_plan: designatedRequirementPathSnapshotMatchesPlan,
      designated_requirement_verified: designatedRequirementVerified,
      binary_chain_symlink_free: binaryChainSymlinkFree,
      plist_chain_symlink_free: plistChain.symlinkFree,
      binary_and_plist_owner_trusted: binaryAndPlistOwnerTrusted,
      caller_plist_and_binary_control_denied: callerPlistAndBinaryControlDenied,
      snapshot_matches_plan: false,
      authorization_ready: false,
    };
    result.snapshot_matches_plan = Object.entries(result)
      .filter(([key]) => !['schema_version', 'snapshot_matches_plan', 'authorization_ready'].includes(key))
      .every(([, value]) => value === true);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 0;
  }
} catch {
  process.exitCode = 1;
}

async function safeLstat(target) {
  try {
    return await fs.lstat(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function inspectPlist(expectedSha256) {
  const noFollow = requireNoFollow();
  const handle = await fs.open(PLIST_PATH, fsConstants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > MAX_PLIST_BYTES) throw new Error('invalid plist');
    const bytes = await readHandleBytes(handle, before.size);
    const { stdout } = await runToolWithFd('/usr/bin/plutil', [
      '-convert', 'json', '-o', '-', '--', '/dev/fd/3',
    ], handle.fd);
    const chain = await inspectChain(PLIST_PATH);
    const after = await handle.stat();
    const pathAfter = await fs.lstat(PLIST_PATH);
    const secondBytes = await readHandleBytes(handle, after.size);
    if (!sameIdentity(before, after) || !sameIdentity(after, pathAfter) ||
        !safeDigestEqual(
          createHash('sha256').update(bytes).digest('hex'),
          createHash('sha256').update(secondBytes).digest('hex'),
        )) throw new Error('plist changed');
    const value = JSON.parse(stdout);
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid plist');
    const actual = createHash('sha256').update(bytes).digest('hex');
    return { value, binding: safeDigestEqual(actual, expectedSha256), chain };
  } finally {
    await handle.close();
  }
}

async function inspectAccount() {
  try {
    const { stdout } = await runTool('/usr/bin/dscl', [
      '.', '-read', `/Users/${ACCOUNT}`, 'UniqueID', 'UserShell', 'NFSHomeDirectory',
    ]);
    const fields = parseDscl(stdout);
    const uid = Number(fields.UniqueID);
    return Number.isSafeInteger(uid) && uid > 0 && uid !== process.geteuid() && uid < 500 &&
      ['/usr/bin/false', '/usr/bin/nologin'].includes(fields.UserShell) &&
      fields.NFSHomeDirectory === '/var/empty';
  } catch {
    return false;
  }
}

function parseDscl(stdout) {
  const result = Object.create(null);
  for (const line of stdout.trim().split('\n')) {
    const match = /^(NFSHomeDirectory|UniqueID|UserShell): (\S+)$/.exec(line);
    if (match === null || Object.hasOwn(result, match[1])) throw new Error('invalid account output');
    result[match[1]] = match[2];
  }
  if (Reflect.ownKeys(result).length !== 3) throw new Error('invalid account output');
  return result;
}

async function inspectBinaryAndRequirement(expectedSha256, expectedLength, expectedRequirementSha256) {
  const flags = fsConstants.O_RDONLY | requireNoFollow();
  const handle = await fs.open(BINARY_PATH, flags);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > MAX_BINARY_BYTES) {
      return { binding: false, requirementPathSnapshot: false, chain: failedChain() };
    }
    const firstBytes = await readHandleBytes(handle, before.size);
    const firstDigest = createHash('sha256').update(firstBytes).digest('hex');
    const binding = before.size === expectedLength && safeDigestEqual(firstDigest, expectedSha256);
    const requirementPathSnapshot = await inspectDesignatedRequirement(expectedRequirementSha256);
    const chain = await inspectChain(BINARY_PATH);
    const after = await handle.stat();
    const pathAfter = await fs.lstat(BINARY_PATH);
    const secondBytes = await readHandleBytes(handle, after.size);
    const secondDigest = createHash('sha256').update(secondBytes).digest('hex');
    const stable = sameIdentity(before, after) && sameIdentity(after, pathAfter) &&
      secondBytes.byteLength === after.size && safeDigestEqual(firstDigest, secondDigest);
    return {
      binding: binding && stable,
      requirementPathSnapshot: requirementPathSnapshot && stable,
      chain: stable ? chain : failedChain(),
    };
  } finally {
    await handle.close();
  }
}

async function inspectDesignatedRequirement(expectedSha256) {
  try {
    await runTool('/usr/bin/codesign', ['--verify', '--strict', '--verbose=0', '--', BINARY_PATH]);
    const { stdout } = await runTool('/usr/bin/codesign', ['-d', '-r-', '--', BINARY_PATH]);
    const digest = digestDesignatedRequirementStdout(stdout);
    if (digest === null) return false;
    return safeDigestEqual(digest, expectedSha256);
  } catch {
    return false;
  }
}

async function inspectChain(target) {
  let cursor = target;
  let symlinkFree = true;
  let ownerTrusted = true;
  let callerControlDenied = process.geteuid() !== 0;
  while (true) {
    const stat = await fs.lstat(cursor);
    if (stat.isSymbolicLink()) symlinkFree = false;
    if (stat.uid !== 0 || (stat.mode & 0o022) !== 0 || await hasExtendedAcl(cursor)) ownerTrusted = false;
    try {
      await fs.access(cursor, fsConstants.W_OK);
      callerControlDenied = false;
    } catch {
      // Expected for a caller-nonwritable chain.
    }
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return { symlinkFree, ownerTrusted, callerControlDenied };
}

async function hasExtendedAcl(target) {
  try {
    const { stdout } = await runTool('/bin/ls', ['-lde', '--', target]);
    const firstToken = stdout.trimStart().split(/\s+/, 1)[0] ?? '';
    return firstToken.endsWith('+');
  } catch {
    return true;
  }
}

async function runTool(executable, args) {
  const result = await execFileAsync(executable, args, {
    timeout: 3000,
    maxBuffer: MAX_TOOL_OUTPUT_BYTES,
    encoding: 'utf8',
    env: TOOL_ENV,
  });
  return { stdout: result.stdout, stderr: result.stderr };
}

function runToolWithFd(executable, args, fd) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      stdio: ['ignore', 'pipe', 'pipe', fd],
      env: TOOL_ENV,
    });
    let stdout = '';
    let stderr = '';
    let size = 0;
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      size += Buffer.byteLength(chunk, 'utf8');
      if (size > MAX_TOOL_OUTPUT_BYTES) child.kill('SIGKILL');
      else stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      size += Buffer.byteLength(chunk, 'utf8');
      if (size > MAX_TOOL_OUTPUT_BYTES) child.kill('SIGKILL');
      else stderr += chunk;
    });
    child.once('error', () => {
      clearTimeout(timer);
      reject(new Error('tool failed'));
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (code !== 0 || signal !== null || size > MAX_TOOL_OUTPUT_BYTES) reject(new Error('tool failed'));
      else resolve({ stdout, stderr });
    });
  });
}

async function readHandleBytes(handle, size) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_BINARY_BYTES) throw new Error('invalid size');
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await handle.read(bytes, offset, size - offset, offset);
    if (result.bytesRead === 0) throw new Error('short read');
    offset += result.bytesRead;
  }
  return bytes;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function failedChain() {
  return { symlinkFree: false, ownerTrusted: false, callerControlDenied: false };
}

function requireNoFollow() {
  if (!Number.isInteger(fsConstants.O_NOFOLLOW) || fsConstants.O_NOFOLLOW === 0) {
    throw new Error('unsupported nofollow');
  }
  return fsConstants.O_NOFOLLOW;
}

function safeDigestEqual(left, right) {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}
