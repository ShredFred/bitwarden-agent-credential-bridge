import { spawn } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { types as utilTypes } from 'node:util';
import { fileURLToPath } from 'node:url';
import { buildMacosLaunchdLifecyclePackage } from './macos-launchd-lifecycle-package.mjs';
import { evaluateMacosLaunchdLifecycleTranscript } from './macos-launchd-lifecycle-evidence.mjs';

const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts',
  'macos-launchd-lifecycle-dry-run-probe.mjs',
);
const MAX_PROBE_SOURCE_BYTES = 64 * 1024;
const MAX_PROBE_OUTPUT_BYTES = 4096;
const BOOLEAN_FIELDS = Object.freeze([
  'account_name_absent',
  'account_uniqueid_candidate_available',
  'account_generateduid_candidate_available',
  'plist_absent',
  'binary_absent',
  'launchd_label_unloaded',
  'mach_service_unbound',
  'parent_directories_secure',
  'run_private_identity_selectable',
  'mutation_performed',
]);
const RESULT_FIELDS = new Set(['schema_version', ...BOOLEAN_FIELDS]);
const STEP_CHECKS = Object.freeze([
  () => true,
  (value) => value.account_name_absent && value.account_uniqueid_candidate_available &&
    value.account_generateduid_candidate_available,
  (value) => value.plist_absent,
  (value) => value.binary_absent,
  (value) => value.launchd_label_unloaded && value.mach_service_unbound,
  (value) => value.parent_directories_secure,
  (value) => value.run_private_identity_selectable,
]);

export class MacosLaunchdLifecycleDryRunError extends Error {
  constructor(code) {
    super(`macOS launchd lifecycle dry run failed: ${code}`);
    this.name = 'MacosLaunchdLifecycleDryRunError';
    this.code = code;
  }
}

/** Build/reverify the exact package, then inspect only fixed read-only host state. */
export async function runMacosLaunchdLifecycleDryRun() {
  if (arguments.length !== 0) throw new MacosLaunchdLifecycleDryRunError('input_forbidden');
  if (process.platform !== 'darwin') throw new MacosLaunchdLifecycleDryRunError('unsupported_platform');
  const packageValue = await buildMacosLaunchdLifecyclePackage();
  const probeSource = await readStableProbeSource();
  const raw = await executeProbe(probeSource);
  const checks = STEP_CHECKS.map((check) => check(raw));
  const firstFailure = checks.indexOf(false);
  const eventCount = firstFailure === -1 ? checks.length : firstFailure + 1;
  const transcript = {
    schema_version: 1,
    terminal_outcome: firstFailure === -1 ? 'dry_run_complete' : 'preflight_failed',
    events: packageValue.lifecycle_gate.pre_mutation_steps.slice(0, eventCount)
      .map((step, index) => ({ step, status: checks[index] ? 'verified' : 'failed' })),
  };
  const structural = evaluateMacosLaunchdLifecycleTranscript(packageValue.lifecycle_gate, transcript);
  return deepFreeze({
    schema_version: 1,
    package_binding_verified: true,
    account_absence_and_identity_space_verified: checks[1],
    plist_absence_verified: checks[2],
    binary_absence_verified: checks[3],
    launchd_label_and_mach_service_absence_verified: checks[4],
    parent_directory_policy_verified: checks[5],
    run_private_identity_selection_verified: checks[6],
    preflight_complete: firstFailure === -1,
    terminal_code: structural.terminal_code,
    mutation_performed: false,
    collector_trust_verified: false,
    live_test_verified: false,
    authorization_ready: false,
    install_gate_eligible: false,
  });
}

export function parseMacosLaunchdLifecycleDryRunProbe(stdout, stderr = '') {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr !== '' ||
      stdout.includes('\0') || Buffer.byteLength(stdout, 'utf8') > 4096) {
    throw new MacosLaunchdLifecycleDryRunError('invalid_probe_output');
  }
  let value;
  try { value = JSON.parse(stdout.trim()); } catch {
    throw new MacosLaunchdLifecycleDryRunError('invalid_probe_output');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== RESULT_FIELDS.size ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !RESULT_FIELDS.has(key)) ||
      value.schema_version !== 1 || BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean') ||
      value.mutation_performed !== false ||
      value.run_private_identity_selectable !== (value.account_name_absent &&
        value.account_uniqueid_candidate_available && value.account_generateduid_candidate_available) ||
      value.mach_service_unbound && !value.launchd_label_unloaded) {
    throw new MacosLaunchdLifecycleDryRunError('invalid_probe_output');
  }
  return Object.freeze({ ...value });
}

async function readStableProbeSource() {
  let handle;
  try {
    handle = await fs.open(SCRIPT_PATH, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o022) !== 0 ||
        before.size < 1 || before.size > MAX_PROBE_SOURCE_BYTES) {
      throw new MacosLaunchdLifecycleDryRunError('unsafe_probe_source');
    }
    const bytes = await handle.readFile();
    const middle = await handle.stat();
    const second = Buffer.allocUnsafe(before.size);
    const reread = await handle.read(second, 0, second.length, 0);
    const after = await handle.stat();
    if (bytes.length !== before.size || reread.bytesRead !== before.size ||
        !sameIdentity(before, middle) || !sameIdentity(middle, after) ||
        !timingSafeEqual(
          createHash('sha256').update(bytes).digest(),
          createHash('sha256').update(second).digest(),
        )) {
      throw new MacosLaunchdLifecycleDryRunError('probe_source_changed');
    }
    return bytes;
  } catch (error) {
    if (error instanceof MacosLaunchdLifecycleDryRunError) throw error;
    throw new MacosLaunchdLifecycleDryRunError('unsafe_probe_source');
  } finally {
    if (handle !== undefined) {
      try { await handle.close(); } catch {
        throw new MacosLaunchdLifecycleDryRunError('probe_source_close_failed');
      }
    }
  }
}

function executeProbe(sourceBytes) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-'], {
      cwd: '/',
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const timer = setTimeout(() => fail('probe_timeout_or_terminated'), 30000);
    const fail = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill('SIGKILL');
      reject(new MacosLaunchdLifecycleDryRunError(code));
    };
    child.on('error', () => fail('probe_failed'));
    child.stdin.on('error', () => fail('probe_failed'));
    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_PROBE_OUTPUT_BYTES) fail('probe_output_too_large');
      else stdout.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_PROBE_OUTPUT_BYTES) fail('probe_output_too_large');
      else stderr.push(chunk);
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0 || signal !== null) {
        reject(new MacosLaunchdLifecycleDryRunError('probe_failed'));
        return;
      }
      try {
        resolve(parseMacosLaunchdLifecycleDryRunProbe(
          Buffer.concat(stdout).toString('utf8'), Buffer.concat(stderr).toString('utf8'),
        ));
      } catch (error) {
        reject(error);
      }
    });
    child.stdin.end(sourceBytes);
  });
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function deepFreeze(value) {
  for (const nested of Object.values(value)) {
    if (nested !== null && typeof nested === 'object') deepFreeze(nested);
  }
  return Object.freeze(value);
}
