import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify, types as utilTypes } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const SOURCE_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)), '..', 'native', 'macos-mach-denial-probe.c',
);
const BUILD_PREFIX = 'bw-agent-mach-denial-';
const BINARY_NAME = 'probe';
const SHA256 = /^[0-9a-f]{64}$/;
const BOOLEAN_FIELDS = Object.freeze([
  'mach_service_bound',
  'launchd_system_service_verified',
  'mach_peer_exchange_verified',
  'request_audit_trailer_verified',
  'request_sender_matches_spawned_caller',
  'request_sender_pid_verified',
  'request_sender_pidversion_verified',
  'reply_audit_trailer_verified',
  'reply_sender_matches_expected_helper',
  'reply_sender_pid_verified',
  'reply_sender_pidversion_verified',
  'caller_euid_verified',
  'helper_euid_verified',
  'same_euid',
  'helper_code_requirement_satisfied',
  'manifest_request_sent',
  'manifest_executor_absent',
  'authorization_denied',
  'install_gate_eligible',
]);
const RESULT_FIELDS = new Set([
  'schema_version', 'transport_kind', ...BOOLEAN_FIELDS,
  'caller_euid_sha256', 'helper_euid_sha256',
]);
const REQUIRED_TRUE = Object.freeze([
  'mach_peer_exchange_verified',
  'request_audit_trailer_verified',
  'request_sender_matches_spawned_caller',
  'request_sender_pid_verified',
  'request_sender_pidversion_verified',
  'reply_audit_trailer_verified',
  'reply_sender_matches_expected_helper',
  'reply_sender_pid_verified',
  'reply_sender_pidversion_verified',
  'caller_euid_verified',
  'helper_euid_verified',
  'same_euid',
  'manifest_executor_absent',
  'authorization_denied',
]);
const REQUIRED_FALSE = Object.freeze([
  'mach_service_bound',
  'launchd_system_service_verified',
  'helper_code_requirement_satisfied',
  'manifest_request_sent',
  'install_gate_eligible',
]);
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C',
});

export class MacosMachDenialSessionError extends Error {
  constructor(code) {
    super(`macOS Mach denial session failed: ${code}`);
    this.name = 'MacosMachDenialSessionError';
    this.code = code;
  }
}

/** Compile and run one same-EUID, no-manifest Mach audit-trailer denial probe. */
export async function runMacosMachDenialSession() {
  if (process.platform !== 'darwin') throw new MacosMachDenialSessionError('unsupported_platform');
  const base = path.resolve(os.tmpdir());
  let root;
  let binary;
  try {
    root = await fs.mkdtemp(path.join(base, BUILD_PREFIX));
    await requirePrivateBuildRoot(root, base);
    binary = path.join(root, BINARY_NAME);
    await execute('/usr/bin/clang', [
      '-std=c17', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-O2',
      SOURCE_PATH, '-lbsm', '-o', binary,
    ], 15000, 64 * 1024);
    const binaryStat = await fs.lstat(binary);
    if (!binaryStat.isFile() || binaryStat.isSymbolicLink() ||
        binaryStat.uid !== process.geteuid() || (binaryStat.mode & 0o022) !== 0) {
      throw new MacosMachDenialSessionError('unsafe_compiler_output');
    }
    const output = await execute(binary, [], 5000, 4096);
    return parseMacosMachDenialResult(output.stdout, output.stderr);
  } finally {
    let cleanupFailed = false;
    if (binary !== undefined) {
      try { await fs.unlink(binary); } catch (error) { if (error?.code !== 'ENOENT') cleanupFailed = true; }
    }
    if (root !== undefined) {
      try { await fs.rmdir(root); } catch { cleanupFailed = true; }
    }
    if (cleanupFailed) throw new MacosMachDenialSessionError('cleanup_failed');
  }
}

export function parseMacosMachDenialResult(stdout, stderr = '') {
  if (process.platform !== 'darwin' || typeof process.geteuid !== 'function') {
    throw new MacosMachDenialSessionError('unsupported_platform');
  }
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr !== '') {
    throw new MacosMachDenialSessionError('invalid_output');
  }
  let value;
  try { value = JSON.parse(stdout.trim()); } catch { throw new MacosMachDenialSessionError('invalid_output'); }
  if (value === null || typeof value !== 'object' || Array.isArray(value) || utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== RESULT_FIELDS.size ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !RESULT_FIELDS.has(key)) ||
      value.schema_version !== 1 || value.transport_kind !== 'macos_mach_message_console' ||
      BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean') ||
      !SHA256.test(value.caller_euid_sha256) || !SHA256.test(value.helper_euid_sha256) ||
      REQUIRED_TRUE.some((field) => value[field] !== true) ||
      REQUIRED_FALSE.some((field) => value[field] !== false) ||
      !safeDigestEqual(value.caller_euid_sha256, value.helper_euid_sha256) ||
      !safeDigestEqual(value.caller_euid_sha256, expectedEuidDigest()) ||
      !safeDigestEqual(value.helper_euid_sha256, expectedEuidDigest())) {
    throw new MacosMachDenialSessionError('invalid_output');
  }
  return Object.freeze({ ...value });
}

async function requirePrivateBuildRoot(root, base) {
  const resolved = path.resolve(root);
  const stat = await fs.lstat(resolved);
  if (path.dirname(resolved) !== base || !path.basename(resolved).startsWith(BUILD_PREFIX) ||
      !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o700) {
    throw new MacosMachDenialSessionError('unsafe_build_root');
  }
}

async function execute(executable, args, timeout, maxBuffer) {
  try {
    return await execFileAsync(executable, args, {
      timeout, maxBuffer, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    throw new MacosMachDenialSessionError(error?.killed ? 'timeout_or_terminated' : 'process_failed');
  }
}

function safeDigestEqual(left, right) {
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function expectedEuidDigest() {
  return createHash('sha256').update(`euid:${process.geteuid()}`, 'utf8').digest('hex');
}
