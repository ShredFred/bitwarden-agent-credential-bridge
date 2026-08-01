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
  path.dirname(fileURLToPath(import.meta.url)), '..', 'native', 'macos-launchd-denial-helper.c',
);
const BUILD_PREFIX = 'bw-agent-launchd-helper-';
const BINARY_NAME = 'helper';
const SOURCE_NAME = 'source.c';
const MAX_BINARY_BYTES = 4 * 1024 * 1024;
const NATIVE_BOOLEAN_FIELDS = Object.freeze([
  'platform_darwin',
  'fixed_account_self_check_compiled',
  'fixed_mach_service_compiled',
  'launchd_checkin_entrypoint_compiled',
  'audit_trailer_request_verification_compiled',
  'send_once_denial_reply_compiled',
  'bounded_messages_compiled',
  'launchd_lifecycle_live_verified',
  'distinct_euid_live_verified',
  'helper_code_requirement_live_verified',
  'manifest_executor_absent',
  'network_stack_absent',
  'keychain_client_absent',
  'vault_client_absent',
  'install_gate_eligible',
]);
const NATIVE_FIELDS = new Set(['schema_version', ...NATIVE_BOOLEAN_FIELDS]);
const REQUIRED_TRUE = Object.freeze([
  'platform_darwin',
  'fixed_account_self_check_compiled',
  'fixed_mach_service_compiled',
  'launchd_checkin_entrypoint_compiled',
  'audit_trailer_request_verification_compiled',
  'send_once_denial_reply_compiled',
  'bounded_messages_compiled',
  'manifest_executor_absent',
  'network_stack_absent',
  'keychain_client_absent',
  'vault_client_absent',
]);
const REQUIRED_FALSE = Object.freeze([
  'launchd_lifecycle_live_verified',
  'distinct_euid_live_verified',
  'helper_code_requirement_live_verified',
  'install_gate_eligible',
]);
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C',
});

export class MacosNativeLaunchdHelperError extends Error {
  constructor(code) {
    super(`macOS native launchd helper failed: ${code}`);
    this.name = 'MacosNativeLaunchdHelperError';
    this.code = code;
  }
}

/** Build twice, self-test once, and prove no-arg execution fails outside launchd. */
export async function inspectMacosNativeLaunchdHelperScaffold() {
  if (process.platform !== 'darwin') throw new MacosNativeLaunchdHelperError('unsupported_platform');
  const sourceBytes = await readSafeSourceSnapshot();
  let base;
  try { base = await fs.realpath(os.tmpdir()); } catch {
    throw new MacosNativeLaunchdHelperError('unsafe_temp_root');
  }
  const builds = [];
  try {
    builds.push(await compileOne(base, sourceBytes));
    builds.push(await compileOne(base, sourceBytes));
    if (!safeDigestEqual(builds[0].digest, builds[1].digest)) {
      throw new MacosNativeLaunchdHelperError('non_reproducible_build');
    }
    const selfTest = await executeSuccess(builds[0].binary, ['--self-test'], 5000, 4096);
    const native = parseMacosNativeLaunchdHelperSelfTest(selfTest.stdout, selfTest.stderr);
    await requireOutsideLaunchdRejection(builds[0].binary);
    return Object.freeze({
      ...native,
      same_host_reproducible_build_verified: true,
      source_snapshot_bound: true,
      outside_launchd_rejected: true,
      private_temp_cleanup_required: true,
      collector_trust_verified: false,
      live_test_verified: false,
      authorization_ready: false,
    });
  } finally {
    let cleanupFailed = false;
    for (const build of builds.reverse()) {
      try { await fs.unlink(build.binary); } catch (error) {
        if (error?.code !== 'ENOENT') cleanupFailed = true;
      }
      try { await fs.unlink(build.source); } catch (error) {
        if (error?.code !== 'ENOENT') cleanupFailed = true;
      }
      try { await fs.rmdir(build.root); } catch { cleanupFailed = true; }
    }
    if (cleanupFailed) throw new MacosNativeLaunchdHelperError('cleanup_failed');
  }
}

export function parseMacosNativeLaunchdHelperSelfTest(stdout, stderr = '') {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr !== '') {
    throw new MacosNativeLaunchdHelperError('invalid_output');
  }
  let value;
  try { value = JSON.parse(stdout.trim()); } catch {
    throw new MacosNativeLaunchdHelperError('invalid_output');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== NATIVE_FIELDS.size ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !NATIVE_FIELDS.has(key)) ||
      value.schema_version !== 1 ||
      NATIVE_BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean') ||
      REQUIRED_TRUE.some((field) => value[field] !== true) ||
      REQUIRED_FALSE.some((field) => value[field] !== false)) {
    throw new MacosNativeLaunchdHelperError('invalid_output');
  }
  return Object.freeze({ ...value });
}

async function compileOne(base, sourceBytes) {
  let root;
  try { root = await fs.mkdtemp(path.join(base, BUILD_PREFIX)); } catch {
    throw new MacosNativeLaunchdHelperError('build_root_create_failed');
  }
  let binary;
  let source;
  try {
    await requirePrivateBuildRoot(root, base);
    source = path.join(root, SOURCE_NAME);
    const sourceHandle = await fs.open(
      source,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
      0o400,
    );
    try {
      await sourceHandle.writeFile(sourceBytes);
      await sourceHandle.sync();
    } finally {
      await sourceHandle.close();
    }
    const sourceStat = await fs.lstat(source);
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink() || sourceStat.uid !== process.geteuid() ||
        (sourceStat.mode & 0o777) !== 0o400 || sourceStat.size !== sourceBytes.length) {
      throw new MacosNativeLaunchdHelperError('unsafe_source_snapshot');
    }
    binary = path.join(root, BINARY_NAME);
    await executeSuccess('/usr/bin/clang', [
      '-std=c17', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
      '-O2', '-fno-ident', source, '-lbsm', '-o', binary,
    ], 15000, 64 * 1024);
    const stat = await fs.lstat(binary);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
        (stat.mode & 0o022) !== 0 || stat.size < 1 || stat.size > MAX_BINARY_BYTES) {
      throw new MacosNativeLaunchdHelperError('unsafe_compiler_output');
    }
    const bytes = await fs.readFile(binary);
    if (bytes.length !== stat.size) throw new MacosNativeLaunchdHelperError('binary_changed');
    return {
      root,
      binary,
      source,
      digest: createHash('sha256').update(bytes).digest('hex'),
    };
  } catch (error) {
    let cleanupFailed = false;
    if (binary !== undefined) {
      try { await fs.unlink(binary); } catch (cleanupError) {
        if (cleanupError?.code !== 'ENOENT') cleanupFailed = true;
      }
    }
    if (source !== undefined) {
      try { await fs.unlink(source); } catch (cleanupError) {
        if (cleanupError?.code !== 'ENOENT') cleanupFailed = true;
      }
    }
    try { await fs.rmdir(root); } catch { cleanupFailed = true; }
    if (cleanupFailed) throw new MacosNativeLaunchdHelperError('cleanup_failed');
    if (error instanceof MacosNativeLaunchdHelperError) throw error;
    throw new MacosNativeLaunchdHelperError('build_failed');
  }
}

async function readSafeSourceSnapshot() {
  let handle;
  try {
    handle = await fs.open(SOURCE_PATH, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o022) !== 0 ||
        before.size < 1 || before.size > 256 * 1024) {
      throw new MacosNativeLaunchdHelperError('unsafe_source');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new MacosNativeLaunchdHelperError('source_changed');
    }
    return bytes;
  } catch (error) {
    if (error instanceof MacosNativeLaunchdHelperError) throw error;
    throw new MacosNativeLaunchdHelperError('unsafe_source');
  } finally {
    if (handle !== undefined) {
      try { await handle.close(); } catch {
        throw new MacosNativeLaunchdHelperError('source_close_failed');
      }
    }
  }
}

async function requirePrivateBuildRoot(root, base) {
  const resolved = path.resolve(root);
  const stat = await fs.lstat(resolved);
  if (path.dirname(resolved) !== base || !path.basename(resolved).startsWith(BUILD_PREFIX) ||
      !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o700) {
    throw new MacosNativeLaunchdHelperError('unsafe_build_root');
  }
}

async function requireOutsideLaunchdRejection(binary) {
  try {
    await execFileAsync(binary, [], {
      timeout: 7000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    if (!error?.killed && [3, 4, 5].includes(error?.code) &&
        error.stdout === '' && error.stderr === '') return;
    throw new MacosNativeLaunchdHelperError(
      error?.killed ? 'timeout_or_terminated' : 'outside_launchd_contract_failed',
    );
  }
  throw new MacosNativeLaunchdHelperError('outside_launchd_contract_failed');
}

async function executeSuccess(executable, args, timeout, maxBuffer) {
  try {
    return await execFileAsync(executable, args, {
      timeout, maxBuffer, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    throw new MacosNativeLaunchdHelperError(error?.killed ? 'timeout_or_terminated' : 'process_failed');
  }
}

function safeDigestEqual(left, right) {
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}
