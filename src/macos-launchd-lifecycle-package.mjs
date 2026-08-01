import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { buildMacosLaunchdBoundaryPlan, isMacosLaunchdBoundaryPlan } from './macos-launchd-boundary-plan.mjs';
import {
  digestDesignatedRequirementStdout,
  evaluateMacosLaunchdPlist,
  MACOS_HELPER_ACCOUNT,
  MACOS_HELPER_BINARY_PATH,
  MACOS_HELPER_LABEL,
} from './macos-launchd-boundary-rules.mjs';
import { buildMacosLaunchdLifecycleGate, isMacosLaunchdLifecycleGate } from './macos-launchd-lifecycle-gate.mjs';
import { parseMacosNativeLaunchdHelperSelfTest } from './macos-native-launchd-helper.mjs';
import { verifyMacosCodeSnapshot } from './macos-code-snapshot-verifier.mjs';

const execFileAsync = promisify(execFile);
const SOURCE_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)), '..', 'native', 'macos-launchd-denial-helper.c',
);
const BUILD_PREFIX = 'bw-agent-launchd-package-';
const SOURCE_NAME = 'source.c';
const BINARY_NAME = 'helper';
const PLIST_NAME = 'helper.plist';
const MAX_BINARY_BYTES = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES = 256 * 1024;
const MAX_TOOL_OUTPUT = 64 * 1024;
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C',
});
const PLIST_TEXT = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${MACOS_HELPER_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${MACOS_HELPER_BINARY_PATH}</string>
  </array>
  <key>UserName</key>
  <string>${MACOS_HELPER_ACCOUNT}</string>
  <key>MachServices</key>
  <dict>
    <key>${MACOS_HELPER_LABEL}</key>
    <true/>
  </dict>
</dict>
</plist>
`;
const PLIST_BYTES = Buffer.from(PLIST_TEXT, 'utf8');
const VALID_PACKAGES = new WeakSet();
const PACKAGE_BYTES = new WeakMap();

export class MacosLaunchdLifecyclePackageError extends Error {
  constructor(code) {
    super(`macOS launchd lifecycle package failed: ${code}`);
    this.name = 'MacosLaunchdLifecyclePackageError';
    this.code = code;
  }
}

/**
 * Build an exact signed helper/plist package in private temp roots. This accepts
 * no input and performs no installation, elevation, account, or launchd work.
 */
export async function buildMacosLaunchdLifecyclePackage() {
  if (process.platform !== 'darwin') {
    throw new MacosLaunchdLifecyclePackageError('unsupported_platform');
  }
  const sourceBytes = await readStableSource();
  let tempBase;
  try { tempBase = await fs.realpath(os.tmpdir()); } catch {
    throw new MacosLaunchdLifecyclePackageError('unsafe_temp_root');
  }
  const builds = [];
  try {
    builds.push(await buildOne(tempBase, sourceBytes));
    builds.push(await buildOne(tempBase, sourceBytes));
    requireMatchingBuilds(builds[0], builds[1]);

    const binarySha256 = sha256(builds[0].binaryBytes);
    const requirementSha256 = digestDesignatedRequirementStdout(builds[0].requirementRecord);
    if (requirementSha256 === null) {
      throw new MacosLaunchdLifecyclePackageError('invalid_requirement_record');
    }
    const plistSha256 = sha256(PLIST_BYTES);
    const plan = buildMacosLaunchdBoundaryPlan({
      platform: 'darwin',
      serviceManager: 'launchd-system',
      binarySha256,
      binaryByteLength: builds[0].binaryBytes.length,
      designatedRequirementSha256: requirementSha256,
      plistSha256,
    });
    const gate = buildMacosLaunchdLifecycleGate(plan);
    const packageValue = deepFreeze({
      schema_version: 1,
      platform: 'darwin',
      artifact_bindings: {
        binary_sha256: binarySha256,
        binary_byte_length: builds[0].binaryBytes.length,
        designated_requirement_sha256: requirementSha256,
        plist_sha256: plistSha256,
      },
      boundary_plan: plan,
      lifecycle_gate: gate,
      fixed_plist_contract_verified: true,
      native_self_test_verified: true,
      ad_hoc_hardened_runtime_signature_verified: true,
      fd_content_code_snapshot_verified: true,
      same_host_reproducible_build_verified: true,
      source_snapshot_bound: true,
      private_temp_cleanup_required: true,
      ready_for_explicit_lifecycle_review: true,
      mutation_authorized: false,
      collector_trust_verified: false,
      live_test_verified: false,
      authorization_ready: false,
      install_gate_eligible: false,
    });
    VALID_PACKAGES.add(packageValue);
    PACKAGE_BYTES.set(packageValue, {
      binary: Buffer.from(builds[0].binaryBytes),
      plist: Buffer.from(PLIST_BYTES),
    });
    return packageValue;
  } finally {
    let cleanupFailed = false;
    for (const build of builds.reverse()) {
      for (const target of [build.binaryPath, build.sourcePath, build.plistPath]) {
        try { await fs.unlink(target); } catch (error) {
          if (error?.code !== 'ENOENT') cleanupFailed = true;
        }
      }
      try { await fs.rmdir(build.root); } catch { cleanupFailed = true; }
    }
    if (cleanupFailed) throw new MacosLaunchdLifecyclePackageError('cleanup_failed');
  }
}

export function isMacosLaunchdLifecyclePackage(value) {
  return value !== null && typeof value === 'object' && VALID_PACKAGES.has(value);
}

/** Return fresh copies; artifact bytes are data, never mutation authority. */
export function copyMacosLaunchdLifecyclePackageArtifacts(packageValue) {
  if (!isMacosLaunchdLifecyclePackage(packageValue)) {
    throw new MacosLaunchdLifecyclePackageError('invalid_package');
  }
  const bytes = PACKAGE_BYTES.get(packageValue);
  if (bytes === undefined) throw new MacosLaunchdLifecyclePackageError('invalid_package');
  return Object.freeze({
    binary: Buffer.from(bytes.binary),
    plist: Buffer.from(bytes.plist),
  });
}

async function buildOne(tempBase, sourceBytes) {
  let root;
  try { root = await fs.mkdtemp(path.join(tempBase, BUILD_PREFIX)); } catch {
    throw new MacosLaunchdLifecyclePackageError('build_root_create_failed');
  }
  const sourcePath = path.join(root, SOURCE_NAME);
  const binaryPath = path.join(root, BINARY_NAME);
  const plistPath = path.join(root, PLIST_NAME);
  try {
    await requirePrivateRoot(root, tempBase);
    await publishExactFile(sourcePath, sourceBytes, 0o400);
    await publishExactFile(plistPath, PLIST_BYTES, 0o400);
    await requirePlistLint(plistPath);
    await executeSilent('/usr/bin/clang', [
      '-std=c17', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
      '-O2', '-fno-ident', '-Wl,-no_adhoc_codesign', sourcePath, '-lbsm', '-o', binaryPath,
    ], 15000);
    await executeSilent('/usr/bin/codesign', [
      '--force', '--sign', '-', '--identifier', MACOS_HELPER_LABEL,
      '--timestamp=none', '--options', 'runtime', '--', binaryPath,
    ], 15000);
    await executeSilent('/usr/bin/codesign', [
      '--verify', '--strict', '--verbose=0', '--', binaryPath,
    ], 5000);
    const requirement = await execute('/usr/bin/codesign', ['-d', '-r-', '--', binaryPath], 5000);
    if (requirement.stderr !== `Executable=${binaryPath}\n` ||
        digestDesignatedRequirementStdout(requirement.stdout) === null) {
      throw new MacosLaunchdLifecyclePackageError('invalid_requirement_output');
    }
    const binaryBytes = await readStableOutput(binaryPath);
    const requirementSha256 = digestDesignatedRequirementStdout(requirement.stdout);
    if (requirementSha256 === null ||
        !await verifyMacosCodeSnapshot(binaryBytes, requirementSha256)) {
      throw new MacosLaunchdLifecyclePackageError('fd_content_code_verification_failed');
    }
    const selfTest = await execute(binaryPath, ['--self-test'], 5000, 4096);
    parseMacosNativeLaunchdHelperSelfTest(selfTest.stdout, selfTest.stderr);
    await requireOutsideLaunchdRejection(binaryPath);
    return {
      root,
      sourcePath,
      binaryPath,
      plistPath,
      binaryBytes,
      requirementRecord: requirement.stdout,
    };
  } catch (error) {
    let cleanupFailed = false;
    for (const target of [binaryPath, sourcePath, plistPath]) {
      try { await fs.unlink(target); } catch (cleanupError) {
        if (cleanupError?.code !== 'ENOENT') cleanupFailed = true;
      }
    }
    try { await fs.rmdir(root); } catch { cleanupFailed = true; }
    if (cleanupFailed) throw new MacosLaunchdLifecyclePackageError('cleanup_failed');
    if (error instanceof MacosLaunchdLifecyclePackageError) throw error;
    throw new MacosLaunchdLifecyclePackageError('build_failed');
  }
}

async function readStableSource() {
  let handle;
  try {
    handle = await fs.open(SOURCE_PATH, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o022) !== 0 ||
        before.size < 1 || before.size > MAX_SOURCE_BYTES) {
      throw new MacosLaunchdLifecyclePackageError('unsafe_source');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || !sameIdentity(before, after)) {
      throw new MacosLaunchdLifecyclePackageError('source_changed');
    }
    return bytes;
  } catch (error) {
    if (error instanceof MacosLaunchdLifecyclePackageError) throw error;
    throw new MacosLaunchdLifecyclePackageError('unsafe_source');
  } finally {
    if (handle !== undefined) {
      try { await handle.close(); } catch {
        throw new MacosLaunchdLifecyclePackageError('source_close_failed');
      }
    }
  }
}

async function publishExactFile(target, bytes, mode) {
  let handle;
  try {
    handle = await fs.open(
      target,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
      mode,
    );
    await handle.writeFile(bytes);
    await handle.sync();
  } catch {
    throw new MacosLaunchdLifecyclePackageError('artifact_publish_failed');
  } finally {
    if (handle !== undefined) {
      try { await handle.close(); } catch {
        throw new MacosLaunchdLifecyclePackageError('artifact_close_failed');
      }
    }
  }
  const stat = await fs.lstat(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== mode || stat.size !== bytes.length) {
    throw new MacosLaunchdLifecyclePackageError('unsafe_published_artifact');
  }
}

async function readStableOutput(binaryPath) {
  let handle;
  try {
    handle = await fs.open(binaryPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = await handle.stat();
    const pathStat = await fs.lstat(binaryPath);
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o022) !== 0 ||
        before.size < 1 || before.size > MAX_BINARY_BYTES || !sameIdentity(before, pathStat)) {
      throw new MacosLaunchdLifecyclePackageError('unsafe_compiler_output');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || !sameIdentity(before, after)) {
      throw new MacosLaunchdLifecyclePackageError('binary_changed');
    }
    return bytes;
  } catch (error) {
    if (error instanceof MacosLaunchdLifecyclePackageError) throw error;
    throw new MacosLaunchdLifecyclePackageError('unsafe_compiler_output');
  } finally {
    if (handle !== undefined) {
      try { await handle.close(); } catch {
        throw new MacosLaunchdLifecyclePackageError('binary_close_failed');
      }
    }
  }
}

async function requirePrivateRoot(root, tempBase) {
  const resolved = path.resolve(root);
  const stat = await fs.lstat(resolved);
  if (path.dirname(resolved) !== tempBase || !path.basename(resolved).startsWith(BUILD_PREFIX) ||
      !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o700) {
    throw new MacosLaunchdLifecyclePackageError('unsafe_build_root');
  }
}

async function requirePlistLint(plistPath) {
  const result = await execute('/usr/bin/plutil', ['-lint', '--', plistPath], 5000, 4096);
  if (result.stderr !== '' || result.stdout !== `${plistPath}: OK\n`) {
    throw new MacosLaunchdLifecyclePackageError('plist_lint_failed');
  }
  const rules = evaluateMacosLaunchdPlist({
    Label: MACOS_HELPER_LABEL,
    ProgramArguments: [MACOS_HELPER_BINARY_PATH],
    UserName: MACOS_HELPER_ACCOUNT,
    MachServices: { [MACOS_HELPER_LABEL]: true },
  });
  if (!rules.system_domain_plist || !rules.demand_activation_only || !rules.mach_service_declared) {
    throw new MacosLaunchdLifecyclePackageError('plist_contract_failed');
  }
}

async function requireOutsideLaunchdRejection(binaryPath) {
  try {
    await execFileAsync(binaryPath, [], {
      timeout: 7000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    if (!error?.killed && [3, 4, 5].includes(error?.code) &&
        error.stdout === '' && error.stderr === '') return;
    throw new MacosLaunchdLifecyclePackageError(
      error?.killed ? 'timeout_or_terminated' : 'outside_launchd_contract_failed',
    );
  }
  throw new MacosLaunchdLifecyclePackageError('outside_launchd_contract_failed');
}

function requireMatchingBuilds(left, right) {
  if (!safeBufferEqual(left.binaryBytes, right.binaryBytes) ||
      left.requirementRecord !== right.requirementRecord) {
    throw new MacosLaunchdLifecyclePackageError('non_reproducible_build');
  }
}

async function executeSilent(executable, args, timeout) {
  const result = await execute(executable, args, timeout);
  if (result.stdout !== '' || result.stderr !== '') {
    throw new MacosLaunchdLifecyclePackageError('unexpected_tool_output');
  }
  return result;
}

async function execute(executable, args, timeout, maxBuffer = MAX_TOOL_OUTPUT) {
  try {
    return await execFileAsync(executable, args, {
      timeout, maxBuffer, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    throw new MacosLaunchdLifecyclePackageError(
      error?.killed ? 'timeout_or_terminated' : 'process_failed',
    );
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function safeBufferEqual(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function packageInternalsAreBranded(packageValue) {
  return isMacosLaunchdLifecyclePackage(packageValue) &&
    isMacosLaunchdBoundaryPlan(packageValue.boundary_plan) &&
    isMacosLaunchdLifecycleGate(packageValue.lifecycle_gate);
}
