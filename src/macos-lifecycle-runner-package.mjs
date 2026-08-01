import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  buildMacosLaunchdLifecyclePackage,
  copyMacosLaunchdLifecyclePackageArtifacts,
  isMacosLaunchdLifecyclePackage,
} from './macos-launchd-lifecycle-package.mjs';
import { digestDesignatedRequirementStdout } from './macos-launchd-boundary-rules.mjs';
import { verifyMacosCodeSnapshot } from './macos-code-snapshot-verifier.mjs';

const execFileAsync = promisify(execFile);
const NATIVE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'native');
const PREFIX = 'bw-agent-runner-package-';
const HEADER = 'reviewed-artifacts.h';
const RUNNER = 'lifecycle-runner';
const RUNNER_IDENTIFIER = 'de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-runner';
const MAX_SOURCE_BYTES = 512 * 1024;
const MAX_RUNNER_BYTES = 8 * 1024 * 1024;
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C',
});
const C_SOURCES = Object.freeze([
  'macos-fixed-command-runner.c', 'macos-retained-file-ops.c', 'macos-account-ownership.c',
  'macos-launchd-job-ownership.c', 'macos-dscl-directory-adapter.c',
  'macos-launchctl-job-adapter.c', 'macos-lifecycle-controller.c',
  'macos-lifecycle-approval.c', 'macos-native-lifecycle-wiring.c',
  'macos-launchctl-mach-presence.c', 'macos-mach-service-probes.c',
  'macos-fixed-system-probes.c', 'macos-lifecycle-runner.c',
]);
const HEADERS = Object.freeze([
  'macos-fixed-command-runner.h', 'macos-retained-file-ops.h', 'macos-account-ownership.h',
  'macos-launchd-job-ownership.h', 'macos-dscl-directory-adapter.h',
  'macos-launchctl-job-adapter.h', 'macos-lifecycle-controller.h',
  'macos-lifecycle-approval.h', 'macos-native-lifecycle-wiring.h',
  'macos-launchctl-mach-presence.h', 'macos-mach-service-probes.h',
  'macos-fixed-system-probes.h',
]);
const SNAPSHOT_NAMES = Object.freeze([...C_SOURCES, ...HEADERS]);
const VALID_PACKAGES = new WeakSet();
const PACKAGE_BYTES = new WeakMap();

export class MacosLifecycleRunnerPackageError extends Error {
  constructor(code) {
    super(`macOS lifecycle runner package failed: ${code}`);
    this.name = 'MacosLifecycleRunnerPackageError';
    this.code = code;
  }
}

export async function buildMacosLifecycleRunnerPackage() {
  if (process.platform !== 'darwin') throw new MacosLifecycleRunnerPackageError('unsupported_platform');
  const lifecyclePackage = await buildMacosLaunchdLifecyclePackage();
  if (!isMacosLaunchdLifecyclePackage(lifecyclePackage)) {
    throw new MacosLifecycleRunnerPackageError('invalid_lifecycle_package');
  }
  const artifacts = copyMacosLaunchdLifecyclePackageArtifacts(lifecyclePackage);
  if (sha256(artifacts.binary) !== lifecyclePackage.artifact_bindings.binary_sha256 ||
      artifacts.binary.length !== lifecyclePackage.artifact_bindings.binary_byte_length ||
      sha256(artifacts.plist) !== lifecyclePackage.artifact_bindings.plist_sha256 ||
      !await verifyMacosCodeSnapshot(
        artifacts.binary,
        lifecyclePackage.artifact_bindings.designated_requirement_sha256,
      )) {
    throw new MacosLifecycleRunnerPackageError('lifecycle_artifact_binding_mismatch');
  }
  const snapshots = await readSourceSnapshots();
  const generatedHeader = Buffer.from(buildArtifactHeader(
    artifacts.binary,
    artifacts.plist,
    lifecyclePackage.artifact_bindings,
  ), 'utf8');
  let tempBase;
  try { tempBase = await fs.realpath(os.tmpdir()); } catch {
    throw new MacosLifecycleRunnerPackageError('unsafe_temp_root');
  }
  const builds = [];
  try {
    builds.push(await buildOne(tempBase, snapshots, generatedHeader));
    builds.push(await buildOne(tempBase, snapshots, generatedHeader));
    if (!safeEqual(builds[0].bytes, builds[1].bytes) ||
        builds[0].requirement !== builds[1].requirement) {
      throw new MacosLifecycleRunnerPackageError('non_reproducible_runner');
    }
    const runnerSha256 = sha256(builds[0].bytes);
    const runnerRequirementSha256 = digestDesignatedRequirementStdout(builds[0].requirement);
    if (runnerRequirementSha256 === null ||
        !await verifyMacosCodeSnapshot(builds[0].bytes, runnerRequirementSha256)) {
      throw new MacosLifecycleRunnerPackageError('runner_code_snapshot_failed');
    }
    const binding = lifecyclePackage.artifact_bindings;
    const requirementBytes = Buffer.from(binding.designated_requirement_sha256, 'hex');
    const embeddedFailure = await embeddedSectionFailure(builds[0].path, builds[0].bytes, {
      helper: artifacts.binary, plist: artifacts.plist, requirement: requirementBytes,
    });
    if (embeddedFailure !== null) {
      throw new MacosLifecycleRunnerPackageError(`embedded_section_${embeddedFailure}`);
    }
    if (!containsBytes(builds[0].bytes, Buffer.from(binding.binary_sha256, 'ascii')) ||
        !containsBytes(builds[0].bytes, Buffer.from(binding.plist_sha256, 'ascii')) ||
        !containsBytes(builds[0].bytes, Buffer.from(binding.designated_requirement_sha256, 'ascii'))) {
      throw new MacosLifecycleRunnerPackageError('embedded_digest_verification_failed');
    }
    const value = deepFreeze({
      schema_version: 1,
      platform: 'darwin',
      runner_bindings: {
        sha256: runnerSha256,
        byte_length: builds[0].bytes.length,
        designated_requirement_sha256: runnerRequirementSha256,
      },
      lifecycle_bindings: lifecyclePackage.artifact_bindings,
      lifecycle_package: lifecyclePackage,
      source_snapshot_bound: false,
      stable_source_files_verified: true,
      embedded_artifacts_verified: true,
      same_host_reproducible_runner_verified: true,
      runner_code_snapshot_verified: true,
      ambient_execution_rejected: true,
      private_temp_cleanup_required: true,
      mutation_authorized: false,
      live_test_verified: false,
      install_gate_eligible: false,
    });
    VALID_PACKAGES.add(value);
    PACKAGE_BYTES.set(value, {
      runner: Buffer.from(builds[0].bytes),
      helper: Buffer.from(artifacts.binary),
      plist: Buffer.from(artifacts.plist),
    });
    return value;
  } finally {
    let failed = false;
    for (const build of builds.reverse()) {
      for (const target of build.targets.reverse()) {
        try { await fs.unlink(target); } catch (error) {
          if (error?.code !== 'ENOENT') failed = true;
        }
      }
      try { await fs.rmdir(build.root); } catch { failed = true; }
    }
    if (failed) throw new MacosLifecycleRunnerPackageError('cleanup_failed');
  }
}

export function isMacosLifecycleRunnerPackage(value) {
  return value !== null && typeof value === 'object' && VALID_PACKAGES.has(value);
}

export function copyMacosLifecycleRunnerPackageArtifacts(value) {
  if (!isMacosLifecycleRunnerPackage(value)) {
    throw new MacosLifecycleRunnerPackageError('invalid_package');
  }
  const bytes = PACKAGE_BYTES.get(value);
  if (bytes === undefined) throw new MacosLifecycleRunnerPackageError('invalid_package');
  return Object.freeze({
    runner: Buffer.from(bytes.runner), helper: Buffer.from(bytes.helper), plist: Buffer.from(bytes.plist),
  });
}

async function readSourceSnapshots() {
  const result = new Map();
  const opened = new Map();
  try {
    for (const name of SNAPSHOT_NAMES) {
      const source = path.join(NATIVE, name);
      const handle = await fs.open(source, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      opened.set(name, { source, handle, before: null });
      const before = await handle.stat();
      const pathStat = await fs.lstat(source);
      if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o022) !== 0 ||
          before.size < 1 || before.size > MAX_SOURCE_BYTES || !sameIdentity(before, pathStat)) {
        throw new MacosLifecycleRunnerPackageError('unsafe_source');
      }
      opened.get(name).before = before;
    }
    for (const [name, entry] of opened) {
      const bytes = await entry.handle.readFile();
      result.set(name, bytes);
    }
    for (const [name, entry] of opened) {
      const bytes = result.get(name);
      const after = await entry.handle.stat();
      const pathStat = await fs.lstat(entry.source);
      if (bytes === undefined || bytes.length !== entry.before.size ||
          !sameIdentity(entry.before, after) || !sameIdentity(after, pathStat)) {
        throw new MacosLifecycleRunnerPackageError('source_tree_changed');
      }
    }
    return result;
  } finally {
    let closeFailed = false;
    for (const entry of opened.values()) {
      try { await entry.handle.close(); } catch { closeFailed = true; }
    }
    if (closeFailed) throw new MacosLifecycleRunnerPackageError('source_close_failed');
  }
}

async function buildOne(tempBase, snapshots, generatedHeader) {
  let root;
  try { root = await fs.mkdtemp(path.join(tempBase, PREFIX)); } catch {
    throw new MacosLifecycleRunnerPackageError('build_root_create_failed');
  }
  const targets = [];
  try {
    await requirePrivateRoot(root, tempBase);
    for (const [name, bytes] of snapshots) {
      const target = path.join(root, name);
      await publish(target, bytes, 0o400);
      targets.push(target);
    }
    const headerPath = path.join(root, HEADER);
    await publish(headerPath, generatedHeader, 0o400);
    targets.push(headerPath);
    const runnerPath = path.join(root, RUNNER);
    targets.push(runnerPath);
    await executeSilent('/usr/bin/clang', [
      '-std=c17', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-O2',
      '-fno-ident', '-Wl,-no_adhoc_codesign', `-DBW_RUNNER_ARTIFACT_HEADER=\"${HEADER}\"`,
      '-I', root, ...C_SOURCES.map((name) => path.join(root, name)), '-lbsm', '-o', runnerPath,
    ], 30000);
    await executeSilent('/usr/bin/codesign', [
      '--force', '--sign', '-', '--identifier', RUNNER_IDENTIFIER,
      '--timestamp=none', '--options', 'runtime', '--', runnerPath,
    ], 15000);
    await executeSilent('/usr/bin/codesign', ['--verify', '--strict', '--verbose=0', '--', runnerPath], 5000);
    const requirement = await execute('/usr/bin/codesign', ['-d', '-r-', '--', runnerPath], 5000);
    if (requirement.stderr !== `Executable=${runnerPath}\n` ||
        digestDesignatedRequirementStdout(requirement.stdout) === null) {
      throw new MacosLifecycleRunnerPackageError('invalid_requirement_output');
    }
    const bytes = await stableOutput(runnerPath);
    await requireAmbientRejection(runnerPath);
    await requireUnelevatedModeRejection(runnerPath);
    return { root, targets, path: runnerPath, bytes, requirement: requirement.stdout };
  } catch (error) {
    let failed = false;
    for (const target of targets.reverse()) {
      try { await fs.unlink(target); } catch (cleanupError) {
        if (cleanupError?.code !== 'ENOENT') failed = true;
      }
    }
    try { await fs.rmdir(root); } catch { failed = true; }
    if (failed) throw new MacosLifecycleRunnerPackageError('cleanup_failed');
    if (error instanceof MacosLifecycleRunnerPackageError) throw error;
    throw new MacosLifecycleRunnerPackageError('build_failed');
  }
}

function buildArtifactHeader(helper, plist, bindings) {
  const requirement = Buffer.from(bindings.designated_requirement_sha256, 'hex');
  if (requirement.length !== 32) throw new MacosLifecycleRunnerPackageError('invalid_bindings');
  return `#ifndef BW_GENERATED_RUNNER_ARTIFACTS_H\n#define BW_GENERATED_RUNNER_ARTIFACTS_H\n` +
    `__attribute__((used, section("__DATA_CONST,__bwhelper")))\n` +
    `static const unsigned char BW_RUNNER_HELPER_BYTES[] = {${byteList(helper)}};\n` +
    `__attribute__((used, section("__DATA_CONST,__bwplist")))\n` +
    `static const unsigned char BW_RUNNER_PLIST_BYTES[] = {${byteList(plist)}};\n` +
    `#define BW_RUNNER_HELPER_LENGTH (sizeof(BW_RUNNER_HELPER_BYTES))\n` +
    `#define BW_RUNNER_PLIST_LENGTH (sizeof(BW_RUNNER_PLIST_BYTES))\n` +
    `#define BW_RUNNER_BINARY_SHA256_HEX "${bindings.binary_sha256}"\n` +
    `#define BW_RUNNER_PLIST_SHA256_HEX "${bindings.plist_sha256}"\n` +
    `#define BW_RUNNER_REQUIREMENT_SHA256_HEX "${bindings.designated_requirement_sha256}"\n` +
    `__attribute__((used, section("__DATA_CONST,__bwreq")))\n` +
    `static const unsigned char BW_RUNNER_REQUIREMENT_SHA256[BW_APPROVAL_DIGEST_BYTES] = {${byteList(requirement)}};\n` +
    `#endif\n`;
}

function byteList(bytes) {
  return [...bytes].map((value) => `0x${value.toString(16).padStart(2, '0')}`).join(',');
}

async function publish(target, bytes, mode) {
  let handle;
  try {
    handle = await fs.open(target,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
      mode);
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    if (handle !== undefined) await handle.close();
  }
  const stat = await fs.lstat(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== mode || stat.size !== bytes.length) {
    throw new MacosLifecycleRunnerPackageError('unsafe_published_source');
  }
}

async function stableOutput(target) {
  let handle;
  try {
    handle = await fs.open(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = await handle.stat();
    const pathStat = await fs.lstat(target);
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o022) !== 0 ||
        before.size < 1 || before.size > MAX_RUNNER_BYTES || !sameIdentity(before, pathStat)) {
      throw new MacosLifecycleRunnerPackageError('unsafe_runner_output');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || !sameIdentity(before, after)) {
      throw new MacosLifecycleRunnerPackageError('runner_changed');
    }
    return bytes;
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function requireAmbientRejection(runnerPath) {
  try {
    await execFileAsync(runnerPath, [], {
      timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    if (!error?.killed && error?.code === 64 && error.stdout === '' && error.stderr === '') return;
    throw new MacosLifecycleRunnerPackageError('ambient_execution_contract_failed');
  }
  throw new MacosLifecycleRunnerPackageError('ambient_execution_contract_failed');
}

async function requireUnelevatedModeRejection(runnerPath) {
  try {
    await execFileAsync(runnerPath, ['--approved-denial-lifecycle'], {
      timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    if (!error?.killed && error?.code === 77 && error.stdout === '' && error.stderr === '') return;
    throw new MacosLifecycleRunnerPackageError('unelevated_mode_contract_failed');
  }
  throw new MacosLifecycleRunnerPackageError('unelevated_mode_contract_failed');
}

async function requirePrivateRoot(root, tempBase) {
  const stat = await fs.lstat(root);
  if (path.dirname(root) !== tempBase || !path.basename(root).startsWith(PREFIX) ||
      !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o700) throw new MacosLifecycleRunnerPackageError('unsafe_build_root');
}

async function executeSilent(executable, args, timeout) {
  const result = await execute(executable, args, timeout);
  if (result.stdout !== '' || result.stderr !== '') {
    throw new MacosLifecycleRunnerPackageError('unexpected_tool_output');
  }
}

async function execute(executable, args, timeout) {
  try {
    return await execFileAsync(executable, args, {
      timeout, maxBuffer: 64 * 1024, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    throw new MacosLifecycleRunnerPackageError(error?.killed ? 'timeout_or_terminated' : 'process_failed');
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function safeEqual(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}
function containsBytes(container, wanted) {
  return wanted.length > 0 && wanted.length <= container.length && container.indexOf(wanted) >= 0;
}

async function embeddedSectionFailure(runnerPath, runnerBytes, expected) {
  const result = await execute('/usr/bin/otool', ['-l', runnerPath], 5000);
  if (result.stderr !== '') return 'tool_output';
  const sections = parseSections(result.stdout);
  for (const [name, wanted] of Object.entries(expected)) {
    const section = sections.get(`__bw${name === 'requirement' ? 'req' : name}`);
    if (section === undefined || !['__DATA', '__DATA_CONST'].includes(section.segment) ||
        section.size !== wanted.length ||
        section.offset < 0 || section.offset + section.size > runnerBytes.length ||
        !safeEqual(runnerBytes.subarray(section.offset, section.offset + section.size), wanted)) {
      return name;
    }
  }
  return null;
}

function parseSections(stdout) {
  const sections = new Map();
  let current = null;
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === 'Section') {
      if (current?.name !== undefined) sections.set(current.name, current);
      current = {};
      continue;
    }
    if (current === null) continue;
    const [key, value] = trimmed.split(/\s+/, 2);
    if (key === 'sectname') current.name = value;
    else if (key === 'segname') current.segment = value;
    else if (key === 'size') current.size = Number.parseInt(value, 16);
    else if (key === 'offset') current.offset = Number.parseInt(value, 10);
  }
  if (current?.name !== undefined) sections.set(current.name, current);
  return sections;
}
function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
