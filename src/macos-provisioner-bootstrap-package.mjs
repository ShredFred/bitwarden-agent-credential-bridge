import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import {
  buildMacosLifecycleRunnerPackage,
  copyMacosLifecycleRunnerPackageArtifacts,
  isMacosLifecycleRunnerPackage,
} from './macos-lifecycle-runner-package.mjs';

const execFileAsync = promisify(execFile);
const PREFIX = 'bw-agent-bootstrap-package-';
const IDENTIFIER = 'de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-provisioner';
const VERSION = '0.1.0';
const PAYLOAD_PATH = 'Library/PrivilegedHelperTools/' + IDENTIFIER;
const MAX_PACKAGE_BYTES = 16 * 1024 * 1024;
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C', COPYFILE_DISABLE: '1',
});
const VALID_PACKAGES = new WeakSet();
const PACKAGE_BYTES = new WeakMap();

export class MacosProvisionerBootstrapPackageError extends Error {
  constructor(code) {
    super(`macOS provisioner bootstrap package failed: ${code}`);
    this.name = 'MacosProvisionerBootstrapPackageError';
    this.code = code;
  }
}

export async function buildMacosProvisionerBootstrapPackage() {
  if (process.platform !== 'darwin') {
    throw new MacosProvisionerBootstrapPackageError('unsupported_platform');
  }
  const lifecyclePackage = await buildMacosLifecycleRunnerPackage();
  if (!isMacosLifecycleRunnerPackage(lifecyclePackage)) {
    throw new MacosProvisionerBootstrapPackageError('invalid_lifecycle_package');
  }
  const lifecycleArtifacts = copyMacosLifecycleRunnerPackageArtifacts(lifecyclePackage);
  if (sha256(lifecycleArtifacts.provisioner) !== lifecyclePackage.provisioner_bindings.sha256 ||
      lifecycleArtifacts.provisioner.length !== lifecyclePackage.provisioner_bindings.byte_length) {
    throw new MacosProvisionerBootstrapPackageError('provisioner_binding_mismatch');
  }
  let tempBase;
  try { tempBase = await fs.realpath(os.tmpdir()); } catch {
    throw new MacosProvisionerBootstrapPackageError('unsafe_temp_root');
  }
  const builds = [];
  let primaryError;
  let value;
  let selectedBytes;
  try {
    builds.push(await buildOne(tempBase, lifecycleArtifacts.provisioner));
    builds.push(await buildOne(tempBase, lifecycleArtifacts.provisioner));
    if (!safeEqual(builds[0].payload, builds[1].payload) ||
        builds[0].bom !== builds[1].bom ||
        builds[0].packageInfo !== builds[1].packageInfo ||
        builds[0].payloadFiles !== builds[1].payloadFiles) {
      throw new MacosProvisionerBootstrapPackageError('non_reproducible_payload');
    }
    value = deepFreeze({
      schema_version: 1,
      platform: 'darwin',
      package_identifier: IDENTIFIER,
      package_version: VERSION,
      install_location: '/',
      payload_path: `/${PAYLOAD_PATH}`,
      provisioner_bindings: lifecyclePackage.provisioner_bindings,
      payload_exactly_verified: true,
      payload_metadata_verified: true,
      payload_same_host_reproducible: true,
      scripts_absent_verified: true,
      archive_metadata_bounded_verified: true,
      recommended_root_wheel_ownership_verified: true,
      package_container_sha256: sha256(builds[0].packageBytes),
      package_container_byte_length: builds[0].packageBytes.length,
      package_container_reproducible: safeEqual(
        builds[0].packageBytes, builds[1].packageBytes),
      installer_signature_verified: false,
      notarization_verified: false,
      bootstrap_installed: false,
      install_authorized: false,
      live_test_verified: false,
    });
    selectedBytes = Buffer.from(builds[0].packageBytes);
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    let cleanupFailed = false;
    for (const build of builds.reverse()) {
      try { await removePrivateTree(build.root, tempBase); } catch { cleanupFailed = true; }
    }
    if (cleanupFailed && primaryError === undefined) {
      throw new MacosProvisionerBootstrapPackageError('cleanup_failed');
    }
    if (cleanupFailed && primaryError !== undefined) primaryError.cleanup_failed = true;
  }
  if (value === undefined || selectedBytes === undefined) {
    throw new MacosProvisionerBootstrapPackageError('invalid_build_state');
  }
  VALID_PACKAGES.add(value);
  PACKAGE_BYTES.set(value, selectedBytes);
  return value;
}

export function isMacosProvisionerBootstrapPackage(value) {
  return value !== null && typeof value === 'object' && VALID_PACKAGES.has(value);
}

export function copyMacosProvisionerBootstrapPackageBytes(value) {
  if (!isMacosProvisionerBootstrapPackage(value)) {
    throw new MacosProvisionerBootstrapPackageError('invalid_package');
  }
  const bytes = PACKAGE_BYTES.get(value);
  if (bytes === undefined) throw new MacosProvisionerBootstrapPackageError('invalid_package');
  return Buffer.from(bytes);
}

async function buildOne(tempBase, provisioner) {
  let root;
  try { root = await fs.mkdtemp(path.join(tempBase, PREFIX)); } catch {
    throw new MacosProvisionerBootstrapPackageError('build_root_create_failed');
  }
  try {
    await requirePrivateRoot(root, tempBase);
    const payloadRoot = path.join(root, 'payload-root');
    const library = path.join(payloadRoot, 'Library');
    const helpers = path.join(library, 'PrivilegedHelperTools');
    await fs.mkdir(payloadRoot, { mode: 0o755 });
    await fs.mkdir(library, { mode: 0o755 });
    await fs.mkdir(helpers, { mode: 0o755 });
    const provisionerPath = path.join(payloadRoot, PAYLOAD_PATH);
    await publish(provisionerPath, provisioner, 0o755);
    await executeSilent('/usr/bin/xattr', ['-cr', payloadRoot], 5000);
    await fs.chmod(provisionerPath, 0o555);
    const hardened = await fs.lstat(provisionerPath);
    if (!hardened.isFile() || hardened.isSymbolicLink() ||
        (hardened.mode & 0o777) !== 0o555) {
      throw new MacosProvisionerBootstrapPackageError('payload_hardening_failed');
    }
    const packagePath = path.join(root, 'provisioner.pkg');
    await executeSilent('/usr/bin/pkgbuild', [
      '--root', payloadRoot,
      '--identifier', IDENTIFIER,
      '--version', VERSION,
      '--install-location', '/',
      '--ownership', 'recommended',
      '--quiet', packagePath,
    ], 30000);
    const packageBytes = await stableFile(packagePath, MAX_PACKAGE_BYTES);
    const payloadList = await execute('/usr/sbin/pkgutil', ['--payload-files', packagePath], 10000);
    if (payloadList.stderr !== '') {
      throw new MacosProvisionerBootstrapPackageError('payload_list_noise');
    }
    const payloadFiles = requirePayloadFiles(payloadList.stdout);
    const expanded = path.join(root, 'expanded');
    await executeSilent('/usr/sbin/pkgutil', ['--expand', packagePath, expanded], 15000);
    const names = (await fs.readdir(expanded)).sort();
    if (names.join('\n') !== ['Bom', 'PackageInfo', 'Payload'].join('\n')) {
      throw new MacosProvisionerBootstrapPackageError('unexpected_package_members');
    }
    const packageInfo = await fs.readFile(path.join(expanded, 'PackageInfo'), 'utf8');
    requirePackageInfo(packageInfo, payloadFiles.length);
    const bomResult = await execute('/usr/bin/lsbom', [
      '-p', 'fMUG', path.join(expanded, 'Bom'),
    ], 10000);
    if (bomResult.stderr !== '') throw new MacosProvisionerBootstrapPackageError('bom_noise');
    requireBom(bomResult.stdout);
    const extracted = path.join(root, 'extracted');
    await fs.mkdir(extracted, { mode: 0o700 });
    await executeSilent('/usr/bin/ditto', [
      '-x', path.join(expanded, 'Payload'), extracted,
    ], 15000);
    await requireExactExtractedTree(extracted, provisioner);
    const extractedXattrs = await execute('/usr/bin/xattr', ['-r', extracted], 5000);
    const xattrLines = extractedXattrs.stdout.trim().split('\n').filter(Boolean);
    if (extractedXattrs.stderr !== '' ||
        xattrLines.some((line) => !line.endsWith(': com.apple.provenance'))) {
      throw new MacosProvisionerBootstrapPackageError('unexpected_extracted_metadata');
    }
    return {
      root,
      packageBytes,
      payload: Buffer.from(provisioner),
      bom: bomResult.stdout,
      packageInfo,
      payloadFiles: payloadList.stdout,
    };
  } catch (error) {
    let cleanupFailed = false;
    try { await removePrivateTree(root, tempBase); } catch { cleanupFailed = true; }
    if (cleanupFailed) {
      const primary = error instanceof MacosProvisionerBootstrapPackageError
        ? error.code
        : 'build_failed';
      throw new MacosProvisionerBootstrapPackageError(`${primary}_cleanup_failed`);
    }
    if (error instanceof MacosProvisionerBootstrapPackageError) throw error;
    throw new MacosProvisionerBootstrapPackageError('build_failed');
  }
}

function requirePackageInfo(xml, payloadFileCount) {
  const rootTags = xml.match(/<pkg-info\b[^>]*>/g) ?? [];
  const payloadTags = xml.match(/<payload\b[^>]*\/?\s*>/g) ?? [];
  const attribute = (tag, name) => {
    const match = tag.match(new RegExp(`(?:^|\\s)${name}="([^"]*)"`));
    return match?.[1] ?? null;
  };
  const bodyMatch = xml.match(/<pkg-info\b[^>]*>([\s\S]*)<\/pkg-info>\s*$/);
  const fixedEmptyChildren = '<bundle-version/><upgrade-bundle/><update-bundle/>' +
      '<atomic-update-bundle/><strict-identifier/><relocate/>';
  const onlyExpectedChildren = bodyMatch !== null && payloadTags.length === 1 &&
      bodyMatch[1].replace(/\s+/g, '') ===
        payloadTags[0].replace(/\s+/g, '') + fixedEmptyChildren;
  const valid = rootTags.length === 1 && payloadTags.length === 1 &&
      onlyExpectedChildren &&
      attribute(rootTags[0], 'identifier') === IDENTIFIER &&
      attribute(rootTags[0], 'version') === VERSION &&
      attribute(rootTags[0], 'install-location') === '/' &&
      attribute(rootTags[0], 'auth') === 'root' &&
      attribute(payloadTags[0], 'numberOfFiles') === String(payloadFileCount) &&
      (xml.match(/<pkg-info\b/g) ?? []).length === 1 &&
      (xml.match(/<payload\b/g) ?? []).length === 1 &&
      /<\/pkg-info>\s*$/.test(xml) && !/<scripts[\s/>]/.test(xml);
  if (!valid) throw new MacosProvisionerBootstrapPackageError('invalid_package_info');
}

function expectedPayloadPaths() {
  return [
    '.', './._Library', './Library', './Library/._PrivilegedHelperTools',
    './Library/PrivilegedHelperTools',
    `./Library/PrivilegedHelperTools/._${IDENTIFIER}`,
    `./${PAYLOAD_PATH}`,
  ];
}

function requirePayloadFiles(stdout) {
  const paths = stdout.trim().split('\n').filter(Boolean).sort();
  const expected = expectedPayloadPaths().sort();
  if (paths.join('\n') !== expected.join('\n')) {
    throw new MacosProvisionerBootstrapPackageError('invalid_payload_file_list');
  }
  return paths;
}

function requireBom(stdout) {
  const lines = stdout.trim().split('\n').filter(Boolean);
  const expectedPaths = expectedPayloadPaths().sort();
  const actualPaths = lines.map((line) => line.split('\t', 1)[0]).sort();
  const validMetadata = lines.every((line) => {
    const parts = line.split('\t');
    const entryPath = parts[0];
    const mode = entryPath.endsWith(IDENTIFIER) || entryPath.endsWith(`._${IDENTIFIER}`)
      ? '-r-xr-xr-x'
      : 'drwxr-xr-x';
    return parts.length === 4 && parts[1].trim() === mode &&
      parts[2] === 'root' && parts[3] === 'wheel';
  });
  if (actualPaths.join('\n') !== expectedPaths.join('\n') || !validMetadata ||
      lines.some((line) => /(^|\/)Scripts(\/|\s|$)/.test(line))) {
    throw new MacosProvisionerBootstrapPackageError('invalid_bom');
  }
}

async function requireExactExtractedTree(extracted, expected) {
  const rootNames = await fs.readdir(extracted);
  const libraryNames = await fs.readdir(path.join(extracted, 'Library'));
  const helperNames = await fs.readdir(path.join(extracted, 'Library', 'PrivilegedHelperTools'));
  if (rootNames.join('\n') !== 'Library' || libraryNames.join('\n') !== 'PrivilegedHelperTools' ||
      helperNames.join('\n') !== IDENTIFIER) {
    throw new MacosProvisionerBootstrapPackageError('unexpected_payload_tree');
  }
  const target = path.join(extracted, PAYLOAD_PATH);
  const stat = await fs.lstat(target);
  const bytes = await fs.readFile(target);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o555 ||
      !safeEqual(bytes, expected)) {
    throw new MacosProvisionerBootstrapPackageError('payload_mismatch');
  }
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
    throw new MacosProvisionerBootstrapPackageError('unsafe_payload_source');
  }
}

async function stableFile(target, maximum) {
  let handle;
  try {
    handle = await fs.open(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = await handle.stat();
    const pathStat = await fs.lstat(target);
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o022) !== 0 ||
        before.size < 1 || before.size > maximum || !sameIdentity(before, pathStat)) {
      throw new MacosProvisionerBootstrapPackageError('unsafe_package_output');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || !sameIdentity(before, after)) {
      throw new MacosProvisionerBootstrapPackageError('package_changed');
    }
    return bytes;
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function requirePrivateRoot(root, tempBase) {
  const stat = await fs.lstat(root);
  if (path.dirname(root) !== tempBase || !path.basename(root).startsWith(PREFIX) ||
      !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o700) {
    throw new MacosProvisionerBootstrapPackageError('unsafe_build_root');
  }
}

async function removePrivateTree(root, tempBase) {
  await requirePrivateRoot(root, tempBase);
  async function removeEntry(target) {
    const stat = await fs.lstat(target);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      for (const name of await fs.readdir(target)) await removeEntry(path.join(target, name));
      await fs.rmdir(target);
      return;
    }
    await fs.unlink(target);
  }
  await removeEntry(root);
}

async function execute(executable, args, timeout) {
  try {
    return await execFileAsync(executable, args, {
      timeout, maxBuffer: 128 * 1024, encoding: 'utf8', env: TOOL_ENV,
    });
  } catch (error) {
    throw new MacosProvisionerBootstrapPackageError(
      error?.killed ? 'timeout_or_terminated' : 'process_failed');
  }
}

async function executeSilent(executable, args, timeout) {
  const result = await execute(executable, args, timeout);
  if (result.stdout !== '' || result.stderr !== '') {
    throw new MacosProvisionerBootstrapPackageError('unexpected_tool_output');
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
function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
