import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import {
  copyMacosProvisionerBootstrapPackageBytes,
  isMacosProvisionerBootstrapPackage,
} from './macos-provisioner-bootstrap-package.mjs';

const execFileAsync = promisify(execFile);
const PREFIX = 'bw-agent-distribution-readiness-';
const IDENTIFIER = 'de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-provisioner';
const MAX_PACKAGE_BYTES = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C', COPYFILE_DISABLE: '1',
});

export class MacosProvisionerDistributionReadinessError extends Error {
  constructor(code) {
    super(`macOS provisioner distribution readiness failed: ${code}`);
    this.name = 'MacosProvisionerDistributionReadinessError';
    this.code = code;
  }
}

export async function inspectMacosProvisionerDistributionReadiness(packageValue) {
  if (process.platform !== 'darwin') fail('unsupported_platform');
  if (!isMacosProvisionerBootstrapPackage(packageValue)) fail('invalid_package');
  const bytes = copyMacosProvisionerBootstrapPackageBytes(packageValue);
  if (bytes.length < 1 || bytes.length > MAX_PACKAGE_BYTES ||
      bytes.length !== packageValue.package_container_byte_length ||
      sha256(bytes) !== packageValue.package_container_sha256) fail('package_binding_mismatch');
  if (packageValue.package_identifier !== IDENTIFIER) fail('package_policy_mismatch');
  const payloadContractVerified = [
    'payload_exactly_verified', 'payload_metadata_verified',
    'payload_same_host_reproducible', 'scripts_absent_verified',
    'archive_metadata_bounded_verified', 'recommended_root_wheel_ownership_verified',
  ].every((field) => packageValue[field] === true);

  let tempBase;
  try { tempBase = await fs.realpath(os.tmpdir()); } catch { fail('unsafe_temp_root'); }
  let root;
  let primaryError;
  try {
    try { root = await fs.mkdtemp(path.join(tempBase, PREFIX)); } catch {
      fail('inspection_root_create_failed');
    }
    await requirePrivateRoot(root, tempBase);
    const packagePath = path.join(root, 'provisioner.pkg');
    await publish(packagePath, bytes);
    const before = await stableIdentity(packagePath, bytes);
    const result = await runPkgutil(packagePath);
    const after = await stableIdentity(packagePath, bytes);
    if (!sameIdentity(before, after)) fail('package_changed_during_inspection');
    const signature = parseMacosPkgutilSignatureOutput(result.stdout);
    if (result.stderr !== '' || signature.package_basename !== 'provisioner.pkg') {
      fail('unexpected_signature_output');
    }
    const expectedExit = signature.signature_kind === 'unsigned' ? 1 : 0;
    if (result.code !== expectedExit) fail('unexpected_signature_status');

    // A production certificate fingerprint has deliberately not been authorized or pinned.
    // Therefore no signed input can become installer-signature-verified in this phase.
    const certificatePinConfigured = false;
    const certificatePinMatches = false;
    const installerSignatureVerified = signature.signature_valid_and_trusted &&
      signature.developer_id_installer_chain_verified &&
      signature.trusted_timestamp_verified && certificatePinConfigured && certificatePinMatches;
    const report = deepFreeze({
      schema_version: 1,
      platform: 'darwin',
      package_bytes_bound: true,
      package_identifier_matches_policy: true,
      payload_contract_verified: payloadContractVerified,
      signature_inspection_complete: true,
      package_signature_present: signature.signature_kind === 'developer_id_installer',
      package_signature_valid_and_trusted: signature.signature_valid_and_trusted,
      developer_id_installer_chain_verified:
        signature.developer_id_installer_chain_verified,
      trusted_timestamp_verified: signature.trusted_timestamp_verified,
      pkgutil_notarization_status_observed: signature.notarization_status_observed,
      certificate_pin_configured: certificatePinConfigured,
      certificate_pin_matches: certificatePinMatches,
      installer_signature_verified: installerSignatureVerified,
      stapled_ticket_verified: false,
      notarization_verified: false,
      distribution_ready: false,
      bootstrap_installed: false,
      install_authorized: false,
      live_test_verified: false,
    });
    requireConsistentReport(report);
    return report;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    if (root !== undefined) {
      try { await removePrivateTree(root, tempBase); } catch {
        if (primaryError !== undefined) primaryError.cleanup_failed = true;
        else fail('cleanup_failed');
      }
    }
  }
}

export function parseMacosPkgutilSignatureOutput(stdout) {
  if (typeof stdout !== 'string' || Buffer.byteLength(stdout) > MAX_OUTPUT_BYTES ||
      stdout.includes('\r') || stdout.includes('\0')) fail('invalid_signature_output');
  const unsigned = stdout.match(/^Package "([A-Za-z0-9._-]+)":\n   Status: no signature\n$/);
  if (unsigned !== null) return deepFreeze({
    package_basename: unsigned[1],
    signature_kind: 'unsigned',
    signature_valid_and_trusted: false,
    developer_id_installer_chain_verified: false,
    trusted_timestamp_verified: false,
    notarization_status_observed: false,
    leaf_certificate_sha256: null,
  });

  const lines = stdout.split('\n');
  if (lines.at(-1) !== '') fail('invalid_signature_output');
  lines.pop();
  const header = lines.shift()?.match(/^Package "([A-Za-z0-9._-]+)":$/);
  if (header === null || header === undefined ||
      lines.shift() !== '   Status: signed by a developer certificate issued by Apple for distribution') {
    fail('invalid_signature_output');
  }
  let notarization = false;
  if (lines[0] === '   Notarization: trusted by the Apple notary service') {
    notarization = true;
    lines.shift();
  }
  if (!/^   Signed with a trusted timestamp on: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$/.test(lines.shift() ?? '') ||
      lines.shift() !== '   Certificate Chain:') fail('invalid_signature_output');
  const certificates = [];
  for (let index = 1; index <= 3; index += 1) {
    const name = lines.shift()?.match(new RegExp(`^    ${index}\\. ([^\\x00-\\x1f]{1,200})$`));
    const expires = lines.shift();
    if (name === null || name === undefined ||
        !/^       Expires: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$/.test(expires ?? '') ||
        lines.shift() !== '       SHA256 Fingerprint:') fail('invalid_signature_output');
    const fingerprintParts = [];
    while (/^           [0-9A-F]{2}(?: [0-9A-F]{2}){0,23} ?$/.test(lines[0] ?? '')) {
      fingerprintParts.push(lines.shift().trim());
    }
    const fingerprint = fingerprintParts.join(' ').replaceAll(' ', '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fingerprint)) fail('invalid_signature_output');
    certificates.push({ name: name[1], fingerprint });
    if (index < 3) {
      if (lines.shift() !== '       ------------------------------------------------------------------------') {
        fail('invalid_signature_output');
      }
    }
  }
  if (lines.length !== 0) fail('invalid_signature_output');
  const chain = /^Developer ID Installer: .+ \([A-Z0-9]{10}\)$/.test(certificates[0].name) &&
    certificates[1].name === 'Developer ID Certification Authority' &&
    certificates[2].name === 'Apple Root CA';
  if (!chain) fail('invalid_signature_output');
  return deepFreeze({
    package_basename: header[1],
    signature_kind: 'developer_id_installer',
    signature_valid_and_trusted: true,
    developer_id_installer_chain_verified: true,
    trusted_timestamp_verified: true,
    notarization_status_observed: notarization,
    leaf_certificate_sha256: certificates[0].fingerprint,
  });
}

async function runPkgutil(packagePath) {
  try {
    const result = await execFileAsync('/usr/sbin/pkgutil', ['--check-signature', packagePath], {
      timeout: 10000, maxBuffer: MAX_OUTPUT_BYTES, encoding: 'utf8', env: TOOL_ENV,
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    if (error?.killed || error?.signal !== undefined && error.signal !== null) {
      fail('signature_inspection_timeout');
    }
    if (!Number.isInteger(error?.code) || typeof error?.stdout !== 'string' ||
        typeof error?.stderr !== 'string') fail('signature_inspection_failed');
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

async function publish(target, bytes) {
  let handle;
  try {
    handle = await fs.open(target,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
      0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function stableIdentity(target, expected) {
  let handle;
  try {
    handle = await fs.open(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = await handle.stat();
    const pathStat = await fs.lstat(target);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o777) !== 0o600 ||
        !sameIdentity(before, pathStat) || !sameIdentity(before, after) ||
        !safeEqual(bytes, expected)) fail('unsafe_package_snapshot');
    return before;
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function requirePrivateRoot(root, tempBase) {
  const stat = await fs.lstat(root);
  if (path.dirname(root) !== tempBase || !path.basename(root).startsWith(PREFIX) ||
      !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o700) fail('unsafe_inspection_root');
}

async function removePrivateTree(root, tempBase) {
  await requirePrivateRoot(root, tempBase);
  for (const name of await fs.readdir(root)) {
    const target = path.join(root, name);
    const stat = await fs.lstat(target);
    if (!stat.isFile() || stat.isSymbolicLink()) fail('unsafe_cleanup_target');
    await fs.unlink(target);
  }
  await fs.rmdir(root);
}

function requireConsistentReport(report) {
  if (report.package_signature_valid_and_trusted && !report.package_signature_present ||
      report.installer_signature_verified || report.stapled_ticket_verified ||
      report.notarization_verified || report.distribution_ready ||
      report.bootstrap_installed || report.install_authorized || report.live_test_verified ||
      report.certificate_pin_configured || report.certificate_pin_matches) fail('invalid_report');
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
function fail(code) { throw new MacosProvisionerDistributionReadinessError(code); }
