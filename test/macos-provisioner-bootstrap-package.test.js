import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  buildMacosProvisionerBootstrapPackage,
  copyMacosProvisionerBootstrapPackageBytes,
  isMacosProvisionerBootstrapPackage,
  MacosProvisionerBootstrapPackageError,
} from '../src/macos-provisioner-bootstrap-package.mjs';

describe('non-installing macOS provisioner bootstrap package', () => {
  it('builds an exact root-owned script-free provisioner payload twice', {
    skip: process.platform !== 'darwin', timeout: 30000,
  }, async () => {
    const tempRoot = await fs.realpath(os.tmpdir());
    const before = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-bootstrap-package-')));
    const value = await buildMacosProvisionerBootstrapPackage();
    const bytes = copyMacosProvisionerBootstrapPackageBytes(value);
    assert.equal(isMacosProvisionerBootstrapPackage(value), true);
    assert.equal(Object.isFrozen(value), true);
    assert.equal(value.payload_path,
      '/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-provisioner');
    assert.equal(value.payload_exactly_verified, true);
    assert.equal(value.payload_metadata_verified, true);
    assert.equal(value.payload_same_host_reproducible, true);
    assert.equal(value.scripts_absent_verified, true);
    assert.equal(value.archive_metadata_bounded_verified, true);
    assert.equal(value.recommended_root_wheel_ownership_verified, true);
    assert.equal(value.installer_signature_verified, false);
    assert.equal(value.notarization_verified, false);
    assert.equal(value.bootstrap_installed, false);
    assert.equal(value.install_authorized, false);
    assert.equal(value.live_test_verified, false);
    assert.equal(Object.hasOwn(value, 'lifecycle_package'), false);
    assert.equal(bytes.length, value.package_container_byte_length);
    assert.equal(createHash('sha256').update(bytes).digest('hex'),
      value.package_container_sha256);
    const after = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-bootstrap-package-')));
    assert.deepEqual(after, before);
  });

  it('returns independent package bytes and rejects authority clones', {
    skip: process.platform !== 'darwin', timeout: 30000,
  }, async () => {
    const value = await buildMacosProvisionerBootstrapPackage();
    const first = copyMacosProvisionerBootstrapPackageBytes(value);
    const original = first[0];
    first[0] ^= 0xff;
    assert.equal(copyMacosProvisionerBootstrapPackageBytes(value)[0], original);
    for (const invalid of [structuredClone(value), { ...value }, {}, null]) {
      assert.throws(() => copyMacosProvisionerBootstrapPackageBytes(invalid),
        (error) => error instanceof MacosProvisionerBootstrapPackageError &&
          error.code === 'invalid_package');
    }
  });

  it('contains no installation, elevation, scripts, network, or credential execution surface', async () => {
    const source = await fs.readFile(path.join(
      path.dirname(fileURLToPath(import.meta.url)), '..', 'src',
      'macos-provisioner-bootstrap-package.mjs'), 'utf8');
    for (const forbidden of [
      "'/usr/bin/sudo'", "'/usr/sbin/installer'", 'osascript', '--scripts',
      'AuthorizationExecuteWithPrivileges', 'curl', 'fetch(', 'process.env',
      'Keychain', 'Bitwarden', 'OneCLI',
    ]) assert.equal(source.includes(forbidden), false, forbidden);
    assert.match(source, /'\/usr\/bin\/pkgbuild'/);
    assert.match(source, /'--ownership', 'recommended'/);
    assert.match(source, /install_authorized: false/);
  });
});
