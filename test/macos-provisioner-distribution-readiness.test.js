import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildMacosProvisionerBootstrapPackage } from '../src/macos-provisioner-bootstrap-package.mjs';
import {
  inspectMacosProvisionerDistributionReadiness,
  MacosProvisionerDistributionReadinessError,
  parseMacosPkgutilSignatureOutput,
} from '../src/macos-provisioner-distribution-readiness.mjs';

const SIGNED = `Package "provisioner.pkg":
   Status: signed by a developer certificate issued by Apple for distribution
   Notarization: trusted by the Apple notary service
   Signed with a trusted timestamp on: 2026-08-01 12:34:56 +0000
   Certificate Chain:
    1. Developer ID Installer: Example GmbH (A1B2C3D4E5)
       Expires: 2030-01-01 00:00:00 +0000
       SHA256 Fingerprint:
           00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 
           66 77 88 99 AA BB CC DD EE FF
       ------------------------------------------------------------------------
    2. Developer ID Certification Authority
       Expires: 2031-09-17 00:00:00 +0000
       SHA256 Fingerprint:
           11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 
           11 11 11 11 11 11 11 11 11 11
       ------------------------------------------------------------------------
    3. Apple Root CA
       Expires: 2035-02-09 21:40:36 +0000
       SHA256 Fingerprint:
           22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 
           22 22 22 22 22 22 22 22 22 22
`;

describe('macOS provisioner distribution readiness', () => {
  it('inspects the real unsigned branded package and refuses every production claim', {
    skip: process.platform !== 'darwin', timeout: 40000,
  }, async () => {
    const tempRoot = await fs.realpath(os.tmpdir());
    const before = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-distribution-readiness-')));
    const value = await buildMacosProvisionerBootstrapPackage();
    const report = await inspectMacosProvisionerDistributionReadiness(value);
    assert.equal(Object.isFrozen(report), true);
    assert.equal(report.package_bytes_bound, true);
    assert.equal(report.payload_contract_verified, true);
    assert.equal(report.signature_inspection_complete, true);
    assert.equal(report.package_signature_present, false);
    assert.equal(report.package_signature_valid_and_trusted, false);
    assert.equal(report.certificate_pin_configured, false);
    assert.equal(report.installer_signature_verified, false);
    assert.equal(report.notarization_verified, false);
    assert.equal(report.distribution_ready, false);
    assert.equal(report.install_authorized, false);
    const after = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-distribution-readiness-')));
    assert.deepEqual(after, before);
  });

  it('parses only exact unsigned and Developer ID Installer pkgutil grammars', () => {
    const unsigned = parseMacosPkgutilSignatureOutput(
      'Package "provisioner.pkg":\n   Status: no signature\n');
    assert.equal(unsigned.signature_kind, 'unsigned');
    assert.equal(unsigned.signature_valid_and_trusted, false);
    const signed = parseMacosPkgutilSignatureOutput(SIGNED);
    assert.equal(signed.signature_kind, 'developer_id_installer');
    assert.equal(signed.signature_valid_and_trusted, true);
    assert.equal(signed.developer_id_installer_chain_verified, true);
    assert.equal(signed.trusted_timestamp_verified, true);
    assert.equal(signed.notarization_status_observed, true);
    assert.equal(signed.leaf_certificate_sha256,
      '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  });

  it('fails closed on forged, loose, incomplete, or unexpected signature output', () => {
    const invalid = [
      '', 'Status: no signature\n',
      'Package "x.pkg":\n   Status: no signature\nextra\n',
      'Package "../x.pkg":\n   Status: no signature\n',
      SIGNED.replace('Developer ID Installer', 'Apple Development'),
      SIGNED.replace('Apple Root CA', 'Untrusted Root'),
      SIGNED.replace('SHA256 Fingerprint:', 'SHA1 Fingerprint:'),
      SIGNED.replace(' +0000\n', ' +0000\r\n'),
    ];
    for (const output of invalid) assert.throws(
      () => parseMacosPkgutilSignatureOutput(output),
      (error) => error instanceof MacosProvisionerDistributionReadinessError &&
        error.code === 'invalid_signature_output');
  });

  it('rejects cloned package authority and has no signing, network, or mutation surface', {
    skip: process.platform !== 'darwin', timeout: 40000,
  }, async () => {
    const value = await buildMacosProvisionerBootstrapPackage();
    for (const invalid of [structuredClone(value), { ...value }, {}, null]) {
      await assert.rejects(inspectMacosProvisionerDistributionReadiness(invalid),
        (error) => error instanceof MacosProvisionerDistributionReadinessError &&
          error.code === 'invalid_package');
    }
    const source = await fs.readFile(path.join(
      path.dirname(fileURLToPath(import.meta.url)), '..', 'src',
      'macos-provisioner-distribution-readiness.mjs'), 'utf8');
    for (const forbidden of [
      "'/usr/bin/sudo'", "'/usr/sbin/installer'", 'productsign', 'notarytool',
      'stapler', 'spctl', 'security find-identity', 'curl', 'fetch(', 'process.env',
      "'/Library/", '--sign',
    ]) assert.equal(source.includes(forbidden), false, forbidden);
    assert.match(source, /'\/usr\/sbin\/pkgutil'/);
    assert.match(source, /certificatePinConfigured = false/);
    assert.match(source, /notarization_verified: false/);
  });
});
