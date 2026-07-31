import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  selectPlatformManifest,
  validateCompatibilityStatus,
  validateOciDigest,
  validateSha256Checksum,
  validateVersion,
} from '../src/supply-chain-audit.mjs';

describe('Phase 3 supply-chain validators', () => {
  it('accepts only canonical SHA-256 checksums and OCI digests', () => {
    const checksum = '7c7dfbe9db85d3e17e654afa4117ae76c5ec16750cee817a80432b2e93f724a2';
    const digest = `sha256:${checksum}`;

    assert.equal(validateSha256Checksum(checksum), checksum);
    assert.equal(validateOciDigest(digest), digest);

    for (const value of [
      '',
      checksum.slice(1),
      checksum.toUpperCase(),
      `sha512:${checksum}`,
      `sha256:${checksum.slice(1)}`,
    ]) {
      assert.throws(() => validateSha256Checksum(value), /SHA-256/);
      assert.throws(() => validateOciDigest(value), /OCI SHA-256/);
    }
  });

  it('accepts only canonical three-part versions', () => {
    for (const version of ['1.45.0', '0.9.0', '0.11.0', '0.12.0']) {
      assert.equal(validateVersion(version), version);
    }

    for (const version of ['', 'v1.45.0', '1.45', '01.45.0', '18-alpine']) {
      assert.throws(() => validateVersion(version), /version/);
    }
  });

  it('selects only an explicitly locked platform manifest', () => {
    const image = {
      indexDigest:
        'sha256:d0177458b1f9ecece4abbe9abb6c5f925475357c1734f50a675d83a2ef9c8687',
      manifests: {
        'linux/amd64':
          'sha256:5b9367221f7b9acb741cadd67b0ce0384bc344994effb9e04ce339f8930cdc8a',
        'linux/arm64':
          'sha256:cb55d9e7b71c655134d4a1fe03a6152ad0e2c44518bcf4f68418c9e6bb98f9df',
      },
    };

    assert.deepEqual(
      selectPlatformManifest(image, { os: 'linux', architecture: 'amd64' }),
      {
        platform: 'linux/amd64',
        digest: image.manifests['linux/amd64'],
      },
    );
    assert.deepEqual(
      selectPlatformManifest(image, { os: 'linux', architecture: 'arm64' }),
      {
        platform: 'linux/arm64',
        digest: image.manifests['linux/arm64'],
      },
    );

    for (const platform of [
      { os: 'win32', architecture: 'amd64' },
      { os: 'linux', architecture: 'x64' },
      { os: 'linux', architecture: 's390x' },
    ]) {
      assert.throws(
        () => selectPlatformManifest(image, platform),
        /locked platform manifest/,
      );
    }
  });

  it('keeps candidate AAC compatibility unverified', () => {
    assert.equal(validateCompatibilityStatus('unverified'), 'unverified');

    for (const status of [
      'compatible',
      'verified',
      'passed',
      true,
      undefined,
    ]) {
      assert.throws(
        () => validateCompatibilityStatus(status),
        /disposable live test/,
      );
    }
  });
});
