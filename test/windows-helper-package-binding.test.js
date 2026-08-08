import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  ONECLI_PROXY_SUPERVISOR_BINDING,
  WINDOWS_HELPER_ENTRYPOINT_MODES,
  WINDOWS_HELPER_PACKAGE_DIGEST,
  WINDOWS_HELPER_SELF_TEST_KEYS,
  WINDOWS_HELPER_SOURCE_BYTE_LENGTHS,
  WINDOWS_HELPER_SOURCE_DIGESTS,
  WINDOWS_HELPER_TOOLCHAIN_PIN,
  brandWindowsHelperPublishBinding,
  digestCanonicalFileFacts,
  evaluateWindowsHelperPackageBinding,
  isWindowsHelperPackageBindingReport,
  isWindowsHelperPublishBinding,
  requireWindowsHelperPublishBinding,
  verifyOneCliProxySupervisorPackageBinding,
  verifyWindowsHelperReviewedSources,
  WindowsHelperPackageBindingError,
} from '../src/windows-helper-package-binding.mjs';

function matchingFiles() {
  return Object.keys(WINDOWS_HELPER_SOURCE_DIGESTS).sort().map((relativePath) => ({
    path: relativePath,
    sha256: WINDOWS_HELPER_SOURCE_DIGESTS[relativePath],
    byte_length: WINDOWS_HELPER_SOURCE_BYTE_LENGTHS[relativePath],
  }));
}

describe('Windows helper package binding (Phase 9f)', () => {
  it('evaluates matching injected source facts as package-bound', () => {
    const report = evaluateWindowsHelperPackageBinding({
      files: matchingFiles(),
      toolchain: { ...WINDOWS_HELPER_TOOLCHAIN_PIN },
      entrypoint_modes_present: true,
      self_test_keys_present: true,
    });
    assert.equal(isWindowsHelperPackageBindingReport(report), true);
    assert.equal(isWindowsHelperPackageBindingReport({ ...report }), false);
    assert.equal(report.package_binding_verified, true);
    assert.equal(report.package_digest, WINDOWS_HELPER_PACKAGE_DIGEST);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.helper_vault_free, true);
    assert.equal(report.terminal_code, 'windows_helper_package_bound');
    assert.equal(
      digestCanonicalFileFacts(matchingFiles()),
      WINDOWS_HELPER_PACKAGE_DIGEST,
    );
  });

  it('rejects digest drift, toolchain drift, and incomplete entrypoint surface', () => {
    const files = matchingFiles();
    files[0] = { ...files[0], sha256: '0'.repeat(64) };
    assert.throws(
      () => evaluateWindowsHelperPackageBinding({
        files,
        toolchain: { ...WINDOWS_HELPER_TOOLCHAIN_PIN },
        entrypoint_modes_present: true,
        self_test_keys_present: true,
      }),
      (error) => error instanceof WindowsHelperPackageBindingError &&
        error.code === 'source_digest_mismatch',
    );
    assert.throws(
      () => evaluateWindowsHelperPackageBinding({
        files: matchingFiles(),
        toolchain: { ...WINDOWS_HELPER_TOOLCHAIN_PIN, sdk_version: '8.0.000' },
        entrypoint_modes_present: true,
        self_test_keys_present: true,
      }),
      (error) => error instanceof WindowsHelperPackageBindingError &&
        error.code === 'toolchain_pin_mismatch',
    );
    assert.throws(
      () => evaluateWindowsHelperPackageBinding({
        files: matchingFiles(),
        toolchain: { ...WINDOWS_HELPER_TOOLCHAIN_PIN },
        entrypoint_modes_present: false,
        self_test_keys_present: true,
      }),
      (error) => error instanceof WindowsHelperPackageBindingError &&
        error.code === 'entrypoint_surface_mismatch',
    );
  });

  it('verifies live reviewed helper sources against committed pins', async () => {
    const report = await verifyWindowsHelperReviewedSources();
    assert.equal(report.package_binding_verified, true);
    assert.equal(report.package_digest, WINDOWS_HELPER_PACKAGE_DIGEST);
    assert.equal(report.authorization_ready, false);
    assert.ok(WINDOWS_HELPER_ENTRYPOINT_MODES.includes('--verify-fixed-server-identity'));
    assert.ok(WINDOWS_HELPER_SELF_TEST_KEYS.includes('scm_entrypoint_compiled'));
    assert.ok(WINDOWS_HELPER_SELF_TEST_KEYS.includes('vault_client_absent'));
  });

  it('verifies OneCLI proxy supervisor entrypoint and imports', async () => {
    const report = await verifyOneCliProxySupervisorPackageBinding();
    assert.equal(report.supervisor_package_binding_verified, true);
    assert.equal(report.authorization_ready, false);
    assert.equal(
      ONECLI_PROXY_SUPERVISOR_BINDING.fixed_runtime_entrypoint_basename,
      'run-onecli-proxy.mjs',
    );
    assert.deepEqual([...ONECLI_PROXY_SUPERVISOR_BINDING.required_imports], [
      './agent-token.js',
      './onecli-proxy-runtime-frame.js',
      './policy.js',
    ]);
  });

  it('brands publish bindings and rejects forged clones', () => {
    const bytes = Buffer.from('reviewed-helper-bytes');
    const realDigest = createHash('sha256').update(bytes).digest('hex');
    const branded = brandWindowsHelperPublishBinding({
      bytes,
      sha256: realDigest,
      byteLength: bytes.byteLength,
      package_digest: WINDOWS_HELPER_PACKAGE_DIGEST,
      package_binding_verified: true,
      authorization_ready: false,
    });
    assert.equal(isWindowsHelperPublishBinding(branded), true);
    assert.equal(requireWindowsHelperPublishBinding(branded), branded);
    assert.throws(
      () => requireWindowsHelperPublishBinding({ ...branded }),
      (error) => error instanceof WindowsHelperPackageBindingError &&
        error.code === 'unbranded_publish_binding',
    );
    assert.throws(
      () => brandWindowsHelperPublishBinding({
        bytes,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        byteLength: bytes.byteLength,
        package_digest: WINDOWS_HELPER_PACKAGE_DIGEST,
        package_binding_verified: true,
        authorization_ready: false,
      }),
      (error) => error instanceof WindowsHelperPackageBindingError &&
        error.code === 'binary_digest_mismatch',
    );
  });
});
