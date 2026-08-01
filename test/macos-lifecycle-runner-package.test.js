import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  buildMacosLifecycleRunnerPackage,
  copyMacosLifecycleRunnerPackageArtifacts,
  isMacosLifecycleRunnerPackage,
  MacosLifecycleRunnerPackageError,
} from '../src/macos-lifecycle-runner-package.mjs';

describe('signed macOS lifecycle runner package', () => {
  it('builds reproducible signed runner bytes embedding the reviewed lifecycle package', {
    skip: process.platform !== 'darwin', timeout: 30000,
  }, async () => {
    const tempRoot = await fs.realpath(os.tmpdir());
    const before = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-runner-package-')));
    const value = await buildMacosLifecycleRunnerPackage();
    const artifacts = copyMacosLifecycleRunnerPackageArtifacts(value);
    assert.equal(isMacosLifecycleRunnerPackage(value), true);
    assert.equal(Object.isFrozen(value), true);
    assert.equal(value.same_host_reproducible_runner_verified, true);
    assert.equal(value.same_host_reproducible_launcher_verified, true);
    assert.equal(value.same_host_reproducible_provisioner_verified, true);
    assert.equal(value.runner_code_snapshot_verified, true);
    assert.equal(value.launcher_code_snapshot_verified, true);
    assert.equal(value.provisioner_code_snapshot_verified, true);
    assert.equal(value.launcher_lifecycle_bindings_embedded, true);
    assert.equal(value.provisioner_runner_embedded, true);
    assert.equal(value.embedded_artifacts_verified, true);
    assert.equal(value.source_snapshot_bound, false);
    assert.equal(value.stable_source_files_verified, true);
    assert.equal(value.runner_bindings.byte_length, artifacts.runner.length);
    assert.equal(createHash('sha256').update(artifacts.runner).digest('hex'), value.runner_bindings.sha256);
    assert.equal(value.launcher_bindings.byte_length, artifacts.launcher.length);
    assert.equal(createHash('sha256').update(artifacts.launcher).digest('hex'),
      value.launcher_bindings.sha256);
    assert.equal(value.provisioner_bindings.byte_length, artifacts.provisioner.length);
    assert.equal(createHash('sha256').update(artifacts.provisioner).digest('hex'),
      value.provisioner_bindings.sha256);
    assert.equal(createHash('sha256').update(artifacts.helper).digest('hex'),
      value.lifecycle_bindings.binary_sha256);
    assert.equal(createHash('sha256').update(artifacts.plist).digest('hex'),
      value.lifecycle_bindings.plist_sha256);
    const after = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-runner-package-')));
    assert.deepEqual(after, before);
  });

  it('returns independent copies and rejects clones as package authority', {
    skip: process.platform !== 'darwin', timeout: 30000,
  }, async () => {
    const value = await buildMacosLifecycleRunnerPackage();
    const first = copyMacosLifecycleRunnerPackageArtifacts(value);
    const original = first.runner[0];
    const originalLauncher = first.launcher[0];
    const originalProvisioner = first.provisioner[0];
    first.runner[0] ^= 0xff;
    first.launcher[0] ^= 0xff;
    first.provisioner[0] ^= 0xff;
    assert.equal(copyMacosLifecycleRunnerPackageArtifacts(value).runner[0], original);
    assert.equal(copyMacosLifecycleRunnerPackageArtifacts(value).launcher[0], originalLauncher);
    assert.equal(copyMacosLifecycleRunnerPackageArtifacts(value).provisioner[0],
      originalProvisioner);
    for (const invalid of [structuredClone(value), { ...value }, {}, null]) {
      assert.throws(() => copyMacosLifecycleRunnerPackageArtifacts(invalid),
        (error) => error instanceof MacosLifecycleRunnerPackageError &&
          error.code === 'invalid_package');
    }
  });

  it('keeps package construction non-authorizing and free of elevation or host mutation', async () => {
    const modulePath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src',
      'macos-lifecycle-runner-package.mjs');
    const source = await fs.readFile(modulePath, 'utf8');
    for (const forbidden of [
      "execute('/usr/bin/sudo'", "executeSilent('/usr/bin/sudo'",
      'osascript', 'AuthorizationExecuteWithPrivileges',
      'curl', 'fetch(', 'process.env', 'fs.rm(', 'shell:',
    ]) assert.equal(source.includes(forbidden), false, forbidden);
    assert.equal(source.includes('"/bin/launchctl"'), false);
    assert.equal(source.includes('"/usr/bin/dscl"'), false);
    assert.match(source, /buildMacosLaunchdLifecyclePackage\(\)/);
    assert.match(source, /verifyMacosCodeSnapshot/);
    assert.match(source, /non_reproducible_runner/);
    assert.match(source, /launcher_binding_section_/);
  });
});
