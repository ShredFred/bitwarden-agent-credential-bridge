import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import process from 'node:process';
import { describe, it } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  buildMacosLaunchdLifecyclePackage,
  copyMacosLaunchdLifecyclePackageArtifacts,
  isMacosLaunchdLifecyclePackage,
  MacosLaunchdLifecyclePackageError,
  packageInternalsAreBranded,
} from '../src/macos-launchd-lifecycle-package.mjs';

const execFileAsync = promisify(execFile);

describe('signed macOS launchd lifecycle package', () => {
  it('builds real reproducible signed artifacts bound to branded plan and gate', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const tempRoot = await fs.realpath(os.tmpdir());
    const before = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-launchd-package-')));
    const packageValue = await buildMacosLaunchdLifecyclePackage();
    const artifacts = copyMacosLaunchdLifecyclePackageArtifacts(packageValue);
    assert.equal(isMacosLaunchdLifecyclePackage(packageValue), true);
    assert.equal(packageInternalsAreBranded(packageValue), true);
    assert.equal(Object.isFrozen(packageValue), true);
    assert.equal(packageValue.fd_content_code_snapshot_verified, true);
    assert.match(packageValue.artifact_bindings.binary_sha256, /^[0-9a-f]{64}$/);
    assert.match(packageValue.artifact_bindings.designated_requirement_sha256, /^[0-9a-f]{64}$/);
    assert.match(packageValue.artifact_bindings.plist_sha256, /^[0-9a-f]{64}$/);
    assert.equal(packageValue.artifact_bindings.binary_byte_length, artifacts.binary.length);
    assert.equal(
      createHash('sha256').update(artifacts.binary).digest('hex'),
      packageValue.artifact_bindings.binary_sha256,
    );
    assert.equal(
      createHash('sha256').update(artifacts.plist).digest('hex'),
      packageValue.artifact_bindings.plist_sha256,
    );
    assert.deepEqual(packageValue.lifecycle_gate.reviewed_bindings, packageValue.artifact_bindings);
    const after = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-launchd-package-')));
    assert.deepEqual(after, before);
  });

  it('returns independent byte copies and rejects cloned or forged packages', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const packageValue = await buildMacosLaunchdLifecyclePackage();
    const first = copyMacosLaunchdLifecyclePackageArtifacts(packageValue);
    const original = first.binary[0];
    first.binary[0] ^= 0xff;
    const second = copyMacosLaunchdLifecyclePackageArtifacts(packageValue);
    assert.equal(second.binary[0], original);
    for (const invalid of [structuredClone(packageValue), { ...packageValue }, null, {}]) {
      assert.throws(
        () => copyMacosLaunchdLifecyclePackageArtifacts(invalid),
        (error) => error instanceof MacosLaunchdLifecyclePackageError &&
          error.code === 'invalid_package',
      );
    }
  });

  it('uses the exact demand-only fixed plist with no output, timer, or keepalive surface', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const packageValue = await buildMacosLaunchdLifecyclePackage();
    const plist = copyMacosLaunchdLifecyclePackageArtifacts(packageValue).plist.toString('utf8');
    for (const required of [
      '<key>Label</key>', '<key>ProgramArguments</key>', '<key>UserName</key>',
      '<key>MachServices</key>',
      'de.frederikstadler.bitwarden-agent-credential-bridge.helper', '_bwagentbridge',
      '/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.helper',
    ]) assert.ok(plist.includes(required), required);
    for (const forbidden of [
      'KeepAlive', 'RunAtLoad', 'StartInterval', 'StartCalendarInterval', 'WatchPaths',
      'QueueDirectories', 'Sockets', 'StandardOutPath', 'StandardErrorPath', 'EnvironmentVariables',
    ]) assert.equal(plist.includes(forbidden), false, forbidden);
  });

  it('keeps every mutation, trust, live, authorization, and install claim false', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const packageValue = await buildMacosLaunchdLifecyclePackage();
    for (const field of [
      'mutation_authorized', 'collector_trust_verified', 'live_test_verified',
      'authorization_ready', 'install_gate_eligible',
    ]) assert.equal(packageValue[field], false, field);
    assert.equal(packageValue.ready_for_explicit_lifecycle_review, true);
    assert.equal(buildMacosLaunchdLifecyclePackage.length, 0);
    const serialized = JSON.stringify(packageValue);
    for (const forbidden of ['# designated =>', 'Executable=', 'source.c', 'helper.plist']) {
      assert.equal(serialized.includes(forbidden), false, forbidden);
    }
  });

  it('rejects package success when mandatory private-root cleanup fails', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const isolatedBase = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-agent-package-cleanup-test-'));
    try {
      const fixture = path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        'fixtures',
        'macos-lifecycle-package-cleanup-failure.mjs',
      );
      const result = await execFileAsync(process.execPath, [fixture], {
        encoding: 'utf8', timeout: 15000, maxBuffer: 4096,
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C', TMPDIR: isolatedBase },
      });
      assert.equal(result.stdout, 'package_cleanup_failure_rejected\n');
      assert.equal(result.stderr, '');
      assert.deepEqual(await fs.readdir(isolatedBase), []);
    } finally {
      await fs.rmdir(isolatedBase);
    }
  });

  it('contains no elevation, account, launchctl, network, or recursive-cleanup execution path', async () => {
    const modulePath = path.join(
      path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'macos-launchd-lifecycle-package.mjs',
    );
    const source = await fs.readFile(modulePath, 'utf8');
    for (const forbidden of [
      'launchctl', 'dscl', 'sudo', 'osascript', 'AuthorizationExecuteWithPrivileges',
      'OpenDirectory', 'Security.framework', 'curl', 'fetch(', 'HttpClient', 'process.env',
      'fs.rm(', 'shell:',
    ]) assert.equal(source.includes(forbidden), false, forbidden);
    assert.ok(source.includes("executeSilent('/usr/bin/clang'"));
    assert.ok(source.includes("executeSilent('/usr/bin/codesign'"));
    assert.ok(source.includes("execute('/usr/bin/plutil'"));
  });
});
