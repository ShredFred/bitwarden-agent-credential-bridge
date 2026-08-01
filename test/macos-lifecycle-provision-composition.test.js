import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const NATIVE = path.join(ROOT, 'native');
const TOOL_ENV = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };

describe('macOS package-bound lifecycle provision composition', () => {
  it('uses one fixed root-owned provisioner and a strict elevation chain', async () => {
    const launcher = await fs.readFile(
      path.join(NATIVE, 'macos-sudo-lifecycle-launcher.c'), 'utf8');
    const provisioner = await fs.readFile(
      path.join(NATIVE, 'macos-lifecycle-provisioner.c'), 'utf8');
    const elevation = await fs.readFile(
      path.join(NATIVE, 'macos-elevation-identity.c'), 'utf8');
    assert.match(launcher, /#define PROVISIONER_PATH "\/Library\/PrivilegedHelperTools\//);
    assert.match(launcher, /runner_absent && bw_fixed_executable_is_secure\(PROVISIONER_PATH\)/);
    assert.match(launcher, /BW_LAUNCHER_PROVISIONER_SHA256/);
    assert.match(launcher, /--provision-run-cleanup-approved-denial-lifecycle/);
    assert.match(provisioner, /BW_PROVISIONER_RUNNER_BYTES/);
    assert.match(provisioner, /bw_stable_direct_sudo_parent\(\)/);
    assert.match(provisioner, /bw_provision_run_cleanup_runner\(&request\)/);
    assert.match(elevation, /PROVISIONER_PATH/);
    assert.match(elevation, /stable_root_process\(grandparent, SUDO_PATH/);
    assert.equal(/system\(|popen\(|\/bin\/sh|process\.env|curl|fetch\(/.test(
      launcher + provisioner + elevation), false);
  });

  it('builds the real provisioner and rejects ambient and unelevated execution', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS native elevation identity APIs');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-provisioner-build-'));
    const binary = path.join(root, 'provisioner');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror',
        '-Wno-deprecated-declarations', '-O2',
        '-DBW_PROVISIONER_RUNNER_HEADER="test/fixtures/macos-provisioner-runner.h"',
        '-I', ROOT,
        path.join(NATIVE, 'macos-retained-file-ops.c'),
        path.join(NATIVE, 'macos-runner-provisioning.c'),
        path.join(NATIVE, 'macos-elevation-identity.c'),
        path.join(NATIVE, 'macos-lifecycle-provisioner.c'), '-o', binary,
      ], { cwd: ROOT, timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      await assert.rejects(execFileAsync(binary, [], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      }), (error) => error.code === 64 && error.stdout === '' && error.stderr === '');
      await assert.rejects(execFileAsync(
        binary, ['--provision-run-cleanup-approved-denial-lifecycle'], {
          timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
        }), (error) => error.code === 77 && error.stdout === '' && error.stderr === '');
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('accepts only direct sudo or the exact provisioner-mediated ancestry', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS native process identity APIs');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-elevation-build-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-DBW_ELEVATION_IDENTITY_TESTING',
        '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-elevation-identity.c'),
        path.join(NATIVE, 'macos-elevation-identity-self-test.c'), '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        direct_sudo: true,
        mediated: true,
        arbitrary_parent_rejected: true,
        missing_sudo_rejected: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
