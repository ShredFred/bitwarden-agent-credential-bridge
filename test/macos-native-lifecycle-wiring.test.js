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
const SOURCES = [
  'macos-retained-file-ops.c', 'macos-account-ownership.c',
  'macos-launchd-job-ownership.c', 'macos-dscl-directory-adapter.c',
  'macos-launchctl-job-adapter.c', 'macos-lifecycle-controller.c',
  'macos-native-lifecycle-wiring.c', 'macos-native-lifecycle-wiring-self-test.c',
].map((name) => path.join(NATIVE, name));

describe('native macOS production lifecycle wiring', () => {
  it('binds real adapters and retained artifacts before any job mutation', async () => {
    const wiring = await fs.readFile(path.join(NATIVE, 'macos-native-lifecycle-wiring.c'), 'utf8');
    const controller = await fs.readFile(path.join(NATIVE, 'macos-lifecycle-controller.c'), 'utf8');
    assert.match(wiring, /bw_init_dscl_directory_ops/);
    assert.match(wiring, /bw_init_launchctl_job_ops/);
    assert.match(wiring, /bw_verify_owned_file\(binding->binary/);
    assert.match(wiring, /bw_verify_owned_file\(binding->plist/);
    assert.match(wiring, /fd_has_path\(binding->binary_parent_fd, BINARY_PARENT\)/);
    assert.match(wiring, /fd_has_path\(binding->plist_parent_fd, PLIST_PARENT\)/);
    assert.match(wiring, /#if defined\(BW_NATIVE_WIRING_TESTING\)/);
    assert.match(controller, /bind_owned_artifacts\(request->artifact_binding_context, &binary, &plist\)/);
    assert.ok(controller.indexOf('bind_owned_artifacts(') < controller.indexOf('bw_bootstrap_owned_launchd_job'));
  });

  it('runs clean and blocks cleanup mutation after retained plist replacement', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires Apple CommonCrypto and native headers');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-native-wiring-build-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-DBW_NATIVE_WIRING_TESTING',
        '-Wall', '-Wextra', '-Werror',
        '-Wno-deprecated-declarations', '-O2', ...SOURCES, '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        clean_complete: true,
        replacement_blocked: true,
        fixture_cleanup: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
