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

describe('retained-FD macOS runner provisioning transaction', () => {
  it('uses one fixed name, exclusive publication, and identity-bound cleanup', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-runner-provisioning.c'), 'utf8');
    assert.match(source, /#define RUNNER_NAME "de\.frederikstadler\./);
    assert.match(source, /bw_publish_owned_file/);
    assert.match(source, /bw_verify_owned_file/);
    assert.match(source, /acl_get_fd_np\(parent_fd, ACL_TYPE_EXTENDED\)/);
    assert.match(source, /execute_retained_fd\(request, runner\.file_fd\)/);
    assert.match(source, /execve\(descriptor_path, arguments, environment\)/);
    assert.match(source, /bw_unlink_owned_file\(&runner\)/);
    assert.ok(source.indexOf('bw_verify_owned_file') <
      source.indexOf('execute_retained_fd(request, runner.file_fd'));
    for (const forbidden of [
      /\/Library\//, /sudo/, /launchctl/, /dscl/, /system\(/, /popen\(/, /exec[lv]p\(/,
      /posix_spawn/,
    ]) {
      assert.equal(forbidden.test(source), false, forbidden);
    }
  });

  it('cleans success, preserves collision, and refuses foreign replacement cleanup', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS retained-FD semantics');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-provision-build-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-DBW_RUNNER_PROVISIONING_TESTING',
        '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-retained-file-ops.c'),
        path.join(NATIVE, 'macos-runner-provisioning.c'),
        path.join(NATIVE, 'macos-runner-provisioning-self-test.c'), '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        clean_complete: true,
        collision_preserved: true,
        replacement_preserved: true,
        fixture_cleanup: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
