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

describe('native macOS fixed command runner', () => {
  it('uses no shell and applies bounded, closed-descriptor execution controls', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-fixed-command-runner.c'), 'utf8');
    assert.match(source, /posix_spawn\(/);
    assert.match(source, /POSIX_SPAWN_CLOEXEC_DEFAULT/);
    assert.match(source, /POSIX_SPAWN_SETPGROUP/);
    assert.match(source, /S_ISUID \| S_ISGID/);
    assert.match(source, /acl_get_file\(path, ACL_TYPE_EXTENDED\)/);
    assert.match(source, /path_value\.st_ino == fd_value\.st_ino/);
    assert.match(source, /PATH=\/usr\/bin:\/bin:\/usr\/sbin:\/sbin/);
    assert.match(source, /open\("\/dev\/null", O_RDONLY \| O_CLOEXEC \| O_NOFOLLOW\)/);
    assert.match(source, /maximum_output_bytes > BW_COMMAND_OUTPUT_CAPACITY/);
    assert.match(source, /kill\(-child, SIGKILL\)/);
    assert.match(source, /waitpid\(child, NULL, 0\)/);
    for (const forbidden of [/system\(/, /popen\(/, /\/bin\/sh/, /exec[lv]p?\(/]) {
      assert.equal(forbidden.test(source), false, forbidden);
    }
  });

  it('captures exit status and kills timeouts and output floods', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS posix_spawn close-on-exec support');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-command-runner-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-fixed-command-runner.c'),
        path.join(NATIVE, 'macos-fixed-command-runner-self-test.c'), '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        true_ok: true,
        capture_ok: true,
        nonzero_reported: true,
        timeout_killed: true,
        flood_killed: true,
        relative_rejected: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
