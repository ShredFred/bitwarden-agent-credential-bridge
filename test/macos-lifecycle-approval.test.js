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

describe('native macOS lifecycle approval boundary', () => {
  it('accepts approval only through a bound one-shot native capability', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-lifecycle-approval.c'), 'utf8');
    const header = await fs.readFile(path.join(NATIVE, 'macos-lifecycle-approval.h'), 'utf8');
    const wiring = await fs.readFile(path.join(NATIVE, 'macos-native-lifecycle-wiring.c'), 'utf8');
    assert.match(source, /getuid\(\) == 0 \|\| geteuid\(\) != 0/);
    assert.match(source, /stable_sudo_parent\(\)/);
    assert.match(source, /strcmp|memcmp/);
    assert.match(source, /getpeereid/);
    assert.match(source, /receipt\.runner_pid != getpid\(\)/);
    assert.match(source, /BW_APPROVAL_MAX_LIFETIME_SECONDS/);
    assert.match(header, /connected AF_UNIX socket/);
    assert.match(wiring, /bw_receive_and_consume_lifecycle_approval\(approval_socket_fd, &current\)/);
    assert.match(wiring, /CC_SHA256\(binary_bytes/);
    assert.match(wiring, /CC_SHA256\(plist_bytes/);
    assert.equal(/getenv\(|argv|--execute/.test(source), false);
  });

  it('rejects mismatched and replayed fixture receipts', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS libproc and native headers');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-approval-build-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-DBW_LIFECYCLE_APPROVAL_TESTING',
        '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-lifecycle-approval.c'),
        path.join(NATIVE, 'macos-lifecycle-approval-self-test.c'), '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        binding_mismatch_rejected: true,
        one_shot_consumed: true,
        replay_rejected: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
