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

describe('fixed macOS sudo lifecycle launcher', () => {
  it('contains one fixed sudo-k invocation and no generic command surface', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-sudo-lifecycle-launcher.c'), 'utf8');
    const header = await fs.readFile(path.join(NATIVE, 'macos-sudo-lifecycle-launcher.h'), 'utf8');
    assert.match(source, /#define SUDO_PATH "\/usr\/bin\/sudo"/);
    assert.match(source, /#define RUNNER_PATH "\/Library\/PrivilegedHelperTools\//);
    assert.match(source, /\(char \*\)SUDO_PATH, "-k", "--", \(char \*\)RUNNER_PATH/);
    assert.match(source, /POSIX_SPAWN_CLOEXEC_DEFAULT \| POSIX_SPAWN_SETPGROUP/);
    assert.match(source, /bw_fixed_executable_is_secure\(SUDO_PATH\)/);
    assert.match(source, /bw_fixed_executable_is_secure\(RUNNER_PATH\)/);
    assert.match(source, /controlling_tty_available\(\)/);
    assert.match(source, /pthread_create/);
    assert.match(source, /pthread_join/);
    assert.match(source, /exact_runner_process/);
    assert.match(source, /stop_exact_runner\(approval_context\.runner_pid\)/);
    assert.match(source, /#define CHILD_TIMEOUT_MS 130000/);
    assert.match(source, /bw_answer_lifecycle_approval_challenge/);
    assert.match(source, /kill\(-child, SIGKILL\)/);
    assert.match(header, /There is no executable, argv, environment, command, or output configuration/);
    for (const forbidden of [/system\(/, /popen\(/, /\/bin\/sh/, /getenv\(/, /exec[lv]p?\(/]) {
      assert.equal(forbidden.test(source), false, forbidden);
    }
  });

  it('runs the full duplex challenge and exact value-free result fixture', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS spawn, libproc, ACL, and native headers');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-sudo-launcher-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-DBW_LIFECYCLE_APPROVAL_TESTING',
        '-DBW_SUDO_LAUNCHER_TESTING', '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-fixed-command-runner.c'),
        path.join(NATIVE, 'macos-lifecycle-approval.c'),
        path.join(NATIVE, 'macos-sudo-lifecycle-launcher.c'),
        path.join(NATIVE, 'macos-sudo-lifecycle-launcher-self-test.c'), '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE',
        `-DBW_LAUNCHER_BINDING_HEADER=\"${path.join(ROOT, 'test', 'fixtures', 'macos-launcher-bindings.h')}\"`,
        '-Wall', '-Wextra', '-Werror', '-O2', '-c',
        path.join(NATIVE, 'macos-sudo-lifecycle-launcher.c'),
        '-o', path.join(root, 'production-launcher.o'),
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 10000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        child_started: true,
        challenge_answered: true,
        child_exited_cleanly: true,
        denial_verified: true,
        cleanup_complete: true,
      });
      const fixture = await fs.readFile(
        path.join(NATIVE, 'macos-sudo-lifecycle-launcher-self-test.c'), 'utf8');
      assert.match(fixture, /\(descriptor_flags & FD_CLOEXEC\) == 0/);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
