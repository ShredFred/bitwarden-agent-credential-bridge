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

describe('native non-activating system Mach-name presence probe', () => {
  it('streams only launchctl print system with bounded hardened execution', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-launchctl-mach-presence.c'), 'utf8');
    assert.match(source, /char \*args\[\] = \{LAUNCHCTL, "print", "system", NULL\}/);
    assert.match(source, /SNAPSHOT_LIMIT \(8U \* 1024U \* 1024U\)/);
    assert.match(source, /POSIX_SPAWN_CLOEXEC_DEFAULT \| POSIX_SPAWN_SETPGROUP/);
    assert.match(source, /kill\(-child, SIGKILL\)/);
    assert.match(source, /stderr_total != 0 \|\| !ended_newline/);
    assert.match(source, /memcmp\(scanner->line \+ left \+ 1 \+ scanner->needle_length, "\\\" = \{"/);
    for (const forbidden of [
      /bootstrap_look_up/, /bootstrap_check_in/, /"bootstrap"/, /"kickstart"/,
      /"bootout"/, /system\(/, /popen\(/, /\/bin\/sh/,
    ]) assert.equal(forbidden.test(source), false, forbidden);
  });

  it('rejects token substrings and confirms fixed-name absence read-only', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS launchctl system domain');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-mach-presence-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-DBW_LAUNCHCTL_PRESENCE_TESTING',
        '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-fixed-command-runner.c'),
        path.join(NATIVE, 'macos-launchctl-mach-presence.c'),
        path.join(NATIVE, 'macos-mach-service-probes.c'),
        path.join(NATIVE, 'macos-fixed-system-probes.c'),
        path.join(NATIVE, 'macos-launchctl-mach-presence-self-test.c'), '-lbsm', '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        parser_exact: true,
        live_fixed_name_absent: true,
        bundle_absent: true,
        activation_attempted: false,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
