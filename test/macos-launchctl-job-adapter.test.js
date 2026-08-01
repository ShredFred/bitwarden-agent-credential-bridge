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

describe('native macOS fixed launchctl job adapter', () => {
  it('contains only fixed system-domain job mutations and injected Mach probes', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-launchctl-job-adapter.c'), 'utf8');
    assert.match(source, /#define LAUNCHCTL "\/bin\/launchctl"/);
    assert.match(source, /#define SERVICE_TARGET "system\/" LABEL/);
    assert.match(source, /"bootstrap", "system", PLIST_PATH/);
    assert.match(source, /"kickstart", SERVICE_TARGET/);
    assert.match(source, /"kill", "SIGTERM", SERVICE_TARGET/);
    assert.match(source, /"bootout", SERVICE_TARGET/);
    assert.match(source, /adapter->mach_presence/);
    assert.match(source, /adapter->denial/);
    assert.match(source, /adapter->artifacts/);
    assert.match(source, /key_count == 1 && expected_count == 1/);
    assert.match(source, /found_count == 1 && found_pid > 1/);
    for (const forbidden of [/system\(/, /popen\(/, /\/bin\/sh/, /sudo/, /dscl/]) {
      assert.equal(forbidden.test(source), false, forbidden);
    }
  });

  it('proves exact lifecycle and rejects malformed loaded-job identity', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS native build');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-launchctl-adapter-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-launchd-job-ownership.c'),
        path.join(NATIVE, 'macos-launchctl-job-adapter.c'),
        path.join(NATIVE, 'macos-launchctl-job-adapter-self-test.c'), '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        clean_lifecycle: true,
        malformed_collision: true,
        duplicate_pid_rejected: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
