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
const FIXTURE = path.join(ROOT, 'test', 'fixtures', 'macos-runner-artifacts.h');
const TOOL_ENV = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };
const SOURCES = [
  'macos-fixed-command-runner.c', 'macos-retained-file-ops.c', 'macos-account-ownership.c',
  'macos-launchd-job-ownership.c', 'macos-dscl-directory-adapter.c',
  'macos-launchctl-job-adapter.c', 'macos-lifecycle-controller.c',
  'macos-lifecycle-approval.c', 'macos-elevation-identity.c',
  'macos-native-lifecycle-wiring.c',
  'macos-launchctl-mach-presence.c', 'macos-mach-service-probes.c',
  'macos-fixed-system-probes.c', 'macos-lifecycle-runner.c',
].map((name) => path.join(NATIVE, name));

describe('fixed macOS privileged lifecycle runner', () => {
  it('wires only embedded reviewed artifacts and the fixed native lifecycle', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-lifecycle-runner.c'), 'utf8');
    assert.match(source, /#error "BW_RUNNER_ARTIFACT_HEADER/);
    assert.match(source, /strcmp\(argv\[1\], MODE\)/);
    assert.match(source, /getuid\(\) == 0 \|\| geteuid\(\) != 0/);
    assert.match(source, /open\(BINARY_PARENT, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW \| O_CLOEXEC\)/);
    assert.match(source, /open\(PLIST_PARENT, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW \| O_CLOEXEC\)/);
    assert.match(source, /bw_init_fixed_system_probes/);
    assert.match(source, /bw_init_native_lifecycle_wiring/);
    assert.match(source, /bw_receive_and_consume_lifecycle_approval\(STDIN_FILENO, &approval_bindings\)/);
    assert.match(source, /bw_run_lifecycle\(&wiring\.request\)/);
    assert.ok(source.indexOf('bw_receive_and_consume_lifecycle_approval') <
      source.indexOf('open(BINARY_PARENT'));
    assert.match(source, /uuid_generate_random/);
    for (const forbidden of [/getenv\(/, /system\(/, /popen\(/, /\/bin\/sh/, /Keychain/, /Bitwarden/, /https?:/]) {
      assert.equal(forbidden.test(source), false, forbidden);
    }
  });

  it('builds the complete production composition and rejects ambient execution', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS native frameworks and headers');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-runner-build-'));
    const binary = path.join(root, 'runner');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE',
        `-DBW_RUNNER_ARTIFACT_HEADER=\"${FIXTURE}\"`,
        '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-O2',
        ...SOURCES, '-lbsm', '-o', binary,
      ], { timeout: 20000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      await assert.rejects(
        execFileAsync(binary, [], { timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV }),
        (error) => error.code === 64 && error.stdout === '' && error.stderr === '',
      );
      await assert.rejects(
        execFileAsync(binary, ['--approved-denial-lifecycle'], {
          timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
        }),
        (error) => error.code === 77 && error.stdout === '' && error.stderr === '',
      );
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
