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

describe('native macOS fixed Mach denial probe', () => {
  it('binds the denial reply to protocol, nonce, PID, EUID, and PID generation', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-mach-service-probes.c'), 'utf8');
    assert.match(source, /MACH_RCV_TRAILER_AUDIT/);
    assert.match(source, /audit_token_to_pid\(trailer->msgh_audit\) == expected_pid/);
    assert.match(source, /audit_token_to_euid\(trailer->msgh_audit\) == expected_euid/);
    assert.match(source, /audit_token_to_pidversion\(trailer->msgh_audit\) > 0/);
    assert.match(source, /proc_pidinfo\(pid, PROC_PIDTBSDINFO/);
    assert.match(source, /before->start_seconds == after->start_seconds/);
    assert.match(source, /strcmp\(before->path, after->path\) == 0/);
    assert.match(source, /mach_msg_destroy\(&buffer\.reply\.header\)/);
    assert.match(source, /buffer\.reply\.authorization_denied == 1u/);
    assert.match(source, /memcmp\(buffer\.reply\.nonce, nonce, NONCE_BYTES\) == 0/);
    assert.match(source, /helper_uid != geteuid\(\)/);
  });

  it('runs an exact private-bootstrap denial exchange without the production name', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires Mach bootstrap and audit trailers');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-mach-probe-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-DBW_MACH_PROBE_TESTING',
        '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-O2',
        path.join(NATIVE, 'macos-mach-service-probes.c'),
        path.join(NATIVE, 'macos-mach-service-probes-self-test.c'), '-lbsm', '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        request_served: true,
        client_verified: true,
        audit_bound_denial: true,
        wrong_pid_rejected: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
