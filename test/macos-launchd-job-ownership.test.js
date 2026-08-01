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
const SOURCE = path.join(ROOT, 'native', 'macos-launchd-job-ownership.c');
const FIXTURE = path.join(ROOT, 'native', 'macos-launchd-job-ownership-self-test.c');
const TOOL_ENV = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };

describe('native macOS launchd job soft-ownership core', () => {
  it('binds bootstrap, activation, denial, stop, and bootout to one exact job', async () => {
    const source = await fs.readFile(SOURCE, 'utf8');
    for (const required of [
      'probe_label', 'probe_mach_service', 'same_record', 'ops->bootstrap', 'ops->read_job',
      'ops->activate', 'ops->verify_process', 'ops->exercise_denial', 'ops->stop_process',
      'ops->bootout', 'bw_verify_owned_launchd_job(ops, owned)',
    ]) assert.ok(source.includes(required), required);
    assert.match(source, /strcmp\(left->binary_sha256, right->binary_sha256\)/);
    assert.match(source, /strcmp\(left->plist_sha256, right->plist_sha256\)/);
    assert.match(source, /cleanup_failed \? BW_JOB_AMBIGUOUS : BW_JOB_OK/);
    for (const forbidden of [
      /system\(/, /popen\(/, /exec[lv]p?\(/, /spawn/, /launchctl/, /dscl/, /sudo/,
      /Keychain/, /Bitwarden/, /https?:/,
    ]) assert.equal(forbidden.test(source), false, forbidden);
  });

  it('proves collision safety, denial, ambiguous activation cleanup, and foreign preservation', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires Apple clang');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-launchd-job-test-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror', '-O2',
        SOURCE, FIXTURE, '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        clean_denial_cleanup: true,
        collision_no_effect: true,
        bootstrap_drift_not_owned: true,
        ambiguous_activation_cleaned: true,
        activation_error_cleaned: true,
        foreign_swap_preserved: true,
        bootout_race_preserved: true,
        cleanup_continues_after_stop_failure: true,
      });
    } finally {
      await fs.unlink(binary).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
      await fs.rmdir(root);
    }
  });

  it('keeps the fault adapter local and accepts only fixed self-test mode', async () => {
    const fixture = await fs.readFile(FIXTURE, 'utf8');
    assert.match(fixture, /argc != 2/);
    for (const scenario of [
      'bootstrap_drift_not_owned', 'ambiguous_activation_cleaned', 'activation_error_cleaned',
      'foreign_swap_preserved',
      'bootout_race_preserved', 'cleanup_continues_after_stop_failure',
    ]) assert.ok(fixture.includes(scenario), scenario);
    for (const forbidden of [/launchctl/, /dscl/, /sudo/, /Keychain/, /Bitwarden/, /https?:/]) {
      assert.equal(forbidden.test(fixture), false, forbidden);
    }
  });
});
