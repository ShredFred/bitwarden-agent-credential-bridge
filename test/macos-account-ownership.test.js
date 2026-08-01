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
const SOURCE = path.join(ROOT, 'native', 'macos-account-ownership.c');
const FIXTURE = path.join(ROOT, 'native', 'macos-account-ownership-self-test.c');
const TOOL_ENV = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };

describe('native macOS account soft-ownership core', () => {
  it('binds prepare, create, verify, and delete to the full identity tuple', async () => {
    const source = await fs.readFile(SOURCE, 'utf8');
    for (const required of [
      'probe_name', 'probe_unique_id', 'probe_generated_uid', 'same_record',
      'owned->identity = *candidate', 'owned->created = true', 'owned->verified = true',
      'bw_verify_owned_account(ops, owned)', 'ops->delete_record(ops->context, &owned->identity)',
    ]) assert.ok(source.includes(required), required);
    assert.match(source, /strcmp\(left->generated_uid, right->generated_uid\)/);
    assert.match(source, /strcmp\(left->shell, right->shell\)/);
    assert.match(source, /strcmp\(left->home, right->home\)/);
    for (const forbidden of [
      /system\(/, /popen\(/, /exec[lv]p?\(/, /spawn/, /dscl/, /launchctl/, /sudo/,
      /\/Library\//, /Keychain/, /Bitwarden/, /https?:/,
    ]) assert.equal(forbidden.test(source), false, forbidden);
  });

  it('proves clean deletion while preserving collisions and identity-swapped records', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires Apple clang');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-account-test-'));
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
        clean_lifecycle: true,
        collision_no_effect: true,
        post_create_drift_ambiguous: true,
        drift_never_deleted: true,
        delete_race_preserved: true,
      });
    } finally {
      await fs.unlink(binary).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
      await fs.rmdir(root);
    }
  });

  it('keeps the fixture adapter local and accepts only its fixed self-test mode', async () => {
    const fixture = await fs.readFile(FIXTURE, 'utf8');
    assert.match(fixture, /argc != 2/);
    assert.match(fixture, /post_create_drift_ambiguous/);
    assert.match(fixture, /drift_never_deleted/);
    assert.match(fixture, /delete_race_preserved/);
    assert.match(fixture, /!drift_delete\.delete_called/);
    for (const forbidden of [/dscl/, /launchctl/, /sudo/, /\/Library\//, /Keychain/, /Bitwarden/]) {
      assert.equal(forbidden.test(fixture), false, forbidden);
    }
  });
});
