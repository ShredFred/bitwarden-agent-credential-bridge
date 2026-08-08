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
const SOURCES = [
  'macos-retained-file-ops.c', 'macos-account-ownership.c',
  'macos-launchd-job-ownership.c', 'macos-lifecycle-controller.c',
  'macos-lifecycle-controller-self-test.c',
].map((name) => path.join(NATIVE, name));
const TOOL_ENV = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };

describe('native macOS composite lifecycle controller', () => {
  it('orders preflight, mutation, denial, and reverse finally-cleanup exactly', async () => {
    // Normalize CRLF so Windows autocrlf checkouts keep this portable source contract.
    const source = (await fs.readFile(path.join(NATIVE, 'macos-lifecycle-controller.c'), 'utf8'))
      .replace(/\r\n/g, '\n');
    const ordered = [
      'bw_prepare_owned_account', 'bw_prepare_owned_launchd_job', 'bw_create_owned_account',
      'bw_publish_owned_file(\n      request->binary_parent_fd',
      'bw_publish_owned_file(\n      request->plist_parent_fd',
      'bw_bootstrap_owned_launchd_job', 'bw_activate_and_verify_owned_launchd_job',
      'bw_exercise_owned_launchd_denial', 'bw_cleanup_owned_launchd_job',
      'report.plist_cleanup_complete = file_cleanup',
      'report.binary_cleanup_complete = file_cleanup', 'bw_delete_owned_account',
    ];
    let cursor = -1;
    for (const token of ordered) {
      const next = source.indexOf(token, cursor + 1);
      assert.ok(next > cursor, token);
      cursor = next;
    }
    assert.match(source, /digest_matches\(request->binary_bytes/);
    assert.match(source, /digest_matches\(request->plist_bytes/);
    assert.match(source, /value\.st_uid == expected_owner/);
    assert.match(source, /value\.st_mode & 0022U/);
    assert.match(source, /manual_recovery_required = report\.cleanup_attempted && !report\.cleanup_complete/);
    assert.match(source, /report\.cleanup_attempted = mutation_attempted/);
    assert.match(source, /job_cleanup == BW_JOB_NO_EFFECT && !job\.bootstrap_attempted/);
  });

  it('runs clean and adversarial cross-layer scenarios with exact cleanup', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires Apple clang and CommonCrypto');
      return;
    }
    const tempBase = await fs.realpath(os.tmpdir());
    const fixturePrefix = 'bw-lifecycle-controller.';
    const before = new Set((await fs.readdir(tempBase)).filter((name) => name.startsWith(fixturePrefix)));
    const root = await fs.mkdtemp(path.join(tempBase, 'bw-controller-build-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror',
        '-Wno-deprecated-declarations', '-O2', ...SOURCES, '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        clean_complete: true,
        collision_no_mutation: true,
        account_ambiguity_preserved: true,
        ambiguous_create_reported: true,
        ambiguous_activation_cleaned: true,
        binding_failure_no_job_mutation: true,
        foreign_plist_preserved: true,
        fixture_cleanup: true,
      });
    } finally {
      await fs.unlink(binary).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
      await fs.rmdir(root);
    }
    const after = new Set((await fs.readdir(tempBase)).filter((name) => name.startsWith(fixturePrefix)));
    assert.deepEqual(after, before);
  });

  it('contains no real account, launchd, elevation, network, or credential adapter', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-lifecycle-controller.c'), 'utf8');
    for (const forbidden of [
      /system\(/, /popen\(/, /exec[lv]p?\(/, /spawn/, /launchctl/, /dscl/, /sudo/,
      /Keychain/, /Bitwarden/, /https?:/, /AuthorizationCreate/,
    ]) assert.equal(forbidden.test(source), false, forbidden);
  });
});
