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
const OPS = path.join(ROOT, 'native', 'macos-retained-file-ops.c');
const SELF_TEST = path.join(ROOT, 'native', 'macos-retained-file-ops-self-test.c');
const TOOL_ENV = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };

describe('native macOS retained-fd file ownership operations', () => {
  it('uses only retained descriptors for publication, verification, and cleanup', async () => {
    const source = await fs.readFile(OPS, 'utf8');
    for (const required of [
      'openat(parent_fd', 'O_CREAT | O_EXCL | O_NOFOLLOW', 'fstat(owned->file_fd',
      'fstatat(owned->parent_fd', 'AT_SYMLINK_NOFOLLOW', 'unlinkat(owned->parent_fd',
      'fsync(parent_fd)', 'st_dev', 'st_ino', 'st_nlink != 1',
    ]) assert.ok(source.includes(required), required);
    for (const forbidden of [
      /system\(/, /popen\(/, /exec[lv]p?\(/, /spawn/, /\/Library\//, /launchctl/,
      /dscl/, /sudo/, /Keychain/, /Bitwarden/, /https?:/, /remove\(/,
    ]) assert.equal(forbidden.test(source), false, forbidden);
  });

  it('rejects collisions and refuses to unlink a path-replaced foreign file', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires Apple openat/fstatat behavior and clang');
      return;
    }
    const tempBase = await fs.realpath(os.tmpdir());
    const fixturePrefix = 'bw-retained-file-ops.';
    const beforeFixtures = new Set(
      (await fs.readdir(tempBase)).filter((name) => name.startsWith(fixturePrefix)),
    );
    const root = await fs.mkdtemp(path.join(tempBase, 'bw-file-ops-test-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror', '-O2',
        OPS, SELF_TEST, '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        exclusive_create_verified: true,
        collision_preserved: true,
        normal_cleanup_verified: true,
        replacement_refused: true,
        replacement_preserved: true,
        name_snapshot_verified: true,
        cleanup_verified: true,
      });
    } finally {
      await fs.unlink(binary).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
      await fs.rmdir(root);
    }
    const afterFixtures = new Set(
      (await fs.readdir(tempBase)).filter((name) => name.startsWith(fixturePrefix)),
    );
    assert.deepEqual(afterFixtures, beforeFixtures);
  });

  it('accepts only the fixed self-test mode and leaves no fixture roots', async () => {
    const source = await fs.readFile(SELF_TEST, 'utf8');
    assert.match(source, /argc != 2/);
    assert.match(source, /strcmp\(argv\[1\], "--self-test"\)/);
    assert.match(source, /replacement_refused/);
    assert.match(source, /rmdir\(root\)/);
    for (const forbidden of [/\/Library\//, /launchctl/, /dscl/, /sudo/, /Keychain/, /Bitwarden/]) {
      assert.equal(forbidden.test(source), false, forbidden);
    }
  });
});
