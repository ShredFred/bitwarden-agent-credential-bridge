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

describe('native macOS fixed dscl directory adapter', () => {
  it('allows only the fixed account and fixed argument-array operations', async () => {
    const source = await fs.readFile(path.join(NATIVE, 'macos-dscl-directory-adapter.c'), 'utf8');
    assert.match(source, /#define DSCL "\/usr\/bin\/dscl"/);
    assert.match(source, /#define ACCOUNT "_bwagentbridge"/);
    assert.match(source, /"-search", "\/Users"/);
    assert.match(source, /"-read", ACCOUNT_PATH/);
    assert.match(source, /"-delete", ACCOUNT_PATH/);
    assert.match(source, /BW_ACCOUNT_AMBIGUOUS/);
    for (const forbidden of [/system\(/, /popen\(/, /\/bin\/sh/, /sudo/, /launchctl/]) {
      assert.equal(forbidden.test(source), false, forbidden);
    }
  });

  it('proves clean lifecycle and rejects malformed or partial results', async (context) => {
    if (process.platform !== 'darwin') {
      context.skip('requires macOS native headers');
      return;
    }
    const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'bw-dscl-adapter-'));
    const binary = path.join(root, 'self-test');
    try {
      await execFileAsync('/usr/bin/clang', [
        '-std=c17', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror', '-O2',
        path.join(NATIVE, 'macos-account-ownership.c'),
        path.join(NATIVE, 'macos-dscl-directory-adapter.c'),
        path.join(NATIVE, 'macos-dscl-directory-adapter-self-test.c'), '-o', binary,
      ], { timeout: 15000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV });
      const result = await execFileAsync(binary, ['--self-test'], {
        timeout: 5000, maxBuffer: 4096, encoding: 'utf8', env: TOOL_ENV,
      });
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        schema_version: 1,
        clean_lifecycle: true,
        malformed_rejected: true,
        partial_ambiguous: true,
        swapped_delete_refused: true,
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
