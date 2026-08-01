import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { verifyMacosCodeSnapshot } from '../src/macos-code-snapshot-verifier.mjs';
import { digestDesignatedRequirementStdout } from '../src/macos-launchd-boundary-rules.mjs';

const execFileAsync = promisify(execFile);
describe('macOS fd-content code snapshot verifier', () => {
  it('rejects invalid bytes and requirement bindings without creating a snapshot', async () => {
    await withIsolatedTempBase(async () => {
      assert.equal(await verifyMacosCodeSnapshot(Buffer.alloc(0), 'a'.repeat(64)), false);
      assert.equal(await verifyMacosCodeSnapshot(Buffer.from('not signed'), 'invalid'), false);
    });
  });

  it('verifies a signed Apple binary snapshot and removes every temporary artifact', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const bytes = await fs.readFile('/bin/ls');
    const { stdout } = await execFileAsync('/usr/bin/codesign', ['-d', '-r-', '--', '/bin/ls'], {
      encoding: 'utf8', maxBuffer: 64 * 1024,
    });
    const requirementDigest = digestDesignatedRequirementStdout(stdout);
    assert.match(requirementDigest, /^[0-9a-f]{64}$/);
    await withIsolatedTempBase(async () => {
      assert.equal(await verifyMacosCodeSnapshot(bytes, requirementDigest), true);
      assert.equal(await verifyMacosCodeSnapshot(
        bytes,
        createHash('sha256').update('wrong requirement').digest('hex'),
      ), false);
    });
  });

  it('runs Apple verification for unsigned bytes and fails closed with exact cleanup', {
    skip: process.platform !== 'darwin',
  }, async () => {
    await withIsolatedTempBase(async () => {
      assert.equal(await verifyMacosCodeSnapshot(
        Buffer.from('unsigned fixture bytes'),
        'a'.repeat(64),
      ), false);
    });
  });

  it('rejects successful measurement when mandatory directory cleanup fails', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const isolatedBase = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-agent-cleanup-test-'));
    try {
      const fixture = path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        'fixtures',
        'macos-code-snapshot-cleanup-failure.mjs',
      );
      const { stdout, stderr } = await execFileAsync(process.execPath, [fixture], {
        encoding: 'utf8',
        timeout: 5000,
        maxBuffer: 4096,
        env: {
          PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
          LANG: 'C',
          LC_ALL: 'C',
          TMPDIR: isolatedBase,
        },
      });
      assert.equal(stdout, 'cleanup_failure_rejected\n');
      assert.equal(stderr, '');
    } finally {
      await fs.rmdir(isolatedBase);
    }
  });
});

async function withIsolatedTempBase(callback) {
  const original = process.env.TMPDIR;
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-agent-snapshot-test-'));
  process.env.TMPDIR = base;
  try {
    await callback();
    assert.deepEqual(await fs.readdir(base), []);
  } finally {
    if (original === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = original;
    await fs.rmdir(base);
  }
}
