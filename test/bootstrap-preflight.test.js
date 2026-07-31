import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { auditBootstrapHost } from '../src/bootstrap-preflight.mjs';

const cleanup = [];
afterEach(async () => Promise.all(cleanup.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true }))));

async function posixFixture() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-preflight-'));
  cleanup.push(root);
  const installRoot = path.join(root, 'install');
  const configPath = path.join(root, 'config.json');
  const launcherPath = path.join(installRoot, 'bridge');
  await fs.mkdir(installRoot, { mode: 0o700 });
  await fs.writeFile(configPath, '{not-read}', { mode: 0o600 });
  await fs.writeFile(launcherPath, 'fake-launcher', { mode: 0o700 });
  await fs.chmod(installRoot, 0o700);
  await fs.chmod(configPath, 0o600);
  await fs.chmod(launcherPath, 0o700);
  const uid = (await fs.lstat(configPath)).uid;
  return { roots: { configPath, installRoot, launcherPath }, uid, digest: createHash('sha256').update('fake-launcher').digest('hex') };
}

describe('read-only bootstrap host preflight', () => {
  it('passes secure POSIX metadata and launcher integrity without reading config contents', async () => {
    const fixture = await posixFixture();
    const reads = [];
    const fsApi = {
      lstat: async (target) => ({
        isSymbolicLink: () => false,
        isFile: () => target !== fixture.roots.installRoot,
        isDirectory: () => target === fixture.roots.installRoot,
        uid: fixture.uid,
        mode: target === fixture.roots.configPath ? 0o100600 : target === fixture.roots.installRoot ? 0o40700 : 0o100700,
      }),
      readFile: async (target) => { reads.push(target); return fs.readFile(target); },
    };
    const result = await auditBootstrapHost({ platform: 'linux', roots: fixture.roots, fsApi, currentUid: fixture.uid, expectedLauncherSha256: fixture.digest });
    assert.equal(result.ready, true, JSON.stringify(result));
    assert.deepEqual(reads, [fixture.roots.launcherPath]);
  });

  it('rejects POSIX links, unsafe modes, owner mismatch, and digest mismatch', async () => {
    const fixture = await posixFixture();
    await fs.chmod(fixture.roots.configPath, 0o644);
    await fs.rm(fixture.roots.launcherPath);
    await fs.symlink(fixture.roots.configPath, fixture.roots.launcherPath);
    const result = await auditBootstrapHost({ platform: 'darwin', roots: fixture.roots, currentUid: fixture.uid + 1, expectedLauncherSha256: '0'.repeat(64) });
    assert.equal(result.ready, false);
    assert.deepEqual(result.checks.map((check) => [check.id, check.reason]), [
      ['config', 'owner_mismatch'],
      ['install_root', 'owner_mismatch'],
      ['launcher', 'link_rejected'],
    ]);
  });

  it('fails closed on Windows without a security adapter', async () => {
    const stats = { isSymbolicLink: () => false, isFile: () => true, isDirectory: () => true };
    const fsApi = { lstat: async () => stats };
    const result = await auditBootstrapHost({ platform: 'win32', roots: { configPath: 'C:\\cfg', installRoot: 'C:\\app', launcherPath: 'C:\\app\\bridge.cmd' }, fsApi });
    assert.equal(result.ready, false);
    assert.ok(result.checks.every((check) => check.reason === 'windows_security_unavailable'));
  });

  it('accepts only exact value-free Windows security results', async () => {
    const stats = { isSymbolicLink: () => false, isFile: () => true, isDirectory: () => true };
    const fsApi = { lstat: async () => stats };
    const roots = { configPath: 'C:\\cfg', installRoot: 'C:\\app', launcherPath: 'C:\\app\\bridge.cmd' };
    const secure = await auditBootstrapHost({ platform: 'win32', roots, fsApi, windowsSecurity: async () => ({ reparsePoint: false, ownerCurrentUser: true, writableByOtherUsers: false }) });
    assert.equal(secure.ready, true);
    for (const adapter of [
      async () => ({ reparsePoint: true, ownerCurrentUser: true, writableByOtherUsers: false }),
      async () => ({ reparsePoint: false, ownerCurrentUser: false, writableByOtherUsers: false }),
      async () => ({ reparsePoint: false, ownerCurrentUser: true, writableByOtherUsers: false, rawAcl: 'secret-principal' }),
      async () => { throw new Error('raw sensitive command output'); },
    ]) {
      const result = await auditBootstrapHost({ platform: 'win32', roots, fsApi, windowsSecurity: adapter });
      assert.equal(result.ready, false);
      assert.ok(!JSON.stringify(result).includes('secret-principal'));
      assert.ok(!JSON.stringify(result).includes('raw sensitive'));
    }
  });

  it('returns fixed value-free failures for missing targets and invalid digests', async () => {
    const roots = { configPath: '/private/user/item-id', installRoot: '/private/user/install', launcherPath: '/private/user/launcher' };
    const fsApi = { lstat: async () => { throw new Error('sensitive OS error'); } };
    const missing = await auditBootstrapHost({ platform: 'linux', roots, fsApi, currentUid: 1 });
    const invalidDigest = await auditBootstrapHost({ platform: 'linux', roots, fsApi, currentUid: 1, expectedLauncherSha256: 'bad' });
    assert.ok(!JSON.stringify(missing).includes('/private'));
    assert.ok(!JSON.stringify(missing).includes('sensitive'));
    assert.equal(invalidDigest.checks[0].reason, 'invalid_expected_digest');
  });
});
