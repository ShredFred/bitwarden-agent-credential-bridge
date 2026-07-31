import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import { afterEach, describe, it } from 'node:test';
import { buildApplyManifest } from '../src/apply-manifest.mjs';
import {
  DisposableApplyError,
  executeDisposableManifest,
  observeDisposableState,
  prepareDisposableScaffold,
} from '../src/disposable-executor.mjs';
import { createDisposableWorkspace } from '../src/disposable-workspace.mjs';

const created = [];
afterEach(async () => Promise.all(created.splice(0).map((root) => fs.rm(root, { recursive: true, force: true }))));

const absent = {
  config_dir: 'absent', config_file: 'absent', install_root: 'absent', bin_dir: 'absent', launcher: { kind: 'absent' },
};

async function setup(bytes, observed = absent) {
  const workspace = await createDisposableWorkspace();
  created.push(workspace.root);
  await prepareDisposableScaffold(workspace);
  const manifest = buildApplyManifest({
    platform: workspace.platform,
    homedir: workspace.homedir,
    env: workspace.env,
    launcherBytes: bytes,
    observed,
  });
  return { workspace, manifest };
}

describe('disposable manifest executor', () => {
  it('performs a real first install and idempotent reinstall only inside the workspace', async () => {
    const bytes = Buffer.from('fake launcher v1');
    const { workspace, manifest } = await setup(bytes);
    const result = await executeDisposableManifest({ workspace, manifest, confirmation: manifest.confirmation, launcherBytes: bytes });
    assert.equal(result.status, 'applied');
    assert.equal(await fs.readFile(manifest.payload.paths.launcher, 'utf8'), 'fake launcher v1');
    assert.equal(await fs.readFile(manifest.payload.paths.config_file, 'utf8'), '{"version":1,"services":{}}\n');
    const observed = await observeDisposableState(workspace, manifest);
    const reinstall = buildApplyManifest({ platform: workspace.platform, homedir: workspace.homedir, env: workspace.env, launcherBytes: bytes, observed });
    assert.deepEqual(reinstall.payload.forward, []);
    assert.equal((await executeDisposableManifest({ workspace, manifest: reinstall, confirmation: reinstall.confirmation, launcherBytes: bytes })).completed_actions, 0);
  });

  it('performs a real upgrade and removes the committed backup', async () => {
    const v1 = Buffer.from('fake launcher v1');
    const first = await setup(v1);
    await executeDisposableManifest({ workspace: first.workspace, manifest: first.manifest, confirmation: first.manifest.confirmation, launcherBytes: v1 });
    const observed = await observeDisposableState(first.workspace, first.manifest);
    const v2 = Buffer.from('fake launcher v2');
    const upgrade = buildApplyManifest({ platform: first.workspace.platform, homedir: first.workspace.homedir, env: first.workspace.env, launcherBytes: v2, observed });
    await executeDisposableManifest({ workspace: first.workspace, manifest: upgrade, confirmation: upgrade.confirmation, launcherBytes: v2 });
    assert.equal(await fs.readFile(upgrade.payload.paths.launcher, 'utf8'), 'fake launcher v2');
    const backup = upgrade.payload.forward.find((action) => action.kind === 'assert_path_absent').target;
    await assert.rejects(() => fs.lstat(backup), { code: 'ENOENT' });
  });

  it('rolls back a first install after injected failure without deleting the workspace marker', async () => {
    const bytes = Buffer.from('fake rollback launcher');
    const { workspace, manifest } = await setup(bytes);
    await assert.rejects(
      () => executeDisposableManifest({ workspace, manifest, confirmation: manifest.confirmation, launcherBytes: bytes, options: { failAfterSequence: 4 } }),
      (error) => error instanceof DisposableApplyError && error.code === 'injected_failure' && error.rollback === 'completed',
    );
    assert.equal((await fs.lstat(workspace.marker_path)).isFile(), true);
    for (const target of Object.values(manifest.payload.paths)) {
      await assert.rejects(() => fs.lstat(target), { code: 'ENOENT' });
    }
  });

  it('rolls back a directory created before a Windows permission-setter failure', { skip: process.platform !== 'win32' }, async () => {
    const bytes = Buffer.from('fake permission failure launcher');
    const { workspace, manifest } = await setup(bytes);
    const setterFailure = Object.assign(new Error('synthetic setter failure'), { code: 1 });
    await assert.rejects(
      () => executeDisposableManifest({
        workspace,
        manifest,
        confirmation: manifest.confirmation,
        launcherBytes: bytes,
        options: {
          execFileImpl: (_file, _args, _options, callback) => callback(setterFailure, '', ''),
        },
      }),
      (error) => error instanceof DisposableApplyError && error.code === 'action_failed' && error.rollback === 'completed',
    );
    await assert.rejects(() => fs.lstat(manifest.payload.paths.config_dir), { code: 'ENOENT' });
  });

  it('restores v1 when an upgrade fails after moving the old launcher', async () => {
    const v1 = Buffer.from('fake launcher original');
    const first = await setup(v1);
    await executeDisposableManifest({ workspace: first.workspace, manifest: first.manifest, confirmation: first.manifest.confirmation, launcherBytes: v1 });
    const observed = await observeDisposableState(first.workspace, first.manifest);
    const v2 = Buffer.from('fake launcher replacement');
    const upgrade = buildApplyManifest({ platform: first.workspace.platform, homedir: first.workspace.homedir, env: first.workspace.env, launcherBytes: v2, observed });
    await assert.rejects(
      () => executeDisposableManifest({ workspace: first.workspace, manifest: upgrade, confirmation: upgrade.confirmation, launcherBytes: v2, options: { failAfterSequence: 2 } }),
      (error) => error instanceof DisposableApplyError && error.rollback === 'completed',
    );
    assert.equal(await fs.readFile(upgrade.payload.paths.launcher, 'utf8'), 'fake launcher original');
  });

  it('restores v1 when an upgrade fails after publishing v2 but before commit', async () => {
    const v1 = Buffer.from('fake launcher original two');
    const first = await setup(v1);
    await executeDisposableManifest({ workspace: first.workspace, manifest: first.manifest, confirmation: first.manifest.confirmation, launcherBytes: v1 });
    const observed = await observeDisposableState(first.workspace, first.manifest);
    const v2 = Buffer.from('fake launcher replacement two');
    const upgrade = buildApplyManifest({ platform: first.workspace.platform, homedir: first.workspace.homedir, env: first.workspace.env, launcherBytes: v2, observed });
    await assert.rejects(
      () => executeDisposableManifest({ workspace: first.workspace, manifest: upgrade, confirmation: upgrade.confirmation, launcherBytes: v2, options: { failAfterSequence: 3 } }),
      (error) => error instanceof DisposableApplyError && error.rollback === 'completed',
    );
    assert.equal(await fs.readFile(upgrade.payload.paths.launcher, 'utf8'), 'fake launcher original two');
  });

  it('rejects wrong confirmation, launcher bytes, and changed observed state before mutation', async () => {
    const bytes = Buffer.from('fake launcher');
    const { workspace, manifest } = await setup(bytes);
    await assert.rejects(() => executeDisposableManifest({ workspace, manifest, confirmation: 'APPLY wrong', launcherBytes: bytes }), /confirmation_rejected/);
    await assert.rejects(() => executeDisposableManifest({ workspace, manifest, confirmation: manifest.confirmation, launcherBytes: Buffer.from('wrong') }), /manifest_workspace_mismatch/);
    await fs.mkdir(manifest.payload.paths.config_dir);
    await assert.rejects(() => executeDisposableManifest({ workspace, manifest, confirmation: manifest.confirmation, launcherBytes: bytes }), /observed_state_changed|unsafe_permissions/);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), manifest.payload.content.launcher_sha256);
  });
});
