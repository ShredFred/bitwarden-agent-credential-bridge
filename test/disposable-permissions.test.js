import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  DisposablePermissionError,
  createDisposablePermissionSetter,
  secureDisposableWorkspace,
} from '../src/disposable-permissions.mjs';
import { createDisposableWorkspace } from '../src/disposable-workspace.mjs';
import { createWindowsSecurityAdapter } from '../src/windows-security-adapter.mjs';

const created = [];
afterEach(async () => Promise.all(created.splice(0).map((root) => fs.rm(root, { recursive: true, force: true }))));

describe('disposable permission setter', () => {
  it('uses a silent bounded argument-array Windows process contract', { skip: process.platform !== 'win32' }, async () => {
    const workspace = await createDisposableWorkspace();
    created.push(workspace.root);
    let invocation;
    const setter = createDisposablePermissionSetter(workspace, {
      powershellPath: 'powershell-test.exe',
      scriptPath: 'C:\\safe setter.ps1',
      timeoutMs: 1234,
      execFileImpl: (file, args, options, callback) => {
        invocation = { file, args, options };
        callback(null, '', '');
      },
    });
    await setter(workspace.marker_path, 'file');
    assert.equal(invocation.file, 'powershell-test.exe');
    assert.equal(invocation.args.at(-2), workspace.marker_path);
    assert.equal(invocation.args.at(-1), 'file');
    assert.deepEqual(invocation.options, { windowsHide: true, timeout: 1234, maxBuffer: 1024, encoding: 'utf8' });
  });

  it('hardens a real Windows workspace, directory, and file and verifies the ACLs', { skip: process.platform !== 'win32' }, async () => {
    const workspace = await createDisposableWorkspace();
    created.push(workspace.root);
    assert.equal(await secureDisposableWorkspace(workspace), true);
    const childDir = path.join(workspace.root, 'child');
    const childFile = path.join(childDir, 'file.txt');
    await fs.mkdir(childDir);
    await fs.writeFile(childFile, 'non-secret');
    const setter = createDisposablePermissionSetter(workspace);
    await setter(childDir, 'directory');
    await setter(childFile, 'file');
    const inspect = createWindowsSecurityAdapter();
    for (const target of [workspace.root, workspace.marker_path, childDir, childFile]) {
      assert.deepEqual(await inspect(target), {
        reparsePoint: false,
        ownerCurrentUser: true,
        writableByOtherUsers: false,
      });
    }
  });

  it('rejects outside paths, links, wrong types, process noise, and process failures', async () => {
    const workspace = await createDisposableWorkspace();
    created.push(workspace.root);
    const target = path.join(workspace.root, 'target.txt');
    const link = path.join(workspace.root, 'link.txt');
    await fs.writeFile(target, 'non-secret');
    await fs.symlink(target, link);
    const setter = createDisposablePermissionSetter(workspace, {
      execFileImpl: (_file, _args, _options, callback) => callback(null, 'noise', ''),
    });
    await assert.rejects(() => setter(path.dirname(workspace.root), 'directory'), /target_outside_workspace/);
    await assert.rejects(() => setter(link, 'file'), /unsafe_target/);
    await assert.rejects(() => setter(target, 'directory'), /unsafe_target/);
    if (process.platform === 'win32') {
      await assert.rejects(() => setter(target, 'file'), /permission_update_failed/);
    }
    assert.throws(() => createDisposablePermissionSetter(workspace, { timeoutMs: 0 }), /invalid_timeout/);
    await assert.rejects(() => setter(target, 'invalid'), DisposablePermissionError);
  });
});
