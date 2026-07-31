import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  DisposableWorkspaceError,
  createDisposableWorkspace,
  verifyDisposableWorkspace,
} from '../src/disposable-workspace.mjs';

const created = [];
afterEach(async () => Promise.all(created.splice(0).map((root) => fs.rm(root, { recursive: true, force: true }))));

describe('marked disposable workspace', () => {
  it('creates and verifies a real workspace under the canonical OS temp root', async () => {
    const workspace = await createDisposableWorkspace();
    created.push(workspace.root);
    assert.equal(await verifyDisposableWorkspace(workspace), true);
    assert.ok(path.relative(await fs.realpath(os.tmpdir()), workspace.root).startsWith('bw-agent-bridge-disposable-'));
    assert.equal(Object.isFrozen(workspace), true);
    assert.equal(Object.isFrozen(workspace.env), true);
  });

  it('derives a synthetic host layout without normal bridge application roots', async () => {
    const workspace = await createDisposableWorkspace();
    created.push(workspace.root);
    assert.equal(await verifyDisposableWorkspace(workspace), true);
    const serialized = JSON.stringify(workspace);
    assert.ok(serialized.includes('bw-agent-bridge-disposable-'));
    assert.ok(!serialized.includes('BitwardenAgentCredentialBridge'));
    assert.ok(!serialized.includes('bitwarden-agent-credential-bridge/config.json'));
    const otherPlatform = process.platform === 'win32' ? 'linux' : 'win32';
    await assert.rejects(
      () => createDisposableWorkspace({ platform: otherPlatform }),
      /platform_host_mismatch/,
    );
  });

  it('rejects marker tampering, replacement links, and layout changes', async () => {
    const workspace = await createDisposableWorkspace();
    created.push(workspace.root);
    await fs.writeFile(workspace.marker_path, '{"tampered":true}\n');
    await assert.rejects(() => verifyDisposableWorkspace(workspace), /marker_mismatch/);

    const replacement = path.join(workspace.root, 'replacement-marker');
    await fs.writeFile(replacement, 'replacement');
    await fs.rm(workspace.marker_path);
    await fs.symlink(replacement, workspace.marker_path);
    await assert.rejects(() => verifyDisposableWorkspace(workspace), /invalid_marker_file/);

    const layoutWorkspace = await createDisposableWorkspace();
    created.push(layoutWorkspace.root);
    const changed = { ...layoutWorkspace, env: { ...layoutWorkspace.env, EXTRA: path.join(layoutWorkspace.root, 'extra') } };
    await assert.rejects(() => verifyDisposableWorkspace(changed), /layout_mismatch/);
  });

  it('rejects unknown fields, accessors, bad nonces, and roots outside temp', async () => {
    const workspace = await createDisposableWorkspace();
    created.push(workspace.root);
    const accessor = { ...workspace };
    Object.defineProperty(accessor, 'nonce', { enumerable: true, get: () => workspace.nonce });
    for (const candidate of [
      { ...workspace, extra: true },
      { ...workspace, nonce: 'bad' },
      { ...workspace, root: path.parse(workspace.root).root },
      accessor,
    ]) await assert.rejects(() => verifyDisposableWorkspace(candidate), DisposableWorkspaceError);
  });
});
