import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import {
  buildWindowsHelperDisposableApplyEnvelope,
  executeWindowsHelperDisposableApplySimulation,
  isWindowsHelperDisposableApplyEnvelope,
  WindowsHelperDisposableApplyError,
} from '../src/windows-helper-disposable-apply.mjs';

function authorizeRequest() {
  return {
    protocol_version: 1,
    request_id: 'req-' + 'a'.repeat(16),
    operation: 'apply_disposable_manifest',
    workspace: {
      platform: 'win32',
      root_digest: 'b'.repeat(64),
      marker_nonce: 'c'.repeat(64),
    },
    manifest_digest: 'd'.repeat(64),
    launcher: { sha256: 'e'.repeat(64), byte_length: 32 },
  };
}

describe('Windows helper disposable apply', () => {
  it('builds a branded deny-until-execute envelope and simulates apply', async () => {
    const boundary = buildWindowsServiceBoundaryPlan({
      platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 32,
    });
    const layout = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'disposable' });
    const envelope = buildWindowsHelperDisposableApplyEnvelope(layout, authorizeRequest());
    assert.equal(isWindowsHelperDisposableApplyEnvelope(envelope), true);
    assert.equal(envelope.helper_vault_free, true);
    assert.equal(envelope.mutation_authorized, false);
    assert.equal(envelope.authorize.authorization_denied, true);

    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-apply-sim-'));
    try {
      const report = await executeWindowsHelperDisposableApplySimulation(envelope, {
        root,
        launcherBytes: Buffer.alloc(32, 7),
      });
      assert.equal(report.applied, true);
      assert.equal(report.digest_matched, true);
      assert.equal(report.helper_vault_free, true);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it('rejects persistent layouts and forged envelopes', () => {
    const boundary = buildWindowsServiceBoundaryPlan({
      platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 32,
    });
    const persistent = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'persistent' });
    assert.throws(
      () => buildWindowsHelperDisposableApplyEnvelope(persistent, authorizeRequest()),
      (error) => error instanceof WindowsHelperDisposableApplyError,
    );
  });
});
