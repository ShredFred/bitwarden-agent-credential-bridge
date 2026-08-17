import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
  OperationalBridgeError,
} from '../src/operational-bridge.mjs';
import {
  absentWindowsOperationalAuthorization,
  buildCompleteOperationalAuthorizationEvidenceForHarness,
  buildIncompleteOperationalAuthorizationEvidence,
  composeWindowsOperationalAuthorization,
  isWindowsOperationalAuthorizationReport,
  WindowsOperationalAuthorizationError,
} from '../src/windows-operational-authorization.mjs';
import { brandWindowsPeerAuthorizationEvidence } from '../src/windows-persistent-peer-session.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

describe('Windows operational authorization (Phase 9e)', () => {
  it('wires incomplete branded evidence to authorization_ready false', () => {
    const report = composeWindowsOperationalAuthorization(
      buildIncompleteOperationalAuthorizationEvidence(),
    );
    assert.equal(isWindowsOperationalAuthorizationReport(report), true);
    assert.equal(isWindowsOperationalAuthorizationReport({ ...report }), false);
    assert.equal(report.operational_bridge_unwired, false);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.terminal_code, 'production_authorization_incomplete');
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.helper_vault_free, true);
    assert.equal(report.personal_vault_forbidden, true);
    assert.equal(report.company_vault_forbidden, true);
  });

  it('default absent path is wired but still false', () => {
    const report = absentWindowsOperationalAuthorization();
    assert.equal(report.operational_bridge_unwired, false);
    assert.equal(report.authorization_ready, false);
  });

  it('sets authorization_ready true only with synthetic complete branded fixtures', () => {
    const report = composeWindowsOperationalAuthorization(
      buildCompleteOperationalAuthorizationEvidenceForHarness(),
    );
    assert.equal(report.operational_bridge_unwired, false);
    assert.equal(report.authorization_ready, true);
    assert.equal(report.terminal_code, 'production_authorization_ready');
    assert.equal(report.mutation_authorized, false);
  });

  it('rejects forged and unbranded evidence bundles', () => {
    const complete = buildCompleteOperationalAuthorizationEvidenceForHarness();
    assert.throws(
      () => composeWindowsOperationalAuthorization({
        installGateReport: { ...complete.installGateReport },
        layoutPlan: complete.layoutPlan,
        handleBoundEvidence: complete.handleBoundEvidence,
        targetAclEvidence: complete.targetAclEvidence,
        peerEvidence: complete.peerEvidence,
      }),
      (error) => error instanceof WindowsOperationalAuthorizationError &&
        error.code === 'unbranded_install_gate',
    );
    assert.throws(
      () => composeWindowsOperationalAuthorization({
        installGateReport: complete.installGateReport,
        layoutPlan: complete.layoutPlan,
        handleBoundEvidence: complete.handleBoundEvidence,
        targetAclEvidence: complete.targetAclEvidence,
        peerEvidence: {
          local_transport: true,
          identity_verified: true,
          different_principal: true,
          caller_write_denied: true,
          helper_write_allowed: true,
        },
      }),
      (error) => error instanceof WindowsOperationalAuthorizationError &&
        error.code === 'unbranded_peer_evidence',
    );
    assert.throws(
      () => composeWindowsOperationalAuthorization({
        installGateReport: complete.installGateReport,
        layoutPlan: complete.layoutPlan,
        handleBoundEvidence: complete.handleBoundEvidence,
        targetAclEvidence: complete.targetAclEvidence,
        peerEvidence: brandWindowsPeerAuthorizationEvidence({
          local_transport: true,
          identity_verified: true,
          different_principal: true,
          caller_write_denied: true,
          helper_write_allowed: true,
        }),
        extra: true,
      }),
      (error) => error instanceof WindowsOperationalAuthorizationError &&
        error.code === 'invalid_evidence_bundle',
    );
  });

  it('operational bridge default path is wired and remains false', async () => {
    const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    const bridge = await startOperationalBridge({ repoRoot: root, bindings });
    try {
      assert.equal(bridge.operational_authorization_wired, true);
      assert.equal(bridge.authorization_ready, false);
      assert.equal(
        bridge.production_authorization_terminal_code,
        'production_authorization_incomplete',
      );
      assert.equal(bridge.personal_vault_forbidden, true);
      assert.equal(bridge.company_vault_forbidden, true);
      assert.equal(bridge.helper_vault_free, true);
    } finally {
      await bridge.close();
    }
  });

  it('operational bridge copies authorization_ready from complete synthetic evidence', async () => {
    const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    const bridge = await startOperationalBridge({
      repoRoot: root,
      bindings,
      platform: 'win32',
      productionAuthorizationEvidence: buildCompleteOperationalAuthorizationEvidenceForHarness(),
    });
    try {
      assert.equal(bridge.operational_authorization_wired, true);
      assert.equal(bridge.authorization_ready, true);
      assert.equal(
        bridge.production_authorization_terminal_code,
        'production_authorization_ready',
      );
      assert.equal(bridge.mutation_authorized ?? false, false);
    } finally {
      await bridge.close();
    }
  });

  it('operational bridge rejects forged production evidence', async () => {
    const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    const complete = buildCompleteOperationalAuthorizationEvidenceForHarness();
    await assert.rejects(
      () => startOperationalBridge({
        repoRoot: root,
        bindings,
        platform: 'win32',
        productionAuthorizationEvidence: {
          ...complete,
          peerEvidence: { ...complete.peerEvidence },
        },
      }),
      (error) => error instanceof OperationalBridgeError &&
        error.code === 'unbranded_peer_evidence',
    );
  });
});
