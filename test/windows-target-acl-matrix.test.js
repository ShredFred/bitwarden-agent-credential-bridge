import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import process from 'node:process';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import {
  brandWindowsTargetAclEvidence,
  collectWindowsTargetAclEvidence,
  mapWindowsTargetAclMatrixProbeToEvidence,
  parseWindowsTargetAclMatrixProbeResult,
  WindowsTargetAclMatrixError,
} from '../src/windows-target-acl-matrix.mjs';
import { isWindowsTargetAclEvidence } from '../src/windows-production-authorization.mjs';

function incompleteProbe(overrides = {}) {
  return {
    schema_version: 1,
    persistent_root_present: false,
    service_running: false,
    helper_token_bound: false,
    all_targets_checked: false,
    caller_write_denied: false,
    helper_write_allowed: false,
    ownership_trusted_not_caller: false,
    shared_local_service_token_user_owner_absent: false,
    reparse_points_absent: false,
    authorization_ready: false,
    ...overrides,
  };
}

function completeProbe(overrides = {}) {
  return {
    schema_version: 1,
    persistent_root_present: true,
    service_running: true,
    helper_token_bound: true,
    all_targets_checked: true,
    caller_write_denied: true,
    helper_write_allowed: true,
    ownership_trusted_not_caller: true,
    shared_local_service_token_user_owner_absent: true,
    reparse_points_absent: true,
    authorization_ready: false,
    ...overrides,
  };
}

function persistentLayout() {
  return buildWindowsHelperLayoutPlan(buildWindowsServiceBoundaryPlan({
    platform: 'win32',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
  }), { layout_mode: 'persistent' });
}

describe('Windows target ACL matrix (Phase 9c)', () => {
  it('maps a complete probe into brandable Phase 9a target-ACL evidence', () => {
    const evidence = brandWindowsTargetAclEvidence(
      mapWindowsTargetAclMatrixProbeToEvidence(completeProbe()),
    );
    assert.equal(isWindowsTargetAclEvidence(evidence), true);
    assert.equal(isWindowsTargetAclEvidence({ ...evidence }), false);
    assert.equal(evidence.all_targets_checked, true);
    assert.equal(evidence.caller_write_denied, true);
    assert.equal(evidence.helper_write_allowed, true);
  });

  it('maps an incomplete probe without inventing success bits', () => {
    const evidence = mapWindowsTargetAclMatrixProbeToEvidence(incompleteProbe());
    assert.equal(evidence.all_targets_checked, false);
    assert.equal(evidence.caller_write_denied, false);
    assert.equal(evidence.helper_write_allowed, false);
  });

  it('rejects authorizing claims and incoherent complete/incomplete mixes', () => {
    assert.throws(
      () => parseWindowsTargetAclMatrixProbeResult(JSON.stringify(
        completeProbe({ authorization_ready: true }),
      )),
      (error) => error instanceof WindowsTargetAclMatrixError &&
        error.code === 'probe_authorization_claim',
    );
    assert.throws(
      () => parseWindowsTargetAclMatrixProbeResult(JSON.stringify(
        completeProbe({ service_running: false }),
      )),
      (error) => error instanceof WindowsTargetAclMatrixError &&
        error.code === 'incoherent_complete_matrix',
    );
    assert.throws(
      () => parseWindowsTargetAclMatrixProbeResult(JSON.stringify(
        incompleteProbe({ caller_write_denied: true }),
      )),
      (error) => error instanceof WindowsTargetAclMatrixError &&
        error.code === 'incoherent_incomplete_matrix',
    );
    assert.throws(
      () => parseWindowsTargetAclMatrixProbeResult(JSON.stringify({
        ...completeProbe(),
        extra: true,
      })),
      (error) => error instanceof WindowsTargetAclMatrixError,
    );
  });

  it('rejects disposable layouts and non-Windows platforms at the collector boundary', async () => {
    const disposable = buildWindowsHelperLayoutPlan(buildWindowsServiceBoundaryPlan({
      platform: 'win32',
      binarySha256: 'a'.repeat(64),
      binaryByteLength: 4096,
    }), { layout_mode: 'disposable' });
    await assert.rejects(
      () => collectWindowsTargetAclEvidence(disposable),
      (error) => error instanceof WindowsTargetAclMatrixError &&
        (error.code === 'invalid_persistent_layout' || error.code === 'unsupported_platform'),
    );
  });
});

describe('Windows target ACL matrix live probe (win32)', () => {
  it('collects an incomplete matrix when the persistent service root is absent', async (t) => {
    if (process.platform !== 'win32') {
      t.skip('Windows-only probe');
      return;
    }
    if (process.env.GITHUB_ACTIONS === 'true') {
      t.skip('live AccessCheck probe is not part of GitHub Actions CI');
      return;
    }
    const { evidence, report } = await collectWindowsTargetAclEvidence(persistentLayout());
    assert.equal(report.authorization_ready, false);
    assert.equal(report.operational_bridge_unwired, true);
    assert.equal(report.helper_vault_free, true);
    assert.equal(isWindowsTargetAclEvidence(evidence), true);
    // Without a running LocalService + ProgramData root the matrix cannot complete.
    if (!report.service_running || !report.persistent_root_present) {
      assert.equal(evidence.all_targets_checked, false);
      assert.equal(report.target_acl_evidence_complete, false);
      assert.equal(report.terminal_code, 'target_acl_matrix_incomplete');
    } else {
      // Leftover operator install: still never authorize the operational bridge.
      assert.equal(report.authorization_ready, false);
      assert.equal(typeof evidence.all_targets_checked, 'boolean');
    }
  });
});
