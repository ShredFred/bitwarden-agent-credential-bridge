import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsServiceLifecycleGate } from '../src/windows-service-lifecycle-gate.mjs';
import {
  evaluateLiveCollectorResult,
  brandWindowsServiceLifecycleLiveReportForHarness,
} from '../src/windows-service-lifecycle-live.mjs';
import { evaluateWindowsServiceInstallGate } from '../src/windows-service-install-gate.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import {
  brandWindowsHandleBoundIdentityEvidenceForHarness,
  brandWindowsTargetAclEvidenceForHarness,
  evaluateWindowsProductionAuthorization,
  isWindowsProductionAuthorizationReport,
  WindowsProductionAuthorizationError,
} from '../src/windows-production-authorization.mjs';

function lifecycleGate() {
  return buildWindowsServiceLifecycleGate(buildWindowsServiceBoundaryPlan({
    platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
  }));
}

function event(step, status = 'verified') {
  return { step, status };
}

function successLive(value) {
  return brandWindowsServiceLifecycleLiveReportForHarness(evaluateLiveCollectorResult(value, {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [
      ...value.pre_mutation_steps,
      ...value.mutation_steps,
      ...value.always_cleanup_steps,
    ].map((step) => event(step)),
    provenance: {
      schema_version: 1,
      elevated_token_verified: true,
      local_only_collection: true,
      retained_handle_binding_complete: true,
      path_reacquisition_absent: true,
      value_free_emission_verified: true,
      stderr_absent: true,
      gate_step_surface_matched: true,
      cleanup_finally_bound: true,
      uac_consent_observed: true,
      admin_group_present: true,
      high_integrity_reported: true,
    },
  }));
}

function absentPreflight() {
  return {
    schema_version: 1,
    service_present: false,
    account_local_service: false,
    demand_start: false,
    win32_own_process: false,
    service_sid_unrestricted: false,
    caller_service_control_denied: false,
    binary_binding_verified: false,
    binary_chain_reparse_free: false,
    binary_owner_trusted: false,
    caller_binary_control_denied: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  };
}

function eligibleInstallGate() {
  const value = lifecycleGate();
  return evaluateWindowsServiceInstallGate(value, successLive(value), absentPreflight());
}

function persistentLayout() {
  return buildWindowsHelperLayoutPlan(buildWindowsServiceBoundaryPlan({
    platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
  }), { layout_mode: 'persistent' });
}

function completeHandleBound(overrides = {}) {
  return brandWindowsHandleBoundIdentityEvidenceForHarness({
    schema_version: 1,
    pipe_local_only: true,
    remote_clients_rejected: true,
    server_pid_handle_bound: true,
    server_token_user_local_service: true,
    server_service_sid_enabled: true,
    scm_service_running_same_pid: true,
    binary_digest_matched_via_handle: true,
    binary_chain_reparse_free: true,
    binary_owner_trusted: true,
    caller_service_control_denied: true,
    service_dacl_caller_change_denied: true,
    path_based_preflight_only: false,
    collector_value_free: true,
    ...overrides,
  });
}

function completeTargetAcl(overrides = {}) {
  return brandWindowsTargetAclEvidenceForHarness({
    schema_version: 1,
    all_targets_checked: true,
    caller_write_denied: true,
    helper_write_allowed: true,
    ownership_trusted_not_caller: true,
    shared_local_service_token_user_owner_absent: true,
    reparse_points_absent: true,
    ...overrides,
  });
}

function completePeer(overrides = {}) {
  return {
    local_transport: true,
    identity_verified: true,
    different_principal: true,
    caller_write_denied: true,
    helper_write_allowed: true,
    ...overrides,
  };
}

describe('Windows production authorization (Phase 9a)', () => {
  it('sets authorization_ready only when every production evidence class is complete', () => {
    const report = evaluateWindowsProductionAuthorization(
      eligibleInstallGate(),
      persistentLayout(),
      completeHandleBound(),
      completeTargetAcl(),
      completePeer(),
    );
    assert.equal(isWindowsProductionAuthorizationReport(report), true);
    assert.equal(isWindowsProductionAuthorizationReport({ ...report }), false);
    assert.equal(report.authorization_ready, true);
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.helper_vault_free, true);
    assert.equal(report.personal_vault_forbidden, true);
    assert.equal(report.company_vault_forbidden, true);
    assert.equal(report.operational_bridge_unwired, true);
    assert.equal(report.install_gate_eligible_alone_insufficient, true);
    assert.equal(report.terminal_code, 'production_authorization_ready');
  });

  it('keeps authorization_ready false when handle-bound identity is incomplete', () => {
    const report = evaluateWindowsProductionAuthorization(
      eligibleInstallGate(),
      persistentLayout(),
      completeHandleBound({ server_pid_handle_bound: false }),
      completeTargetAcl(),
      completePeer(),
    );
    assert.equal(report.authorization_ready, false);
    assert.equal(report.handle_bound_identity_verified, false);
    assert.equal(report.terminal_code, 'production_authorization_incomplete');
  });

  it('keeps authorization_ready false when target ACL matrix is incomplete', () => {
    const report = evaluateWindowsProductionAuthorization(
      eligibleInstallGate(),
      persistentLayout(),
      completeHandleBound(),
      completeTargetAcl({ all_targets_checked: false }),
      completePeer(),
    );
    assert.equal(report.authorization_ready, false);
    assert.equal(report.target_acl_evidence_complete, false);
  });

  it('keeps authorization_ready false when peer five-facts are incomplete', () => {
    const report = evaluateWindowsProductionAuthorization(
      eligibleInstallGate(),
      persistentLayout(),
      completeHandleBound(),
      completeTargetAcl(),
      completePeer({ different_principal: false }),
    );
    assert.equal(report.authorization_ready, false);
    assert.equal(report.peer_authorization_complete, false);
  });

  it('rejects path-based advisory preflight posing as handle-bound evidence', () => {
    assert.throws(
      () => evaluateWindowsProductionAuthorization(
        eligibleInstallGate(),
        persistentLayout(),
        completeHandleBound({ path_based_preflight_only: true }),
        completeTargetAcl(),
        completePeer(),
      ),
      (error) => error instanceof WindowsProductionAuthorizationError &&
        error.code === 'path_based_preflight_insufficient',
    );
  });

  it('rejects forged/unbranded inputs and disposable layout', () => {
    const gate = eligibleInstallGate();
    const layout = persistentLayout();
    const identity = completeHandleBound();
    const acl = completeTargetAcl();
    const peer = completePeer();

    assert.throws(
      () => evaluateWindowsProductionAuthorization({ ...gate }, layout, identity, acl, peer),
      (error) => error instanceof WindowsProductionAuthorizationError &&
        error.code === 'unbranded_install_gate',
    );
    assert.throws(
      () => evaluateWindowsProductionAuthorization(gate, { ...layout }, identity, acl, peer),
      (error) => error instanceof WindowsProductionAuthorizationError &&
        error.code === 'invalid_persistent_layout',
    );
    assert.throws(
      () => evaluateWindowsProductionAuthorization(
        gate,
        buildWindowsHelperLayoutPlan(buildWindowsServiceBoundaryPlan({
          platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
        }), { layout_mode: 'disposable' }),
        identity,
        acl,
        peer,
      ),
      (error) => error instanceof WindowsProductionAuthorizationError &&
        error.code === 'invalid_persistent_layout',
    );
    assert.throws(
      () => evaluateWindowsProductionAuthorization(gate, layout, { ...identity }, acl, peer),
      (error) => error instanceof WindowsProductionAuthorizationError &&
        error.code === 'unbranded_handle_bound_evidence',
    );
    assert.throws(
      () => evaluateWindowsProductionAuthorization(gate, layout, identity, { ...acl }, peer),
      (error) => error instanceof WindowsProductionAuthorizationError &&
        error.code === 'unbranded_target_acl_evidence',
    );
    assert.throws(
      () => evaluateWindowsProductionAuthorization(gate, layout, identity, acl, {
        ...peer,
        extra: true,
      }),
      (error) => error instanceof WindowsProductionAuthorizationError &&
        error.code === 'invalid_peer_evidence',
    );
  });
});
