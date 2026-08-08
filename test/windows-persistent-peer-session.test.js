import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import process from 'node:process';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import {
  brandWindowsPeerAuthorizationEvidence,
  isWindowsPeerAuthorizationEvidence,
  mapWindowsPersistentPeerSessionToEvidence,
  parseWindowsServiceDenialClientReport,
  WindowsPersistentPeerSessionError,
} from '../src/windows-persistent-peer-session.mjs';
import { evaluateWindowsProductionAuthorization } from '../src/windows-production-authorization.mjs';

function denialClient(overrides = {}) {
  return {
    schema_version: 1,
    narrow_pipe_rights: true,
    create_pipe_instance_right_absent: true,
    response_schema_exact: true,
    different_principal: true,
    authorization_denied: true,
    ...overrides,
  };
}

function verifiedIdentity(overrides = {}) {
  return {
    schema_version: 1,
    local_pipe_connected: true,
    server_pid_bound: true,
    scm_service_running: true,
    scm_server_pid_match: true,
    server_token_bound: true,
    server_token_user_local_service: true,
    service_sid_group_enabled: true,
    server_identity_verified: true,
    request_sent: false,
    authorization_denied: true,
    ...overrides,
  };
}

function completeAcl(overrides = {}) {
  return {
    schema_version: 1,
    all_targets_checked: true,
    caller_write_denied: true,
    helper_write_allowed: true,
    ownership_trusted_not_caller: true,
    shared_local_service_token_user_owner_absent: true,
    reparse_points_absent: true,
    ...overrides,
  };
}

describe('Windows persistent peer session (Phase 9d)', () => {
  it('maps a verified LocalService denial + ACL into complete five-facts', () => {
    const peer = mapWindowsPersistentPeerSessionToEvidence({
      denialClient: denialClient(),
      identity: verifiedIdentity(),
      targetAcl: completeAcl(),
      pipeConnected: true,
    });
    assert.deepEqual(peer, {
      local_transport: true,
      identity_verified: true,
      different_principal: true,
      caller_write_denied: true,
      helper_write_allowed: true,
    });
    const branded = brandWindowsPeerAuthorizationEvidence(peer);
    assert.equal(isWindowsPeerAuthorizationEvidence(branded), true);
    assert.equal(isWindowsPeerAuthorizationEvidence({ ...branded }), false);
  });

  it('does not invent different_principal from client report alone', () => {
    const peer = mapWindowsPersistentPeerSessionToEvidence({
      denialClient: denialClient(),
      identity: {
        ...verifiedIdentity(),
        server_identity_verified: false,
        server_token_user_local_service: false,
        service_sid_group_enabled: false,
        scm_service_running: false,
        scm_server_pid_match: false,
      },
      targetAcl: completeAcl(),
      pipeConnected: true,
    });
    assert.equal(peer.local_transport, true);
    assert.equal(peer.identity_verified, false);
    assert.equal(peer.different_principal, false);
  });

  it('keeps an absent-pipe host incomplete / same-principal style false', () => {
    const peer = mapWindowsPersistentPeerSessionToEvidence({
      denialClient: null,
      identity: null,
      targetAcl: {
        schema_version: 1,
        all_targets_checked: false,
        caller_write_denied: false,
        helper_write_allowed: false,
        ownership_trusted_not_caller: false,
        shared_local_service_token_user_owner_absent: false,
        reparse_points_absent: false,
      },
      pipeConnected: false,
    });
    assert.deepEqual(peer, {
      local_transport: false,
      identity_verified: false,
      different_principal: false,
      caller_write_denied: false,
      helper_write_allowed: false,
    });
  });

  it('keeps write facts false until the ACL matrix is complete', () => {
    const peer = mapWindowsPersistentPeerSessionToEvidence({
      denialClient: denialClient(),
      identity: verifiedIdentity(),
      targetAcl: completeAcl({
        all_targets_checked: false,
        caller_write_denied: false,
        helper_write_allowed: false,
        ownership_trusted_not_caller: false,
        shared_local_service_token_user_owner_absent: false,
        reparse_points_absent: false,
      }),
      pipeConnected: true,
    });
    assert.equal(peer.different_principal, true);
    assert.equal(peer.caller_write_denied, false);
    assert.equal(peer.helper_write_allowed, false);
  });

  it('rejects malformed denial client reports', () => {
    assert.throws(
      () => parseWindowsServiceDenialClientReport(JSON.stringify({
        ...denialClient(),
        authorization_denied: false,
      })),
      (error) => error instanceof WindowsPersistentPeerSessionError,
    );
    assert.throws(
      () => parseWindowsServiceDenialClientReport(JSON.stringify({
        ...denialClient(),
        extra: true,
      })),
      (error) => error instanceof WindowsPersistentPeerSessionError,
    );
  });

  it('feeds branded peer five-facts into the Phase 9a compiler without wiring the bridge', async () => {
    // Import harness helpers from production authorization tests' pattern via dynamic eval
    // of the public APIs only — peer object remains an exact plain five-fact shape.
    const { brandWindowsHandleBoundIdentityEvidenceForHarness,
      brandWindowsTargetAclEvidenceForHarness } = await import(
      '../src/windows-production-authorization.mjs'
    );
    const { evaluateWindowsServiceInstallGate } = await import(
      '../src/windows-service-install-gate.mjs'
    );
    const { buildWindowsServiceLifecycleGate } = await import(
      '../src/windows-service-lifecycle-gate.mjs'
    );
    const {
      evaluateLiveCollectorResult,
      brandWindowsServiceLifecycleLiveReportForHarness,
    } = await import('../src/windows-service-lifecycle-live.mjs');

    const boundary = buildWindowsServiceBoundaryPlan({
      platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
    });
    const gate = buildWindowsServiceLifecycleGate(boundary);
    const live = brandWindowsServiceLifecycleLiveReportForHarness(evaluateLiveCollectorResult(gate, {
      schema_version: 1,
      terminal_outcome: 'denial_verified',
      events: [
        ...gate.pre_mutation_steps,
        ...gate.mutation_steps,
        ...gate.always_cleanup_steps,
      ].map((step) => ({ step, status: 'verified' })),
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
    const installGate = evaluateWindowsServiceInstallGate(gate, live, {
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
    });
    const layout = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'persistent' });
    const peer = mapWindowsPersistentPeerSessionToEvidence({
      denialClient: denialClient(),
      identity: verifiedIdentity(),
      targetAcl: completeAcl(),
      pipeConnected: true,
    });
    const report = evaluateWindowsProductionAuthorization(
      installGate,
      layout,
      brandWindowsHandleBoundIdentityEvidenceForHarness({
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
      }),
      brandWindowsTargetAclEvidenceForHarness(completeAcl()),
      peer,
    );
    assert.equal(report.authorization_ready, true);
    assert.equal(report.operational_bridge_unwired, true);
    assert.equal(report.mutation_authorized, false);
  });
});

describe('Windows persistent peer session live (win32)', () => {
  it('maps absent-pipe incomplete facts without inventing authorization', async (t) => {
    if (process.platform !== 'win32') {
      t.skip('Windows-only');
      return;
    }
    // Full collect() publishes the native helper; keep default tests publish-free.
    // Operator live: npm run live:windows-persistent-peer-session
    const peer = mapWindowsPersistentPeerSessionToEvidence({
      denialClient: null,
      identity: null,
      targetAcl: {
        schema_version: 1,
        all_targets_checked: false,
        caller_write_denied: false,
        helper_write_allowed: false,
        ownership_trusted_not_caller: false,
        shared_local_service_token_user_owner_absent: false,
        reparse_points_absent: false,
      },
      pipeConnected: false,
    });
    assert.equal(peer.different_principal, false);
    assert.equal(brandWindowsPeerAuthorizationEvidence(peer).local_transport, false);
  });
});
