import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildLinuxSystemdBoundaryPlan } from '../src/linux-systemd-boundary-plan.mjs';
import {
  buildLinuxHelperLayoutPlan,
  isLinuxHelperLayoutPlan,
  LinuxHelperLayoutPlanError,
} from '../src/linux-helper-layout-plan.mjs';
import {
  buildLinuxSystemdLifecycleGate,
  isLinuxSystemdLifecycleGate,
} from '../src/linux-systemd-lifecycle-gate.mjs';
import { evaluateLinuxSystemdLifecycleTranscript } from '../src/linux-systemd-lifecycle-evidence.mjs';
import {
  buildLinuxSystemdLifecycleCollectorContract,
  evaluateLinuxSystemdLifecycleCollectorTrust,
} from '../src/linux-systemd-lifecycle-collector-trust.mjs';
import {
  brandLinuxSystemdLifecycleLiveReportForHarness,
  evaluateLinuxSystemdInstallGate,
  isLinuxSystemdInstallGateReport,
  LinuxSystemdInstallGateError,
} from '../src/linux-systemd-install-gate.mjs';
import {
  buildLinuxHelperAuthorizeEnvelope,
  isLinuxHelperAuthorizeEnvelope,
  LinuxHelperAuthorizeEnvelopeError,
} from '../src/linux-helper-authorize-envelope.mjs';

function boundary() {
  return buildLinuxSystemdBoundaryPlan({
    platform: 'linux',
    serviceManager: 'systemd-system',
    binarySha256: 'd'.repeat(64),
    binaryByteLength: 8192,
  });
}

function gate() {
  return buildLinuxSystemdLifecycleGate(boundary());
}

function completeTranscript(value) {
  return {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [
      ...value.pre_mutation_steps,
      ...value.mutation_steps,
      ...value.always_cleanup_steps,
    ].map((step) => ({ step, status: 'verified' })),
  };
}

function completeProvenance() {
  return {
    schema_version: 1,
    elevated_token_verified: true,
    local_only_collection: true,
    retained_handle_binding_complete: true,
    path_reacquisition_absent: true,
    value_free_emission_verified: true,
    stderr_absent: true,
    gate_step_surface_matched: true,
    cleanup_finally_bound: true,
    root_euid_reported: true,
    systemd_system_manager_reported: true,
    initial_user_namespace_reported: true,
  };
}

function successLive(value) {
  const trust = evaluateLinuxSystemdLifecycleCollectorTrust(
    value,
    completeTranscript(value),
    completeProvenance(),
  );
  return brandLinuxSystemdLifecycleLiveReportForHarness({
    schema_version: 1,
    preflight_claim_structurally_complete: trust.preflight_claim_structurally_complete,
    mutation_claim_structurally_complete: trust.mutation_claim_structurally_complete,
    denial_claim_structurally_complete: trust.denial_claim_structurally_complete,
    cleanup_claim_structurally_complete: trust.cleanup_claim_structurally_complete,
    final_absence_claim_structurally_complete: trust.final_absence_claim_structurally_complete,
    transcript_structure_complete: trust.transcript_structure_complete,
    required_provenance_complete: trust.required_provenance_complete,
    collector_trust_verified: trust.collector_trust_verified,
    live_test_executed: true,
    live_test_verified: true,
    mutation_authorized: false,
    install_gate_eligible: false,
    authorization_ready: false,
    terminal_code: 'live_denial_verified_cleaned',
  });
}

function absentPreflight() {
  return {
    schema_version: 1,
    account_present: false,
    service_unit_present: false,
    socket_unit_present: false,
    binary_present: false,
    socket_path_present: false,
    binary_binding_verified: false,
    unit_fragments_match_plan: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  };
}

describe('Linux Phase 12 pure gate stack', () => {
  it('builds layout plans that forbid home/XDG writer roots', () => {
    const plan = boundary();
    const disposable = buildLinuxHelperLayoutPlan(plan, { layout_mode: 'disposable' });
    const persistent = buildLinuxHelperLayoutPlan(plan, { layout_mode: 'persistent' });
    assert.equal(isLinuxHelperLayoutPlan(disposable), true);
    assert.equal(disposable.home_profile_root_forbidden, true);
    assert.equal(disposable.xdg_user_runtime_root_forbidden, true);
    assert.equal(disposable.dynamic_user_forbidden, true);
    assert.equal(disposable.authorization_ready, false);
    assert.equal(persistent.persistent_uninstall_proof_required, true);
    assert.equal(JSON.stringify(disposable).includes('/home'), false);
    assert.throws(
      () => buildLinuxHelperLayoutPlan(plan, { layout_mode: 'user_xdg' }),
      (error) => error instanceof LinuxHelperLayoutPlanError &&
        error.code === 'unsupported_layout_mode',
    );
  });

  it('builds a branded lifecycle gate and validates a complete transcript', () => {
    const value = gate();
    assert.equal(isLinuxSystemdLifecycleGate(value), true);
    assert.equal(value.scope.dynamic_user_forbidden, true);
    assert.equal(value.authorization_ready, false);
    const structure = evaluateLinuxSystemdLifecycleTranscript(value, completeTranscript(value));
    assert.equal(structure.transcript_structure_complete, true);
    assert.equal(structure.collector_trust_verified, false);
    assert.equal(structure.authorization_ready, false);
  });

  it('compiles collector trust without live verification', () => {
    const value = gate();
    const contract = buildLinuxSystemdLifecycleCollectorContract(value);
    assert.equal(contract.live_test_verified, false);
    const trust = evaluateLinuxSystemdLifecycleCollectorTrust(
      value,
      completeTranscript(value),
      completeProvenance(),
    );
    assert.equal(trust.collector_trust_verified, true);
    assert.equal(trust.live_test_verified, false);
    assert.equal(trust.authorization_ready, false);
  });

  it('marks install_gate_eligible only for branded disposable live denial', () => {
    const value = gate();
    const report = evaluateLinuxSystemdInstallGate(value, successLive(value), absentPreflight());
    assert.equal(isLinuxSystemdInstallGateReport(report), true);
    assert.equal(report.install_gate_eligible, true);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.terminal_code, 'install_gate_eligible_disposable_verified');
    assert.throws(
      () => evaluateLinuxSystemdInstallGate(value, {
        schema_version: 1,
        preflight_claim_structurally_complete: true,
        mutation_claim_structurally_complete: true,
        denial_claim_structurally_complete: true,
        cleanup_claim_structurally_complete: true,
        final_absence_claim_structurally_complete: true,
        transcript_structure_complete: true,
        required_provenance_complete: true,
        collector_trust_verified: true,
        live_test_executed: true,
        live_test_verified: true,
        mutation_authorized: false,
        install_gate_eligible: false,
        authorization_ready: false,
        terminal_code: 'live_denial_verified_cleaned',
      }, absentPreflight()),
      (error) => error instanceof LinuxSystemdInstallGateError &&
        error.code === 'unbranded_live_report',
    );
  });

  it('builds a vault-free authorize envelope only for disposable layouts', () => {
    const value = gate();
    const install = evaluateLinuxSystemdInstallGate(value, successLive(value), absentPreflight());
    const disposable = buildLinuxHelperLayoutPlan(boundary(), { layout_mode: 'disposable' });
    const envelope = buildLinuxHelperAuthorizeEnvelope(install, disposable);
    assert.equal(isLinuxHelperAuthorizeEnvelope(envelope), true);
    assert.equal(envelope.authorize_eligible, true);
    assert.equal(envelope.mutation_authorized, false);
    assert.equal(envelope.authorization_ready, false);
    assert.equal(envelope.helper_vault_free, true);
    const persistent = buildLinuxHelperLayoutPlan(boundary(), { layout_mode: 'persistent' });
    assert.throws(
      () => buildLinuxHelperAuthorizeEnvelope(install, persistent),
      (error) => error instanceof LinuxHelperAuthorizeEnvelopeError &&
        error.code === 'persistent_layout_forbidden_for_envelope',
    );
  });
});
