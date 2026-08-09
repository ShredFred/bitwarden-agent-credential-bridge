import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildMacosLaunchdBoundaryPlan } from '../src/macos-launchd-boundary-plan.mjs';
import { buildMacosLaunchdLifecycleGate } from '../src/macos-launchd-lifecycle-gate.mjs';
import {
  buildMacosLaunchdLifecycleCollectorContract,
  evaluateMacosLaunchdLifecycleCollectorTrust,
  isMacosLaunchdLifecycleCollectorContract,
} from '../src/macos-launchd-lifecycle-collector-trust.mjs';
import {
  brandMacosLaunchdLifecycleLiveReportForHarness,
  evaluateMacosLaunchdInstallGate,
  isMacosLaunchdInstallGateReport,
  MacosLaunchdInstallGateError,
} from '../src/macos-launchd-install-gate.mjs';
import {
  buildMacosHelperLayoutPlan,
  isMacosHelperLayoutPlan,
  MacosHelperLayoutPlanError,
} from '../src/macos-helper-layout-plan.mjs';

function boundary() {
  return buildMacosLaunchdBoundaryPlan({
    platform: 'darwin',
    serviceManager: 'launchd-system',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
    designatedRequirementSha256: 'b'.repeat(64),
    plistSha256: 'c'.repeat(64),
  });
}

function gate() {
  return buildMacosLaunchdLifecycleGate(boundary());
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
    sudo_consent_observed: true,
    root_euid_reported: true,
    system_domain_reported: true,
  };
}

function successLive(value) {
  const trust = evaluateMacosLaunchdLifecycleCollectorTrust(
    value,
    completeTranscript(value),
    completeProvenance(),
  );
  return brandMacosLaunchdLifecycleLiveReportForHarness({
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
    plist_present: false,
    binary_present: false,
    label_loaded: false,
    mach_service_bound: false,
    binary_binding_verified: false,
    designated_requirement_verified: false,
    parent_chain_policy_matched: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  };
}

describe('macOS Phase 11a collector trust + install gate', () => {
  it('builds a branded collector-trust contract', () => {
    const value = gate();
    const contract = buildMacosLaunchdLifecycleCollectorContract(value);
    assert.equal(isMacosLaunchdLifecycleCollectorContract(contract), true);
    assert.equal(isMacosLaunchdLifecycleCollectorContract({ ...contract }), false);
    assert.equal(contract.authorization_ready, false);
    assert.equal(contract.mutation_authorized, false);
    assert.equal(contract.requirements.same_euid_helper_forbidden, true);
  });

  it('verifies collector trust schema without claiming live verification', () => {
    const value = gate();
    const trust = evaluateMacosLaunchdLifecycleCollectorTrust(
      value,
      completeTranscript(value),
      completeProvenance(),
    );
    assert.equal(trust.collector_trust_verified, true);
    assert.equal(trust.live_test_verified, false);
    assert.equal(trust.authorization_ready, false);
    assert.equal(trust.terminal_code, 'collector_trust_schema_satisfied_unlive');
  });

  it('marks install_gate_eligible only after branded disposable live denial', () => {
    const value = gate();
    const report = evaluateMacosLaunchdInstallGate(value, successLive(value), absentPreflight());
    assert.equal(isMacosLaunchdInstallGateReport(report), true);
    assert.equal(isMacosLaunchdInstallGateReport({ ...report }), false);
    assert.equal(report.install_gate_eligible, true);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.keychain_access_forbidden, true);
    assert.equal(report.terminal_code, 'install_gate_eligible_disposable_verified');
  });

  it('rejects unbranded live reports and authorizing preflight', () => {
    const value = gate();
    assert.throws(
      () => evaluateMacosLaunchdInstallGate(value, {
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
      (error) => error instanceof MacosLaunchdInstallGateError &&
        error.code === 'unbranded_live_report',
    );
    assert.throws(
      () => evaluateMacosLaunchdInstallGate(value, successLive(value), {
        ...absentPreflight(),
        authorization_ready: true,
      }),
      (error) => error instanceof MacosLaunchdInstallGateError &&
        error.code === 'preflight_authorization_claim',
    );
  });

  it('rejects incomplete provenance for trust', () => {
    const value = gate();
    const provenance = completeProvenance();
    provenance.retained_handle_binding_complete = false;
    const trust = evaluateMacosLaunchdLifecycleCollectorTrust(
      value,
      completeTranscript(value),
      provenance,
    );
    assert.equal(trust.collector_trust_verified, false);
    assert.equal(trust.authorization_ready, false);
  });
});

describe('macOS Phase 11b helper layout plan', () => {
  it('builds disposable and persistent trusted-root contracts', () => {
    const plan = boundary();
    const disposable = buildMacosHelperLayoutPlan(plan, { layout_mode: 'disposable' });
    const persistent = buildMacosHelperLayoutPlan(plan, { layout_mode: 'persistent' });
    assert.equal(isMacosHelperLayoutPlan(disposable), true);
    assert.equal(isMacosHelperLayoutPlan({ ...disposable }), false);
    assert.equal(disposable.application_support_root_forbidden, true);
    assert.equal(disposable.home_profile_root_forbidden, true);
    assert.equal(disposable.privileged_helper_tools_class_root_required, true);
    assert.equal(disposable.launch_daemons_class_root_required, true);
    assert.equal(disposable.authorization_ready, false);
    assert.equal(persistent.persistent_uninstall_proof_required, true);
    assert.equal(JSON.stringify(disposable).includes('/Library'), false);
    assert.equal(JSON.stringify(disposable).toLowerCase().includes('applicationsupport'), false);
  });

  it('rejects forged boundary plans and unknown modes', () => {
    assert.throws(
      () => buildMacosHelperLayoutPlan({ schema_version: 1 }, { layout_mode: 'disposable' }),
      (error) => error instanceof MacosHelperLayoutPlanError &&
        error.code === 'invalid_boundary_plan',
    );
    assert.throws(
      () => buildMacosHelperLayoutPlan(boundary(), { layout_mode: 'user_home' }),
      (error) => error instanceof MacosHelperLayoutPlanError &&
        error.code === 'unsupported_layout_mode',
    );
  });
});
