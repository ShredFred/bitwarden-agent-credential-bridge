import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsServiceLifecycleGate } from '../src/windows-service-lifecycle-gate.mjs';
import { evaluateLiveCollectorResult, brandWindowsServiceLifecycleLiveReportForHarness } from '../src/windows-service-lifecycle-live.mjs';
import {
  evaluateWindowsServiceInstallGate,
  isWindowsServiceInstallGateReport,
  WindowsServiceInstallGateError,
} from '../src/windows-service-install-gate.mjs';

function gate() {
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

describe('Windows service install gate', () => {
  it('marks install_gate_eligible only after verified disposable live denial', () => {
    const value = gate();
    const report = evaluateWindowsServiceInstallGate(value, successLive(value), absentPreflight());
    assert.equal(isWindowsServiceInstallGateReport(report), true);
    assert.equal(isWindowsServiceInstallGateReport({ ...report }), false);
    assert.equal(report.install_gate_eligible, true);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.persistent_mutator_absent, true);
    assert.equal(report.vault_access_forbidden, true);
    assert.equal(report.terminal_code, 'install_gate_eligible_disposable_verified');
  });

  it('stays ineligible when live denial was not verified', () => {
    const value = gate();
    const live = brandWindowsServiceLifecycleLiveReportForHarness(evaluateLiveCollectorResult(value, {
      schema_version: 1,
      terminal_outcome: 'preflight_failed',
      events: [
        event(value.pre_mutation_steps[0]),
        event(value.pre_mutation_steps[1], 'failed'),
      ],
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
    const report = evaluateWindowsServiceInstallGate(value, live, absentPreflight());
    assert.equal(report.install_gate_eligible, false);
    assert.equal(report.terminal_code, 'install_gate_ineligible');
  });

  it('rejects forged gates, authorizing preflight, and extra fields', () => {
    const value = gate();
    const live = successLive(value);
    assert.throws(
      () => evaluateWindowsServiceInstallGate({ ...value }, live, absentPreflight()),
      (error) => error instanceof WindowsServiceInstallGateError &&
        error.code === 'invalid_lifecycle_gate',
    );
    assert.throws(
      () => evaluateWindowsServiceInstallGate(value, { ...live }, absentPreflight()),
      (error) => error instanceof WindowsServiceInstallGateError &&
        error.code === 'unbranded_live_report',
    );
    assert.throws(
      () => evaluateWindowsServiceInstallGate(value, live, {
        ...absentPreflight(),
        authorization_ready: true,
      }),
      (error) => error instanceof WindowsServiceInstallGateError &&
        error.code === 'preflight_authorization_claim',
    );
    assert.throws(
      () => evaluateWindowsServiceInstallGate(value, { ...live, extra: true }, absentPreflight()),
      (error) => error instanceof WindowsServiceInstallGateError,
    );
  });
});
