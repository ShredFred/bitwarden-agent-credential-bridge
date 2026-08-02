import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsServiceLifecycleGate } from '../src/windows-service-lifecycle-gate.mjs';
import {
  buildWindowsServiceLifecycleCollectorContract,
  evaluateWindowsServiceLifecycleCollectorTrust,
  isWindowsServiceLifecycleCollectorContract,
  WindowsServiceLifecycleCollectorTrustError,
} from '../src/windows-service-lifecycle-collector-trust.mjs';

function gate() {
  return buildWindowsServiceLifecycleGate(buildWindowsServiceBoundaryPlan({
    platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
  }));
}

function event(step, status = 'verified') {
  return { step, status };
}

function successTranscript(value) {
  return {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [
      ...value.pre_mutation_steps,
      ...value.mutation_steps,
      ...value.always_cleanup_steps,
    ].map((step) => event(step)),
  };
}

function provenance(overrides = {}) {
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
    uac_consent_observed: false,
    admin_group_present: false,
    high_integrity_reported: false,
    ...overrides,
  };
}

describe('Windows service lifecycle collector trust', () => {
  it('builds a branded non-executable collector contract from a lifecycle gate', () => {
    const value = gate();
    const contract = buildWindowsServiceLifecycleCollectorContract(value);
    assert.equal(isWindowsServiceLifecycleCollectorContract(contract), true);
    assert.equal(isWindowsServiceLifecycleCollectorContract({ ...contract }), false);
    assert.equal(isWindowsServiceLifecycleCollectorContract(structuredClone(contract)), false);
    assert.equal(contract.mutation_authorized, false);
    assert.equal(contract.live_test_executed, false);
    assert.equal(contract.live_test_verified, false);
    assert.equal(contract.install_gate_eligible, false);
    assert.equal(contract.authorization_ready, false);
    assert.deepEqual(contract.required_provenance_fields, [
      'elevated_token_verified',
      'local_only_collection',
      'retained_handle_binding_complete',
      'path_reacquisition_absent',
      'value_free_emission_verified',
      'stderr_absent',
      'gate_step_surface_matched',
      'cleanup_finally_bound',
    ]);
  });

  it('rejects non-branded gates for the collector contract', () => {
    assert.throws(
      () => buildWindowsServiceLifecycleCollectorContract({ schema_version: 1 }),
      (error) => error instanceof WindowsServiceLifecycleCollectorTrustError &&
        error.code === 'invalid_gate',
    );
  });

  it('sets collector_trust_verified only for complete transcript plus required provenance', () => {
    const value = gate();
    const report = evaluateWindowsServiceLifecycleCollectorTrust(
      value,
      successTranscript(value),
      provenance(),
    );
    assert.deepEqual(report, {
      schema_version: 1,
      preflight_claim_structurally_complete: true,
      mutation_claim_structurally_complete: true,
      denial_claim_structurally_complete: true,
      cleanup_claim_structurally_complete: true,
      final_absence_claim_structurally_complete: true,
      transcript_structure_complete: true,
      required_provenance_complete: true,
      defense_in_depth_signals_complete: false,
      collector_trust_verified: true,
      live_test_verified: false,
      mutation_authorized: false,
      install_gate_eligible: false,
      authorization_ready: false,
      terminal_code: 'collector_trust_schema_satisfied_unlive',
    });
  });

  it('never treats UAC, admin group, or high integrity alone as collector trust', () => {
    const value = gate();
    const report = evaluateWindowsServiceLifecycleCollectorTrust(
      value,
      successTranscript(value),
      provenance({
        elevated_token_verified: false,
        retained_handle_binding_complete: false,
        path_reacquisition_absent: false,
        uac_consent_observed: true,
        admin_group_present: true,
        high_integrity_reported: true,
      }),
    );
    assert.equal(report.defense_in_depth_signals_complete, true);
    assert.equal(report.required_provenance_complete, false);
    assert.equal(report.collector_trust_verified, false);
    assert.equal(report.live_test_verified, false);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.terminal_code, 'transcript_complete_provenance_incomplete');
  });

  it('keeps collector trust false when the transcript is incomplete even with full provenance', () => {
    const value = gate();
    const report = evaluateWindowsServiceLifecycleCollectorTrust(
      value,
      {
        schema_version: 1,
        terminal_outcome: 'preflight_failed',
        events: [
          event(value.pre_mutation_steps[0]),
          event(value.pre_mutation_steps[1], 'failed'),
        ],
      },
      provenance({
        uac_consent_observed: true,
        admin_group_present: true,
        high_integrity_reported: true,
      }),
    );
    assert.equal(report.transcript_structure_complete, false);
    assert.equal(report.required_provenance_complete, true);
    assert.equal(report.collector_trust_verified, false);
    assert.equal(report.live_test_verified, false);
    assert.equal(report.terminal_code, 'preflight_failed');
  });

  it('fails closed on forged provenance shapes and non-branded gates', () => {
    const value = gate();
    const good = provenance();
    assert.throws(
      () => evaluateWindowsServiceLifecycleCollectorTrust(
        { ...value },
        successTranscript(value),
        good,
      ),
      (error) => error instanceof WindowsServiceLifecycleCollectorTrustError &&
        error.code === 'invalid_gate',
    );
    assert.throws(
      () => evaluateWindowsServiceLifecycleCollectorTrust(value, successTranscript(value), {
        ...good,
        extra: true,
      }),
      (error) => error instanceof WindowsServiceLifecycleCollectorTrustError,
    );
    assert.throws(
      () => evaluateWindowsServiceLifecycleCollectorTrust(value, successTranscript(value), {
        ...good,
        schema_version: 2,
      }),
      (error) => error instanceof WindowsServiceLifecycleCollectorTrustError,
    );
    const withAccessor = { ...good };
    Object.defineProperty(withAccessor, 'elevated_token_verified', {
      get() { return true; },
      enumerable: true,
    });
    assert.throws(
      () => evaluateWindowsServiceLifecycleCollectorTrust(
        value,
        successTranscript(value),
        withAccessor,
      ),
      (error) => error instanceof WindowsServiceLifecycleCollectorTrustError,
    );
  });

  it('never exposes paths, SIDs, ACLs, or approval values in the trust report', () => {
    const value = gate();
    const report = evaluateWindowsServiceLifecycleCollectorTrust(
      value,
      successTranscript(value),
      provenance({
        uac_consent_observed: true,
        admin_group_present: true,
        high_integrity_reported: true,
      }),
    );
    const encoded = JSON.stringify(report);
    assert.equal(encoded.includes('S-1-'), false);
    assert.equal(encoded.includes('C:\\'), false);
    assert.equal(encoded.includes('approval'), false);
    assert.equal(encoded.includes('LocalService'), false);
    assert.equal(report.defense_in_depth_signals_complete, true);
    assert.equal(report.collector_trust_verified, true);
    assert.equal(report.live_test_verified, false);
  });
});
