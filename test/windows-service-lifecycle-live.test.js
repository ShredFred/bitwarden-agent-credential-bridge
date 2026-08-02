import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsServiceLifecycleGate } from '../src/windows-service-lifecycle-gate.mjs';
import {
  evaluateLiveCollectorResult,
  isWindowsServiceLifecycleLiveReport,
  WindowsServiceLifecycleLiveError,
} from '../src/windows-service-lifecycle-live.mjs';

function gate() {
  return buildWindowsServiceLifecycleGate(buildWindowsServiceBoundaryPlan({
    platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
  }));
}

function event(step, status = 'verified') {
  return { step, status };
}

function successPayload(value) {
  return {
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
  };
}

describe('Windows service lifecycle live result evaluation', () => {
  it('marks live denial verified only for complete trusted denial transcripts', () => {
    const value = gate();
    const report = evaluateLiveCollectorResult(value, successPayload(value));
    assert.equal(report.live_test_executed, true);
    assert.equal(report.live_test_verified, true);
    assert.equal(report.collector_trust_verified, true);
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.install_gate_eligible, false);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.terminal_code, 'live_denial_verified_cleaned');
  });

  it('does not brand structural evaluation results as install capabilities', () => {
    const value = gate();
    const report = evaluateLiveCollectorResult(value, successPayload(value));
    assert.equal(isWindowsServiceLifecycleLiveReport(report), false);
    assert.equal(isWindowsServiceLifecycleLiveReport({ ...report }), false);
  });

  it('keeps live_test_verified false when provenance is incomplete', () => {
    const value = gate();
    const payload = successPayload(value);
    payload.provenance.elevated_token_verified = false;
    const report = evaluateLiveCollectorResult(value, payload);
    assert.equal(report.live_test_executed, true);
    assert.equal(report.live_test_verified, false);
    assert.equal(report.collector_trust_verified, false);
    assert.equal(report.authorization_ready, false);
  });

  it('rejects truncated, oversized-claim, and mutation-failed transcripts for live verification', () => {
    const value = gate();
    const failed = successPayload(value);
    failed.terminal_outcome = 'mutation_failed';
    const failedMutation = value.mutation_steps.slice(0, 1).map((step) => event(step));
    failedMutation[0] = event(value.mutation_steps[0], 'failed');
    failed.events = [
      ...value.pre_mutation_steps.map((step) => event(step)),
      ...failedMutation,
      ...value.always_cleanup_steps.map((step) => event(step, 'skipped_not_owned')),
    ];
    // Final absence must still be verified even when nothing was owned.
    failed.events[failed.events.length - 1] = event(
      value.always_cleanup_steps.at(-1),
      'verified',
    );
    const report = evaluateLiveCollectorResult(value, failed);
    assert.equal(report.live_test_verified, false);
    assert.equal(report.live_test_executed, true);
    assert.equal(report.install_gate_eligible, false);

    assert.throws(
      () => evaluateLiveCollectorResult(value, {
        schema_version: 1,
        terminal_outcome: 'denial_verified',
        events: 'not-array',
        provenance: successPayload(value).provenance,
      }),
      (error) => error instanceof WindowsServiceLifecycleLiveError,
    );
  });

  it('never upgrades a preflight failure into live verification', () => {
    const value = gate();
    const report = evaluateLiveCollectorResult(value, {
      schema_version: 1,
      terminal_outcome: 'preflight_failed',
      events: [
        event(value.pre_mutation_steps[0]),
        event(value.pre_mutation_steps[1], 'failed'),
      ],
      provenance: successPayload(value).provenance,
    });
    assert.equal(report.live_test_verified, false);
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.authorization_ready, false);
  });
});

describe('Windows service boundary pipe name binding', () => {
  it('pins the native denial pipe name used by the helper binary', () => {
    const plan = buildWindowsServiceBoundaryPlan({
      platform: 'win32', binarySha256: 'b'.repeat(64), binaryByteLength: 2048,
    });
    assert.equal(plan.ipc.pipe_name, 'BitwardenAgentCredentialBridgeHelper.v1.denial');
  });
});
