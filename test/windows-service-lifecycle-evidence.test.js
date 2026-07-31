import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsServiceLifecycleGate } from '../src/windows-service-lifecycle-gate.mjs';
import {
  evaluateWindowsServiceLifecycleTranscript,
  WindowsServiceLifecycleEvidenceError,
} from '../src/windows-service-lifecycle-evidence.mjs';

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

describe('Windows service lifecycle value-free transcript', () => {
  it('recognizes the exact complete denial and cleanup sequence without trusting it', () => {
    const value = gate();
    assert.deepEqual(evaluateWindowsServiceLifecycleTranscript(value, successTranscript(value)), {
      schema_version: 1,
      preflight_claim_structurally_complete: true,
      mutation_claim_structurally_complete: true,
      denial_claim_structurally_complete: true,
      cleanup_claim_structurally_complete: true,
      final_absence_claim_structurally_complete: true,
      transcript_structure_complete: true,
      collector_trust_verified: false,
      live_test_verified: false,
      authorization_ready: false,
      terminal_code: 'transcript_complete_untrusted',
    });
  });

  it('accepts a preflight failure only before mutation and without cleanup claims', () => {
    const value = gate();
    const report = evaluateWindowsServiceLifecycleTranscript(value, {
      schema_version: 1,
      terminal_outcome: 'preflight_failed',
      events: [event(value.pre_mutation_steps[0]), event(value.pre_mutation_steps[1], 'failed')],
    });
    assert.equal(report.preflight_claim_structurally_complete, false);
    assert.equal(report.cleanup_claim_structurally_complete, false);
    assert.equal(report.transcript_structure_complete, false);
    assert.equal(report.terminal_code, 'preflight_failed');
  });

  it('requires full finally cleanup after a mutation failure', () => {
    const value = gate();
    const failedMutation = value.mutation_steps.slice(0, 6).map((step) => event(step));
    failedMutation.at(-1).status = 'failed';
    const transcript = {
      schema_version: 1,
      terminal_outcome: 'mutation_failed',
      events: [
        ...value.pre_mutation_steps.map((step) => event(step)),
        ...failedMutation,
        ...value.always_cleanup_steps.map((step, index) =>
          event(step, index < 4 ? 'skipped_not_owned' : 'verified')),
      ],
    };
    const report = evaluateWindowsServiceLifecycleTranscript(value, transcript);
    assert.equal(report.mutation_claim_structurally_complete, false);
    assert.equal(report.cleanup_claim_structurally_complete, true);
    assert.equal(report.final_absence_claim_structurally_complete, true);
    assert.equal(report.terminal_code, 'mutation_failed_cleanup_complete');
    assert.equal(report.live_test_verified, false);
  });

  it('requires stop cleanup after any attempted start, including ambiguous failure', () => {
    const value = gate();
    const startIndex = value.mutation_steps.indexOf('start_fixed_service_via_retained_handle');
    const failedMutation = value.mutation_steps.slice(0, startIndex + 1).map((step) => event(step));
    failedMutation.at(-1).status = 'failed';
    const cleanup = value.always_cleanup_steps.map((step) => event(step));
    cleanup[0].status = 'skipped_not_started';
    assert.throws(
      () => evaluateWindowsServiceLifecycleTranscript(value, {
        schema_version: 1,
        terminal_outcome: 'mutation_failed',
        events: [
          ...value.pre_mutation_steps.map((step) => event(step)),
          ...failedMutation,
          ...cleanup,
        ],
      }),
      (error) => error instanceof WindowsServiceLifecycleEvidenceError &&
        error.code === 'cleanup_ownership_mismatch',
    );
    cleanup[0].status = 'verified';
    const report = evaluateWindowsServiceLifecycleTranscript(value, {
      schema_version: 1,
      terminal_outcome: 'mutation_failed',
      events: [
        ...value.pre_mutation_steps.map((step) => event(step)),
        ...failedMutation,
        ...cleanup,
      ],
    });
    assert.equal(report.cleanup_claim_structurally_complete, true);
  });

  it('rejects cleanup skips that contradict objects already created by this run', () => {
    const value = gate();
    const failedMutation = value.mutation_steps.slice(0, 4).map((step) => event(step));
    failedMutation.at(-1).status = 'failed';
    const badCleanup = value.always_cleanup_steps.map((step) => event(step, 'skipped_not_owned'));
    badCleanup.at(-1).status = 'verified';
    assert.throws(
      () => evaluateWindowsServiceLifecycleTranscript(value, {
        schema_version: 1,
        terminal_outcome: 'mutation_failed',
        events: [
          ...value.pre_mutation_steps.map((step) => event(step)),
          ...failedMutation,
          ...badCleanup,
        ],
      }),
      (error) => error instanceof WindowsServiceLifecycleEvidenceError &&
        error.code === 'cleanup_ownership_mismatch',
    );
  });

  it('tracks root and binary ownership independently across partial staging failure', () => {
    const value = gate();
    const binaryCreateIndex = value.mutation_steps.indexOf('create_exclusive_binary_and_retain_handle');
    const failedMutation = value.mutation_steps.slice(0, binaryCreateIndex + 1).map((step) => event(step));
    failedMutation.at(-1).status = 'failed';
    const cleanup = value.always_cleanup_steps.map((step, index) => {
      if (index < 6) return event(step, 'skipped_not_owned');
      return event(step, 'verified');
    });
    const report = evaluateWindowsServiceLifecycleTranscript(value, {
      schema_version: 1,
      terminal_outcome: 'mutation_failed',
      events: [
        ...value.pre_mutation_steps.map((step) => event(step)),
        ...failedMutation,
        ...cleanup,
      ],
    });
    assert.equal(report.cleanup_claim_structurally_complete, true);
    const abandonedRoot = structuredClone(cleanup);
    abandonedRoot[6].status = 'skipped_not_owned';
    abandonedRoot[7].status = 'skipped_not_owned';
    assert.throws(
      () => evaluateWindowsServiceLifecycleTranscript(value, {
        schema_version: 1,
        terminal_outcome: 'mutation_failed',
        events: [
          ...value.pre_mutation_steps.map((step) => event(step)),
          ...failedMutation,
          ...abandonedRoot,
        ],
      }),
      (error) => error instanceof WindowsServiceLifecycleEvidenceError &&
        error.code === 'cleanup_ownership_mismatch',
    );
  });

  it('reports cleanup failure but never upgrades it to a complete transcript', () => {
    const value = gate();
    const cleanup = value.always_cleanup_steps.map((step) => event(step));
    cleanup[3].status = 'failed';
    const report = evaluateWindowsServiceLifecycleTranscript(value, {
      ...successTranscript(value),
      terminal_outcome: 'cleanup_failed',
      events: [
        ...value.pre_mutation_steps.map((step) => event(step)),
        ...value.mutation_steps.map((step) => event(step)),
        ...cleanup,
      ],
    });
    assert.equal(report.cleanup_claim_structurally_complete, false);
    assert.equal(report.final_absence_claim_structurally_complete, false);
    assert.equal(report.transcript_structure_complete, false);
    assert.equal(report.terminal_code, 'cleanup_failed');
  });

  it('rejects proxies and snapshots data descriptors before validation', () => {
    const value = gate();
    const valid = successTranscript(value);
    const proxiedRoot = new Proxy(valid, {});
    const proxiedEvents = { ...valid, events: new Proxy(valid.events, {}) };
    const proxiedEvent = successTranscript(value);
    proxiedEvent.events[0] = new Proxy(proxiedEvent.events[0], {});
    for (const transcript of [proxiedRoot, proxiedEvents, proxiedEvent]) {
      assert.throws(
        () => evaluateWindowsServiceLifecycleTranscript(value, transcript),
        (error) => error instanceof WindowsServiceLifecycleEvidenceError,
      );
    }
  });

  it('rejects reordering, omissions, false success, illegal skips, extras, and forged gates', () => {
    const value = gate();
    const cases = [];
    const reordered = successTranscript(value);
    [reordered.events[0], reordered.events[1]] = [reordered.events[1], reordered.events[0]];
    cases.push(reordered);
    const omittedCleanup = successTranscript(value);
    omittedCleanup.events.pop();
    cases.push(omittedCleanup);
    const falseSuccess = successTranscript(value);
    falseSuccess.events[value.pre_mutation_steps.length + 2].status = 'failed';
    cases.push(falseSuccess);
    const illegalSkip = successTranscript(value);
    illegalSkip.events[0].status = 'skipped_not_owned';
    cases.push(illegalSkip);
    const extra = successTranscript(value);
    extra.events.push(event('invented'));
    cases.push(extra);
    for (const transcript of cases) {
      assert.throws(
        () => evaluateWindowsServiceLifecycleTranscript(value, transcript),
        (error) => error instanceof WindowsServiceLifecycleEvidenceError,
      );
    }
    assert.throws(
      () => evaluateWindowsServiceLifecycleTranscript(structuredClone(value), successTranscript(value)),
      (error) => error instanceof WindowsServiceLifecycleEvidenceError && error.code === 'invalid_gate',
    );
  });

  it('rejects accessor-backed and non-exact transcript/event objects', () => {
    const value = gate();
    const accessor = successTranscript(value);
    Object.defineProperty(accessor.events[0], 'status', { get: () => 'verified', enumerable: true });
    const extra = successTranscript(value);
    extra.events[0].detail = 'not-value-free';
    for (const transcript of [accessor, extra, { ...successTranscript(value), approval: true }]) {
      assert.throws(
        () => evaluateWindowsServiceLifecycleTranscript(value, transcript),
        (error) => error instanceof WindowsServiceLifecycleEvidenceError,
      );
    }
  });
});
