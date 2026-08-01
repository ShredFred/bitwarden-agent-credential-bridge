import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildMacosLaunchdBoundaryPlan } from '../src/macos-launchd-boundary-plan.mjs';
import { buildMacosLaunchdLifecycleGate } from '../src/macos-launchd-lifecycle-gate.mjs';
import {
  evaluateMacosLaunchdLifecycleTranscript,
  MacosLaunchdLifecycleEvidenceError,
} from '../src/macos-launchd-lifecycle-evidence.mjs';

function gate() {
  return buildMacosLaunchdLifecycleGate(buildMacosLaunchdBoundaryPlan({
    platform: 'darwin', serviceManager: 'launchd-system',
    binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
    designatedRequirementSha256: 'b'.repeat(64), plistSha256: 'c'.repeat(64),
  }));
}

function event(step, status = 'verified') {
  return { step, status };
}

function successTranscript(value) {
  return {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [...value.pre_mutation_steps, ...value.mutation_steps, ...value.always_cleanup_steps]
      .map((step) => event(step)),
  };
}

function failedMutationTranscript(value, failedStep, failureStatus, cleanupStatuses) {
  const index = value.mutation_steps.indexOf(failedStep);
  assert.ok(index >= 0, failedStep);
  const mutation = value.mutation_steps.slice(0, index + 1).map((step) => event(step));
  mutation.at(-1).status = failureStatus;
  return {
    schema_version: 1,
    terminal_outcome: 'mutation_failed',
    events: [
      ...value.pre_mutation_steps.map((step) => event(step)),
      ...mutation,
      ...value.always_cleanup_steps.map((step, cleanupIndex) =>
        event(step, cleanupStatuses[cleanupIndex])),
    ],
  };
}

describe('macOS LaunchDaemon lifecycle value-free transcript', () => {
  it('accepts a complete pre-mutation-only dry run without implying mutation or trust', () => {
    const value = gate();
    const report = evaluateMacosLaunchdLifecycleTranscript(value, {
      schema_version: 1,
      terminal_outcome: 'dry_run_complete',
      events: value.pre_mutation_steps.map((step) => event(step)),
    });
    assert.equal(report.preflight_claim_structurally_complete, true);
    assert.equal(report.mutation_claim_structurally_complete, false);
    assert.equal(report.live_test_verified, false);
    assert.equal(report.install_gate_eligible, false);
    assert.equal(report.terminal_code, 'dry_run_complete_untrusted');
  });

  it('rejects mutation or cleanup evidence after a dry-run terminal', () => {
    const value = gate();
    for (const extraStep of [value.mutation_steps[0], value.always_cleanup_steps[0]]) {
      assert.throws(() => evaluateMacosLaunchdLifecycleTranscript(value, {
        schema_version: 1,
        terminal_outcome: 'dry_run_complete',
        events: [...value.pre_mutation_steps.map((step) => event(step)), event(extraStep)],
      }), (error) => error instanceof MacosLaunchdLifecycleEvidenceError &&
        error.code === 'invalid_dry_run_terminal');
    }
  });

  it('recognizes the exact complete denial and cleanup structure without trusting it', () => {
    const value = gate();
    assert.deepEqual(evaluateMacosLaunchdLifecycleTranscript(value, successTranscript(value)), {
      schema_version: 1,
      preflight_claim_structurally_complete: true,
      mutation_claim_structurally_complete: true,
      denial_claim_structurally_complete: true,
      cleanup_claim_structurally_complete: true,
      final_absence_claim_structurally_complete: true,
      transcript_structure_complete: true,
      manual_recovery_claim_structurally_required: false,
      collector_trust_verified: false,
      live_test_verified: false,
      authorization_ready: false,
      install_gate_eligible: false,
      terminal_code: 'transcript_complete_untrusted',
    });
  });

  it('accepts preflight failure only before mutation and without cleanup claims', () => {
    const value = gate();
    const report = evaluateMacosLaunchdLifecycleTranscript(value, {
      schema_version: 1,
      terminal_outcome: 'preflight_failed',
      events: [event(value.pre_mutation_steps[0]), event(value.pre_mutation_steps[1], 'failed')],
    });
    assert.equal(report.preflight_claim_structurally_complete, false);
    assert.equal(report.cleanup_claim_structurally_complete, false);
    assert.equal(report.terminal_code, 'preflight_failed');
  });

  it('distinguishes a proven account non-create from an ambiguous account outcome', () => {
    const value = gate();
    const nonOwned = Array(10).fill('skipped_not_owned').concat('verified');
    const noEffect = failedMutationTranscript(
      value, 'create_static_helper_account_record', 'failed_no_effect', nonOwned,
    );
    assert.equal(
      evaluateMacosLaunchdLifecycleTranscript(value, noEffect).cleanup_claim_structurally_complete,
      true,
    );

    const ambiguous = Array(10).fill('skipped_not_owned').concat('verified');
    ambiguous[8] = 'skipped_ownership_ambiguous';
    ambiguous[9] = 'skipped_ownership_ambiguous';
    const uncertain = failedMutationTranscript(
      value, 'create_static_helper_account_record', 'failed_effect_ambiguous', ambiguous,
    );
    assert.equal(
      evaluateMacosLaunchdLifecycleTranscript(value, uncertain).cleanup_claim_structurally_complete,
      true,
    );
  });

  it('never deletes an account after identity re-verification failed', () => {
    const value = gate();
    const statuses = Array(8).fill('skipped_not_owned')
      .concat(['skipped_ownership_ambiguous', 'skipped_ownership_ambiguous', 'verified']);
    const transcript = failedMutationTranscript(
      value, 'reverify_account_record_identity_shell_home_and_distinct_euid', 'failed', statuses,
    );
    const report = evaluateMacosLaunchdLifecycleTranscript(value, transcript);
    assert.equal(report.cleanup_claim_structurally_complete, true);
    const unsafe = structuredClone(transcript);
    unsafe.events.at(-3).status = 'verified';
    unsafe.events.at(-2).status = 'verified';
    assert.throws(
      () => evaluateMacosLaunchdLifecycleTranscript(value, unsafe),
      (error) => error instanceof MacosLaunchdLifecycleEvidenceError &&
        error.code === 'cleanup_ownership_mismatch',
    );
  });

  it('tracks retained-fd binary ownership independently after later failure', () => {
    const value = gate();
    const statuses = [
      'skipped_not_owned', 'skipped_not_owned', 'skipped_not_owned', 'skipped_not_owned',
      'skipped_not_owned', 'skipped_not_owned', 'verified', 'verified', 'verified', 'verified', 'verified',
    ];
    const transcript = failedMutationTranscript(
      value, 'reverify_binary_digest_owner_mode_and_requirement_via_retained_fd_and_private_snapshot',
      'failed', statuses,
    );
    assert.equal(
      evaluateMacosLaunchdLifecycleTranscript(value, transcript).cleanup_claim_structurally_complete,
      true,
    );
    const abandoned = structuredClone(transcript);
    abandoned.events.at(-5).status = 'skipped_not_owned';
    abandoned.events.at(-4).status = 'skipped_not_owned';
    assert.throws(() => evaluateMacosLaunchdLifecycleTranscript(value, abandoned),
      (error) => error instanceof MacosLaunchdLifecycleEvidenceError &&
        error.code === 'cleanup_ownership_mismatch');
  });

  it('forbids bootout when bootstrap outcome is ambiguous', () => {
    const value = gate();
    const statuses = [
      'skipped_ownership_ambiguous', 'skipped_ownership_ambiguous',
      'skipped_ownership_ambiguous', 'skipped_ownership_ambiguous',
      'verified', 'verified', 'verified', 'verified', 'verified', 'verified', 'verified',
    ];
    const transcript = failedMutationTranscript(
      value, 'bootstrap_system_domain_job_for_fixed_label', 'failed_effect_ambiguous', statuses,
    );
    assert.equal(
      evaluateMacosLaunchdLifecycleTranscript(value, transcript).cleanup_claim_structurally_complete,
      true,
    );
    const unsafe = structuredClone(transcript);
    unsafe.events.at(-9).status = 'verified';
    unsafe.events.at(-8).status = 'verified';
    assert.throws(() => evaluateMacosLaunchdLifecycleTranscript(value, unsafe),
      (error) => error instanceof MacosLaunchdLifecycleEvidenceError &&
        error.code === 'cleanup_ownership_mismatch');
  });

  it('requires process stop after an ambiguous activation of an owned job', () => {
    const value = gate();
    const statuses = Array(11).fill('verified');
    const transcript = failedMutationTranscript(
      value, 'demand_activate_denial_only_helper', 'failed_effect_ambiguous', statuses,
    );
    assert.equal(
      evaluateMacosLaunchdLifecycleTranscript(value, transcript).cleanup_claim_structurally_complete,
      true,
    );
    const unsafe = structuredClone(transcript);
    unsafe.events.at(-11).status = 'skipped_not_started';
    assert.throws(() => evaluateMacosLaunchdLifecycleTranscript(value, unsafe),
      (error) => error instanceof MacosLaunchdLifecycleEvidenceError &&
        error.code === 'cleanup_ownership_mismatch');
  });

  it('allows skipped-not-started only when activation proved no effect or was not reached', () => {
    const value = gate();
    const statuses = ['skipped_not_started', 'skipped_not_started', ...Array(9).fill('verified')];
    const transcript = failedMutationTranscript(
      value, 'demand_activate_denial_only_helper', 'failed_no_effect', statuses,
    );
    assert.equal(
      evaluateMacosLaunchdLifecycleTranscript(value, transcript).cleanup_claim_structurally_complete,
      true,
    );
  });

  it('continues cleanup after failure and requires manual recovery when final absence fails', () => {
    const value = gate();
    const cleanup = value.always_cleanup_steps.map((step) => event(step));
    cleanup[4].status = 'failed';
    cleanup.at(-1).status = 'failed';
    const report = evaluateMacosLaunchdLifecycleTranscript(value, {
      schema_version: 1,
      terminal_outcome: 'cleanup_failed',
      events: [
        ...value.pre_mutation_steps.map((step) => event(step)),
        ...value.mutation_steps.map((step) => event(step)),
        ...cleanup,
      ],
    });
    assert.equal(report.cleanup_claim_structurally_complete, false);
    assert.equal(report.final_absence_claim_structurally_complete, false);
    assert.equal(report.manual_recovery_claim_structurally_required, true);
    assert.equal(report.terminal_code, 'cleanup_failed_manual_recovery_required');
  });

  it('does not claim manual recovery when final absence resolves an earlier cleanup failure', () => {
    const value = gate();
    const cleanup = value.always_cleanup_steps.map((step) => event(step));
    cleanup[4].status = 'failed';
    const report = evaluateMacosLaunchdLifecycleTranscript(value, {
      schema_version: 1,
      terminal_outcome: 'cleanup_failed',
      events: [
        ...value.pre_mutation_steps.map((step) => event(step)),
        ...value.mutation_steps.map((step) => event(step)),
        ...cleanup,
      ],
    });
    assert.equal(report.cleanup_claim_structurally_complete, false);
    assert.equal(report.final_absence_claim_structurally_complete, true);
    assert.equal(report.manual_recovery_claim_structurally_required, false);
    assert.equal(report.terminal_code, 'cleanup_failed');
  });

  it('rejects effect ambiguity statuses on observations and ordinary failures on effect steps', () => {
    const value = gate();
    const badPreflight = {
      schema_version: 1, terminal_outcome: 'preflight_failed',
      events: [event(value.pre_mutation_steps[0], 'failed_effect_ambiguous')],
    };
    const badCreate = failedMutationTranscript(
      value, 'create_static_helper_account_record', 'failed',
      Array(10).fill('skipped_not_owned').concat('verified'),
    );
    for (const transcript of [badPreflight, badCreate]) {
      assert.throws(() => evaluateMacosLaunchdLifecycleTranscript(value, transcript),
        (error) => error instanceof MacosLaunchdLifecycleEvidenceError &&
          error.code === 'invalid_status_for_step');
    }
  });

  it('rejects reordering, omissions, false success, extras, and forged gates', () => {
    const value = gate();
    const cases = [];
    const reordered = successTranscript(value);
    [reordered.events[0], reordered.events[1]] = [reordered.events[1], reordered.events[0]];
    cases.push(reordered);
    const omitted = successTranscript(value);
    omitted.events.pop();
    cases.push(omitted);
    const falseSuccess = successTranscript(value);
    falseSuccess.events[value.pre_mutation_steps.length + 1].status = 'failed';
    cases.push(falseSuccess);
    const extra = successTranscript(value);
    extra.events.push(event('invented'));
    cases.push(extra);
    for (const transcript of cases) {
      assert.throws(() => evaluateMacosLaunchdLifecycleTranscript(value, transcript),
        (error) => error instanceof MacosLaunchdLifecycleEvidenceError);
    }
    assert.throws(
      () => evaluateMacosLaunchdLifecycleTranscript(structuredClone(value), successTranscript(value)),
      (error) => error instanceof MacosLaunchdLifecycleEvidenceError && error.code === 'invalid_gate',
    );
  });

  it('rejects proxies, accessors, prototypes, holes, and extra data', () => {
    const value = gate();
    const valid = successTranscript(value);
    const accessor = successTranscript(value);
    Object.defineProperty(accessor.events[0], 'status', { enumerable: true, get: () => 'verified' });
    const extra = successTranscript(value);
    extra.events[0].detail = 'forbidden';
    const hole = successTranscript(value);
    delete hole.events[2];
    for (const transcript of [
      new Proxy(valid, {}), { ...valid, events: new Proxy(valid.events, {}) },
      accessor, extra, hole, { ...valid, approval: true },
    ]) assert.throws(() => evaluateMacosLaunchdLifecycleTranscript(value, transcript));
  });

  it('does not consult poisoned prototypes or return transcript values', () => {
    const value = gate();
    let calls = 0;
    const previous = Object.getOwnPropertyDescriptor(Object.prototype, 'terminal_outcome');
    Object.defineProperty(Object.prototype, 'terminal_outcome', {
      configurable: true, get() { calls += 1; return 'denial_verified'; },
    });
    try {
      const report = evaluateMacosLaunchdLifecycleTranscript(value, successTranscript(value));
      assert.equal(calls, 0);
      const serialized = JSON.stringify(report);
      for (const forbidden of ['events', 'step', 'status', 'path', 'uid', 'guid', 'audit']) {
        assert.equal(serialized.toLowerCase().includes(forbidden), false, forbidden);
      }
    } finally {
      if (previous === undefined) delete Object.prototype.terminal_outcome;
      else Object.defineProperty(Object.prototype, 'terminal_outcome', previous);
    }
  });
});
