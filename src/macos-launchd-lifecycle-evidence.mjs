import { types as utilTypes } from 'node:util';
import { isMacosLaunchdLifecycleGate } from './macos-launchd-lifecycle-gate.mjs';

const ROOT_FIELDS = new Set(['schema_version', 'terminal_outcome', 'events']);
const EVENT_FIELDS = new Set(['step', 'status']);
const TERMINAL_OUTCOMES = new Set([
  'denial_verified',
  'preflight_failed',
  'mutation_failed',
  'cleanup_failed',
  'dry_run_complete',
]);
const BASE_STATUSES = new Set(['verified', 'failed']);
const EFFECT_STATUSES = new Set(['verified', 'failed_no_effect', 'failed_effect_ambiguous']);
const CLEANUP_STATUSES = new Set([
  'verified',
  'failed',
  'skipped_not_owned',
  'skipped_not_started',
  'skipped_ownership_ambiguous',
]);
const EFFECT_STEPS = new Set([
  'create_static_helper_account_record',
  'create_exclusive_helper_binary_via_retained_parent_fd',
  'create_exclusive_plist_via_retained_parent_fd',
  'bootstrap_system_domain_job_for_fixed_label',
  'demand_activate_denial_only_helper',
]);

export class MacosLaunchdLifecycleEvidenceError extends Error {
  constructor(code = 'invalid_transcript') {
    super(`macOS launchd lifecycle evidence rejected: ${code}`);
    this.name = 'MacosLaunchdLifecycleEvidenceError';
    this.code = code;
  }
}

/**
 * Validate only the structure of value-free facts from a future collector.
 * Even a complete transcript remains caller-supplied and untrusted.
 */
export function evaluateMacosLaunchdLifecycleTranscript(gate, raw) {
  if (!isMacosLaunchdLifecycleGate(gate)) {
    throw new MacosLaunchdLifecycleEvidenceError('invalid_gate');
  }
  const transcript = exactObject(raw, ROOT_FIELDS);
  if (transcript.schema_version !== 1 || !TERMINAL_OUTCOMES.has(transcript.terminal_outcome) ||
      !Array.isArray(transcript.events)) {
    throw new MacosLaunchdLifecycleEvidenceError();
  }
  const maximum = gate.pre_mutation_steps.length + gate.mutation_steps.length +
    gate.always_cleanup_steps.length;
  const events = exactArray(transcript.events, maximum).map(readEvent);
  if (events.length === 0) throw new MacosLaunchdLifecycleEvidenceError();

  const preflight = consumeLinearPhase(events, 0, gate.pre_mutation_steps, 'preflight');
  let cursor = preflight.cursor;
  let mutation = emptyPhase(cursor);
  let cleanup = emptyPhase(cursor);
  let cleanupStart = cursor;

  if (preflight.failed) {
    if (transcript.terminal_outcome !== 'preflight_failed' || cursor !== events.length) {
      throw new MacosLaunchdLifecycleEvidenceError('invalid_preflight_terminal');
    }
  } else {
    if (!preflight.complete) throw new MacosLaunchdLifecycleEvidenceError('incomplete_preflight');
    if (transcript.terminal_outcome === 'dry_run_complete') {
      if (cursor !== events.length) {
        throw new MacosLaunchdLifecycleEvidenceError('invalid_dry_run_terminal');
      }
    } else {
      mutation = consumeLinearPhase(events, cursor, gate.mutation_steps, 'mutation');
      cursor = mutation.cursor;
      if (mutation.failed || mutation.complete) {
        cleanupStart = cursor;
        cleanup = consumeCleanup(events, cursor, gate.always_cleanup_steps);
        cursor = cleanup.cursor;
        if (cleanup.complete) {
          validateCleanupOwnership(
            events.slice(preflight.cursor, mutation.cursor),
            events.slice(cleanupStart, cleanup.cursor),
            gate,
          );
        }
      }
      if (cursor !== events.length) throw new MacosLaunchdLifecycleEvidenceError('unexpected_event');
    }
  }

  const denialComplete = mutation.complete && !mutation.failed;
  const finalAbsenceComplete = cleanup.complete && cleanup.lastStatus === 'verified';
  const cleanupComplete = cleanup.complete && !cleanup.failed && finalAbsenceComplete;

  if (transcript.terminal_outcome === 'denial_verified' &&
      !(preflight.complete && denialComplete && cleanupComplete)) {
    throw new MacosLaunchdLifecycleEvidenceError('false_success');
  }
  if (transcript.terminal_outcome === 'mutation_failed' &&
      !(preflight.complete && mutation.failed && cleanupComplete)) {
    throw new MacosLaunchdLifecycleEvidenceError('invalid_mutation_terminal');
  }
  if (transcript.terminal_outcome === 'cleanup_failed' &&
      !(preflight.complete && (mutation.failed || mutation.complete) && cleanup.complete && cleanup.failed)) {
    throw new MacosLaunchdLifecycleEvidenceError('invalid_cleanup_terminal');
  }
  if (transcript.terminal_outcome === 'preflight_failed' && !preflight.failed) {
    throw new MacosLaunchdLifecycleEvidenceError('invalid_preflight_terminal');
  }
  if (transcript.terminal_outcome === 'dry_run_complete' &&
      !(preflight.complete && !preflight.failed && mutation.cursor === preflight.cursor)) {
    throw new MacosLaunchdLifecycleEvidenceError('invalid_dry_run_terminal');
  }

  const structureComplete = transcript.terminal_outcome === 'denial_verified' && cleanupComplete;
  return Object.freeze({
    schema_version: 1,
    preflight_claim_structurally_complete: preflight.complete && !preflight.failed,
    mutation_claim_structurally_complete: mutation.complete && !mutation.failed,
    denial_claim_structurally_complete: denialComplete,
    cleanup_claim_structurally_complete: cleanupComplete,
    final_absence_claim_structurally_complete: finalAbsenceComplete,
    transcript_structure_complete: structureComplete,
    manual_recovery_claim_structurally_required: cleanup.complete && !finalAbsenceComplete,
    collector_trust_verified: false,
    live_test_verified: false,
    authorization_ready: false,
    install_gate_eligible: false,
    terminal_code: terminalCode(transcript.terminal_outcome, finalAbsenceComplete),
  });
}

function consumeLinearPhase(events, start, expectedSteps, phase) {
  let cursor = start;
  let failed = false;
  let lastStatus = '';
  for (const step of expectedSteps) {
    if (cursor >= events.length) return { cursor, complete: false, failed, lastStatus };
    const event = events[cursor];
    if (event.step !== step) throw new MacosLaunchdLifecycleEvidenceError('step_order_mismatch');
    const allowed = phase === 'mutation' && EFFECT_STEPS.has(step) ? EFFECT_STATUSES : BASE_STATUSES;
    if (!allowed.has(event.status)) throw new MacosLaunchdLifecycleEvidenceError('invalid_status_for_step');
    failed = event.status !== 'verified';
    lastStatus = event.status;
    cursor += 1;
    if (failed) return { cursor, complete: false, failed, lastStatus };
  }
  return { cursor, complete: true, failed, lastStatus };
}

function consumeCleanup(events, start, expectedSteps) {
  let cursor = start;
  let failed = false;
  let lastStatus = '';
  for (const step of expectedSteps) {
    if (cursor >= events.length) return { cursor, complete: false, failed, lastStatus };
    const event = events[cursor];
    if (event.step !== step) throw new MacosLaunchdLifecycleEvidenceError('step_order_mismatch');
    if (!CLEANUP_STATUSES.has(event.status)) {
      throw new MacosLaunchdLifecycleEvidenceError('invalid_status_for_step');
    }
    if (event.status === 'failed') failed = true;
    lastStatus = event.status;
    cursor += 1;
  }
  return { cursor, complete: true, failed, lastStatus };
}

function validateCleanupOwnership(mutationEvents, cleanupEvents, gate) {
  if (cleanupEvents.length !== gate.always_cleanup_steps.length) {
    throw new MacosLaunchdLifecycleEvidenceError('incomplete_cleanup');
  }
  const statusFor = (step) => mutationEvents.find((event) => event.step === step)?.status;
  const account = softIdentityState(
    statusFor('create_static_helper_account_record'),
    statusFor('reverify_account_record_identity_shell_home_and_distinct_euid'),
  );
  const binary = retainedFdState(statusFor('create_exclusive_helper_binary_via_retained_parent_fd'));
  const plist = retainedFdState(statusFor('create_exclusive_plist_via_retained_parent_fd'));
  const job = softIdentityState(
    statusFor('bootstrap_system_domain_job_for_fixed_label'),
    statusFor('reverify_loaded_job_identity_program_user_machservices_and_domain'),
  );
  const activation = statusFor('demand_activate_denial_only_helper');
  const process = processState(job, activation);
  const expected = [process, process, job, job, plist, plist, binary, binary, account, account, 'always'];

  for (let index = 0; index < expected.length; index += 1) {
    const status = cleanupEvents[index].status;
    if (expected[index] === 'owned' && status !== 'verified' && status !== 'failed') {
      throw new MacosLaunchdLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
    if (expected[index] === 'not_owned' && status !== 'skipped_not_owned') {
      throw new MacosLaunchdLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
    if (expected[index] === 'not_started' && status !== 'skipped_not_started') {
      throw new MacosLaunchdLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
    if (expected[index] === 'ambiguous' && status !== 'skipped_ownership_ambiguous') {
      throw new MacosLaunchdLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
    if (expected[index] === 'always' && status !== 'verified' && status !== 'failed') {
      throw new MacosLaunchdLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
  }
}

function softIdentityState(createStatus, verifyStatus) {
  if (createStatus === undefined || createStatus === 'failed_no_effect') return 'not_owned';
  if (createStatus === 'failed_effect_ambiguous') return 'ambiguous';
  return verifyStatus === 'verified' ? 'owned' : 'ambiguous';
}

function retainedFdState(createStatus) {
  if (createStatus === undefined || createStatus === 'failed_no_effect') return 'not_owned';
  if (createStatus === 'failed_effect_ambiguous') return 'ambiguous';
  return 'owned';
}

function processState(jobState, activationStatus) {
  if (jobState === 'ambiguous') return 'ambiguous';
  if (jobState === 'not_owned') return 'not_owned';
  if (activationStatus === undefined || activationStatus === 'failed_no_effect') return 'not_started';
  return 'owned';
}

function readEvent(value) {
  const event = exactObject(value, EVENT_FIELDS);
  if (typeof event.step !== 'string' || typeof event.status !== 'string') {
    throw new MacosLaunchdLifecycleEvidenceError();
  }
  return event;
}

function emptyPhase(cursor) {
  return { cursor, complete: false, failed: false, lastStatus: '' };
}

function terminalCode(outcome, finalAbsenceComplete) {
  if (outcome === 'dry_run_complete') return 'dry_run_complete_untrusted';
  if (outcome === 'denial_verified') return 'transcript_complete_untrusted';
  if (outcome === 'preflight_failed') return 'preflight_failed';
  if (outcome === 'mutation_failed') return 'mutation_failed_cleanup_complete';
  return finalAbsenceComplete ? 'cleanup_failed' : 'cleanup_failed_manual_recovery_required';
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new MacosLaunchdLifecycleEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new MacosLaunchdLifecycleEvidenceError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new MacosLaunchdLifecycleEvidenceError();
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}

function exactArray(value, maximumLength) {
  if (!Array.isArray(value) || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype ||
      value.length > maximumLength) {
    throw new MacosLaunchdLifecycleEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  const expected = new Set(['length', ...Array.from({ length: value.length }, (_, index) => String(index))]);
  if (keys.length !== expected.size ||
      keys.some((key) => typeof key !== 'string' || !expected.has(key))) {
    throw new MacosLaunchdLifecycleEvidenceError();
  }
  const snapshot = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new MacosLaunchdLifecycleEvidenceError();
    }
    Object.defineProperty(snapshot, String(index), {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
