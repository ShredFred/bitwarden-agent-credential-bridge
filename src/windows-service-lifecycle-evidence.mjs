import { isWindowsServiceLifecycleGate } from './windows-service-lifecycle-gate.mjs';
import { types as utilTypes } from 'node:util';

const ROOT_FIELDS = new Set(['schema_version', 'terminal_outcome', 'events']);
const EVENT_FIELDS = new Set(['step', 'status']);
const TERMINAL_OUTCOMES = new Set([
  'denial_verified',
  'preflight_failed',
  'mutation_failed',
  'cleanup_failed',
]);
const EVENT_STATUSES = new Set(['verified', 'failed', 'skipped_not_owned', 'skipped_not_started']);

export class WindowsServiceLifecycleEvidenceError extends Error {
  constructor(code = 'invalid_transcript') {
    super(`Windows service lifecycle evidence rejected: ${code}`);
    this.name = 'WindowsServiceLifecycleEvidenceError';
    this.code = code;
  }
}

/**
 * Validate the ordering and fail-closed cleanup shape of value-free facts from a
 * future trusted collector. A syntactically complete transcript is not live
 * evidence or authorization by itself.
 */
export function evaluateWindowsServiceLifecycleTranscript(gate, raw) {
  if (!isWindowsServiceLifecycleGate(gate)) {
    throw new WindowsServiceLifecycleEvidenceError('invalid_gate');
  }
  const transcript = exactObject(raw, ROOT_FIELDS);
  if (transcript.schema_version !== 1 || !TERMINAL_OUTCOMES.has(transcript.terminal_outcome) ||
      !Array.isArray(transcript.events)) {
    throw new WindowsServiceLifecycleEvidenceError();
  }
  const totalSteps = gate.pre_mutation_steps.length + gate.mutation_steps.length +
    gate.always_cleanup_steps.length;
  const eventValues = exactArray(transcript.events, totalSteps);
  if (eventValues.length < 1) {
    throw new WindowsServiceLifecycleEvidenceError();
  }
  const events = eventValues.map(readEvent);
  const preflight = consumePhase(events, 0, gate.pre_mutation_steps, false);
  let cursor = preflight.cursor;
  let mutation = emptyPhase(cursor);
  let cleanup = emptyPhase(cursor);

  if (preflight.failed) {
    if (transcript.terminal_outcome !== 'preflight_failed' || cursor !== events.length) {
      throw new WindowsServiceLifecycleEvidenceError('invalid_preflight_terminal');
    }
  } else {
    if (!preflight.complete) throw new WindowsServiceLifecycleEvidenceError('incomplete_preflight');
    mutation = consumePhase(events, cursor, gate.mutation_steps, false);
    cursor = mutation.cursor;
    if (mutation.failed || mutation.complete) {
      const cleanupStart = cursor;
      cleanup = consumePhase(events, cursor, gate.always_cleanup_steps, true);
      cursor = cleanup.cursor;
      if (cleanup.complete) {
        validateCleanupOwnership(
          events.slice(preflight.cursor, mutation.cursor),
          events.slice(cleanupStart, cleanup.cursor),
          gate,
        );
      }
    }
    if (cursor !== events.length) throw new WindowsServiceLifecycleEvidenceError('unexpected_event');
  }

  const denialClaimComplete = mutation.complete && !mutation.failed;
  const finalAbsenceClaimComplete = cleanup.complete && !cleanup.failed &&
    cleanup.lastStatus === 'verified';
  const cleanupComplete = cleanup.complete && !cleanup.failed && finalAbsenceClaimComplete;

  if (transcript.terminal_outcome === 'denial_verified' &&
      !(preflight.complete && denialClaimComplete && cleanupComplete)) {
    throw new WindowsServiceLifecycleEvidenceError('false_success');
  }
  if (transcript.terminal_outcome === 'mutation_failed' &&
      !(preflight.complete && mutation.failed && cleanupComplete)) {
    throw new WindowsServiceLifecycleEvidenceError('invalid_mutation_terminal');
  }
  if (transcript.terminal_outcome === 'cleanup_failed' &&
      !(preflight.complete && (mutation.failed || mutation.complete) && cleanup.complete && cleanup.failed)) {
    throw new WindowsServiceLifecycleEvidenceError('invalid_cleanup_terminal');
  }
  if (transcript.terminal_outcome === 'preflight_failed' && !preflight.failed) {
    throw new WindowsServiceLifecycleEvidenceError('invalid_preflight_terminal');
  }

  const structureComplete = transcript.terminal_outcome === 'denial_verified' && cleanupComplete;
  return Object.freeze({
    schema_version: 1,
    preflight_claim_structurally_complete: preflight.complete && !preflight.failed,
    mutation_claim_structurally_complete: mutation.complete && !mutation.failed,
    denial_claim_structurally_complete: denialClaimComplete,
    cleanup_claim_structurally_complete: cleanupComplete,
    final_absence_claim_structurally_complete: finalAbsenceClaimComplete,
    transcript_structure_complete: structureComplete,
    collector_trust_verified: false,
    live_test_verified: false,
    authorization_ready: false,
    terminal_code: terminalCode(transcript.terminal_outcome),
  });
}

function readEvent(value) {
  const event = exactObject(value, EVENT_FIELDS);
  if (typeof event.step !== 'string' || !EVENT_STATUSES.has(event.status)) {
    throw new WindowsServiceLifecycleEvidenceError();
  }
  return event;
}

function consumePhase(events, start, expectedSteps, cleanup) {
  let cursor = start;
  let failed = false;
  let lastStatus = '';
  for (const step of expectedSteps) {
    if (cursor >= events.length) return { cursor, complete: false, failed, lastStatus };
    const event = events[cursor];
    if (event.step !== step) throw new WindowsServiceLifecycleEvidenceError('step_order_mismatch');
    if (!cleanup && (event.status === 'skipped_not_owned' || event.status === 'skipped_not_started')) {
      throw new WindowsServiceLifecycleEvidenceError('invalid_skip');
    }
    if (failed && !cleanup) throw new WindowsServiceLifecycleEvidenceError('event_after_failure');
    if (event.status === 'failed') failed = true;
    lastStatus = event.status;
    cursor += 1;
    if (failed && !cleanup) return { cursor, complete: false, failed, lastStatus };
  }
  return { cursor, complete: true, failed, lastStatus };
}

function validateCleanupOwnership(mutationEvents, cleanupEvents, gate) {
  const statusFor = (step) => mutationEvents.find((event) => event.step === step)?.status;
  const rootOwned = statusFor('create_disposable_admin_root_and_retain_handle') === 'verified';
  const binaryOwned = statusFor('create_exclusive_binary_and_retain_handle') === 'verified';
  const serviceOwned = statusFor('create_fixed_demand_start_local_service_and_retain_handle') === 'verified';
  const startStatus = statusFor('start_fixed_service_via_retained_handle');
  const serviceStartAttempted = startStatus === 'verified' || startStatus === 'failed';
  const expected = [
    serviceStartAttempted ? 'owned' : serviceOwned ? 'not_started' : 'not_owned',
    serviceOwned ? 'owned' : 'not_owned',
    serviceOwned ? 'owned' : 'not_owned',
    serviceOwned ? 'owned' : 'not_owned',
    binaryOwned ? 'owned' : 'not_owned',
    binaryOwned ? 'owned' : 'not_owned',
    rootOwned ? 'owned' : 'not_owned',
    rootOwned ? 'owned' : 'not_owned',
    'owned',
  ];
  if (cleanupEvents.length !== gate.always_cleanup_steps.length) {
    throw new WindowsServiceLifecycleEvidenceError('incomplete_cleanup');
  }
  for (let index = 0; index < expected.length; index += 1) {
    const status = cleanupEvents[index].status;
    if (expected[index] === 'not_owned' && status !== 'skipped_not_owned') {
      throw new WindowsServiceLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
    if (expected[index] === 'not_started' && status !== 'skipped_not_started') {
      throw new WindowsServiceLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
    if (expected[index] === 'owned' && status !== 'verified' && status !== 'failed') {
      throw new WindowsServiceLifecycleEvidenceError('cleanup_ownership_mismatch');
    }
  }
}

function emptyPhase(cursor) {
  return { cursor, complete: false, failed: false, lastStatus: '' };
}

function terminalCode(outcome) {
  if (outcome === 'denial_verified') return 'transcript_complete_untrusted';
  if (outcome === 'preflight_failed') return 'preflight_failed';
  if (outcome === 'mutation_failed') return 'mutation_failed_cleanup_complete';
  return 'cleanup_failed';
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsServiceLifecycleEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsServiceLifecycleEvidenceError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsServiceLifecycleEvidenceError();
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
    throw new WindowsServiceLifecycleEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  const expectedKeys = new Set(['length', ...Array.from({ length: value.length }, (_, index) => String(index))]);
  if (keys.length !== expectedKeys.size ||
      keys.some((key) => typeof key !== 'string' || !expectedKeys.has(key))) {
    throw new WindowsServiceLifecycleEvidenceError();
  }
  const snapshot = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsServiceLifecycleEvidenceError();
    }
    Object.defineProperty(snapshot, String(index), {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
