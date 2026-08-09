import { types as utilTypes } from 'node:util';
import { isLinuxSystemdLifecycleGate } from './linux-systemd-lifecycle-gate.mjs';

/**
 * Phase 12c: pure value-free Linux lifecycle transcript state machine.
 * Structural claims only; collector trust and live verification stay false.
 */

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
  'create_static_system_user_record',
  'create_exclusive_helper_binary_via_retained_parent_fd',
  'create_exclusive_service_and_socket_units_via_retained_parent_fd',
  'start_socket_activated_denial_only_helper',
]);

export class LinuxSystemdLifecycleEvidenceError extends Error {
  constructor(code = 'invalid_transcript') {
    super(`Linux systemd lifecycle evidence rejected: ${code}`);
    this.name = 'LinuxSystemdLifecycleEvidenceError';
    this.code = code;
  }
}

export function evaluateLinuxSystemdLifecycleTranscript(gate, raw) {
  if (!isLinuxSystemdLifecycleGate(gate)) {
    throw new LinuxSystemdLifecycleEvidenceError('invalid_gate');
  }
  const transcript = exactObject(raw, ROOT_FIELDS);
  if (transcript.schema_version !== 1 || !TERMINAL_OUTCOMES.has(transcript.terminal_outcome) ||
      !Array.isArray(transcript.events)) {
    throw new LinuxSystemdLifecycleEvidenceError();
  }
  const maximum = gate.pre_mutation_steps.length + gate.mutation_steps.length +
    gate.always_cleanup_steps.length;
  const events = exactArray(transcript.events, maximum).map(readEvent);
  if (events.length === 0) throw new LinuxSystemdLifecycleEvidenceError();

  const preflight = consumeLinearPhase(events, 0, gate.pre_mutation_steps, 'preflight');
  let cursor = preflight.cursor;
  let mutation = emptyPhase(cursor);
  let cleanup = emptyPhase(cursor);

  if (preflight.failed) {
    if (transcript.terminal_outcome !== 'preflight_failed' || cursor !== events.length) {
      throw new LinuxSystemdLifecycleEvidenceError('invalid_preflight_terminal');
    }
  } else {
    if (!preflight.complete) throw new LinuxSystemdLifecycleEvidenceError('incomplete_preflight');
    if (transcript.terminal_outcome === 'dry_run_complete') {
      if (cursor !== events.length) {
        throw new LinuxSystemdLifecycleEvidenceError('invalid_dry_run_terminal');
      }
    } else {
      mutation = consumeLinearPhase(events, cursor, gate.mutation_steps, 'mutation');
      cursor = mutation.cursor;
      if (mutation.failed || mutation.complete) {
        cleanup = consumeCleanup(events, cursor, gate.always_cleanup_steps);
        cursor = cleanup.cursor;
      }
      if (cursor !== events.length) throw new LinuxSystemdLifecycleEvidenceError('unexpected_event');
    }
  }

  const denialComplete = mutation.complete && !mutation.failed;
  const finalAbsenceComplete = cleanup.complete && cleanup.lastStatus === 'verified';
  const cleanupComplete = cleanup.complete && !cleanup.failed && finalAbsenceComplete;

  if (transcript.terminal_outcome === 'denial_verified' &&
      !(preflight.complete && denialComplete && cleanupComplete)) {
    throw new LinuxSystemdLifecycleEvidenceError('false_success');
  }
  if (transcript.terminal_outcome === 'mutation_failed' &&
      !(preflight.complete && mutation.failed && cleanupComplete)) {
    throw new LinuxSystemdLifecycleEvidenceError('invalid_mutation_terminal');
  }
  if (transcript.terminal_outcome === 'cleanup_failed' &&
      !(preflight.complete && (mutation.failed || mutation.complete) && cleanup.complete && cleanup.failed)) {
    throw new LinuxSystemdLifecycleEvidenceError('invalid_cleanup_terminal');
  }
  if (transcript.terminal_outcome === 'preflight_failed' && !preflight.failed) {
    throw new LinuxSystemdLifecycleEvidenceError('invalid_preflight_terminal');
  }
  if (transcript.terminal_outcome === 'dry_run_complete' &&
      !(preflight.complete && !preflight.failed && mutation.cursor === preflight.cursor)) {
    throw new LinuxSystemdLifecycleEvidenceError('invalid_dry_run_terminal');
  }

  const structureComplete = transcript.terminal_outcome === 'denial_verified' && cleanupComplete;
  return Object.freeze({
    schema_version: 1,
    platform: 'linux',
    preflight_claim_structurally_complete: preflight.complete && !preflight.failed,
    mutation_claim_structurally_complete: mutation.complete && !mutation.failed,
    denial_claim_structurally_complete: denialComplete,
    cleanup_claim_structurally_complete: cleanupComplete,
    final_absence_claim_structurally_complete: finalAbsenceComplete,
    transcript_structure_complete: structureComplete,
    collector_trust_verified: false,
    live_test_verified: false,
    authorization_ready: false,
    install_gate_eligible: false,
    terminal_code: structureComplete
      ? 'transcript_complete_untrusted'
      : (transcript.terminal_outcome === 'dry_run_complete'
        ? 'dry_run_complete_untrusted'
        : transcript.terminal_outcome),
  });
}

function consumeLinearPhase(events, start, expectedSteps, phase) {
  let cursor = start;
  let failed = false;
  let lastStatus = '';
  for (const step of expectedSteps) {
    if (cursor >= events.length) return { cursor, complete: false, failed, lastStatus };
    const event = events[cursor];
    if (event.step !== step) throw new LinuxSystemdLifecycleEvidenceError('step_order_mismatch');
    const allowed = phase === 'mutation' && EFFECT_STEPS.has(step) ? EFFECT_STATUSES : BASE_STATUSES;
    if (!allowed.has(event.status)) throw new LinuxSystemdLifecycleEvidenceError('invalid_status_for_step');
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
    if (event.step !== step) throw new LinuxSystemdLifecycleEvidenceError('step_order_mismatch');
    if (!CLEANUP_STATUSES.has(event.status)) {
      throw new LinuxSystemdLifecycleEvidenceError('invalid_status_for_step');
    }
    failed = event.status === 'failed';
    lastStatus = event.status;
    cursor += 1;
  }
  return { cursor, complete: true, failed, lastStatus };
}

function emptyPhase(cursor) {
  return { cursor, complete: false, failed: false, lastStatus: '' };
}

function readEvent(value) {
  const event = exactObject(value, EVENT_FIELDS);
  if (typeof event.step !== 'string' || typeof event.status !== 'string') {
    throw new LinuxSystemdLifecycleEvidenceError();
  }
  return event;
}

function exactArray(value, maximum) {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new LinuxSystemdLifecycleEvidenceError();
  }
  return value;
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new LinuxSystemdLifecycleEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new LinuxSystemdLifecycleEvidenceError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new LinuxSystemdLifecycleEvidenceError();
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
