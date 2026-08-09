import { types as utilTypes } from 'node:util';
import { isLinuxSystemdLifecycleGate } from './linux-systemd-lifecycle-gate.mjs';

/**
 * Phase 12e: pure Linux install-gate compiler. authorization_ready stays false.
 */

const LIVE_REPORT_FIELDS = new Set([
  'schema_version',
  'preflight_claim_structurally_complete',
  'mutation_claim_structurally_complete',
  'denial_claim_structurally_complete',
  'cleanup_claim_structurally_complete',
  'final_absence_claim_structurally_complete',
  'transcript_structure_complete',
  'required_provenance_complete',
  'collector_trust_verified',
  'live_test_executed',
  'live_test_verified',
  'mutation_authorized',
  'install_gate_eligible',
  'authorization_ready',
  'terminal_code',
]);

const PREFLIGHT_FIELDS = new Set([
  'schema_version',
  'account_present',
  'service_unit_present',
  'socket_unit_present',
  'binary_present',
  'socket_path_present',
  'binary_binding_verified',
  'unit_fragments_match_plan',
  'snapshot_matches_plan',
  'authorization_ready',
]);

const BOOLEAN_LIVE_FIELDS = [...LIVE_REPORT_FIELDS].filter((field) =>
  field !== 'schema_version' && field !== 'terminal_code');

export class LinuxSystemdInstallGateError extends Error {
  constructor(code = 'invalid_install_gate_input') {
    super(`Linux systemd install gate rejected: ${code}`);
    this.name = 'LinuxSystemdInstallGateError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();
const VALID_LIVE_REPORTS = new WeakSet();

export function brandLinuxSystemdLifecycleLiveReportForHarness(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new LinuxSystemdInstallGateError('invalid_live_report');
  }
  const branded = Object.freeze({ ...report });
  VALID_LIVE_REPORTS.add(branded);
  return branded;
}

export function isLinuxSystemdLifecycleLiveReport(value) {
  return value !== null && typeof value === 'object' && VALID_LIVE_REPORTS.has(value);
}

export function evaluateLinuxSystemdInstallGate(lifecycleGate, liveReport, preflight = null) {
  if (!isLinuxSystemdLifecycleGate(lifecycleGate)) {
    throw new LinuxSystemdInstallGateError('invalid_lifecycle_gate');
  }
  if (!isLinuxSystemdLifecycleLiveReport(liveReport)) {
    throw new LinuxSystemdInstallGateError('unbranded_live_report');
  }
  const live = exactObject(liveReport, LIVE_REPORT_FIELDS);
  if (live.schema_version !== 1 || typeof live.terminal_code !== 'string' ||
      BOOLEAN_LIVE_FIELDS.some((field) => typeof live[field] !== 'boolean')) {
    throw new LinuxSystemdInstallGateError();
  }

  let preflightOk = true;
  if (preflight !== null) {
    const facts = exactObject(preflight, PREFLIGHT_FIELDS);
    if (facts.schema_version !== 1 ||
        [...PREFLIGHT_FIELDS].some((field) => field !== 'schema_version' && typeof facts[field] !== 'boolean')) {
      throw new LinuxSystemdInstallGateError('invalid_preflight');
    }
    if (facts.authorization_ready === true) {
      throw new LinuxSystemdInstallGateError('preflight_authorization_claim');
    }
    preflightOk = facts.account_present === false &&
      facts.service_unit_present === false &&
      facts.socket_unit_present === false &&
      facts.binary_present === false &&
      facts.socket_path_present === false &&
      facts.snapshot_matches_plan === false &&
      facts.authorization_ready === false;
  }

  const binaryBound = typeof lifecycleGate.reviewed_bindings?.binary_sha256 === 'string' &&
    typeof lifecycleGate.reviewed_bindings?.binary_byte_length === 'number' &&
    lifecycleGate.reviewed_bindings.binary_byte_length > 0;

  const eligible = live.live_test_executed === true &&
    live.live_test_verified === true &&
    live.collector_trust_verified === true &&
    live.transcript_structure_complete === true &&
    live.terminal_code === 'live_denial_verified_cleaned' &&
    live.mutation_authorized === false &&
    live.authorization_ready === false &&
    binaryBound &&
    preflightOk;

  const report = Object.freeze({
    schema_version: 1,
    platform: 'linux',
    disposable_live_denial_verified: live.live_test_verified === true,
    collector_trust_verified: live.collector_trust_verified === true,
    binary_binding_present: binaryBound,
    post_cleanup_preflight_coherent: preflightOk,
    persistent_mutator_absent: true,
    vault_access_forbidden: true,
    dynamic_user_forbidden: true,
    abstract_socket_forbidden: true,
    install_gate_eligible: eligible,
    authorization_ready: false,
    mutation_authorized: false,
    terminal_code: eligible
      ? 'install_gate_eligible_disposable_verified'
      : 'install_gate_ineligible',
  });
  VALID_GATES.add(report);
  return report;
}

export function isLinuxSystemdInstallGateReport(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new LinuxSystemdInstallGateError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new LinuxSystemdInstallGateError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new LinuxSystemdInstallGateError();
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
