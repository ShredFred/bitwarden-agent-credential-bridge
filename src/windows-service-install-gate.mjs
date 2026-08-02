import { types as utilTypes } from 'node:util';
import { isWindowsServiceLifecycleGate } from './windows-service-lifecycle-gate.mjs';
import { isWindowsServiceLifecycleLiveReport } from './windows-service-lifecycle-live.mjs';

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
  'service_present',
  'account_local_service',
  'demand_start',
  'win32_own_process',
  'service_sid_unrestricted',
  'caller_service_control_denied',
  'binary_binding_verified',
  'binary_chain_reparse_free',
  'binary_owner_trusted',
  'caller_binary_control_denied',
  'snapshot_matches_plan',
  'authorization_ready',
]);

const BOOLEAN_LIVE_FIELDS = [...LIVE_REPORT_FIELDS].filter((field) =>
  field !== 'schema_version' && field !== 'terminal_code');

export class WindowsServiceInstallGateError extends Error {
  constructor(code = 'invalid_install_gate_input') {
    super(`Windows service install gate rejected: ${code}`);
    this.name = 'WindowsServiceInstallGateError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();

/**
 * Compile branded lifecycle gate + live disposable denial report (+ optional
 * advisory preflight) into install-gate eligibility. This performs no host
 * mutation and does not authorize a persistent install executor by itself.
 */
export function evaluateWindowsServiceInstallGate(lifecycleGate, liveReport, preflight = null) {
  if (!isWindowsServiceLifecycleGate(lifecycleGate)) {
    throw new WindowsServiceInstallGateError('invalid_lifecycle_gate');
  }
  if (!isWindowsServiceLifecycleLiveReport(liveReport)) {
    throw new WindowsServiceInstallGateError('unbranded_live_report');
  }
  const live = exactObject(liveReport, LIVE_REPORT_FIELDS);
  if (live.schema_version !== 1 || typeof live.terminal_code !== 'string' ||
      BOOLEAN_LIVE_FIELDS.some((field) => typeof live[field] !== 'boolean')) {
    throw new WindowsServiceInstallGateError();
  }

  let preflightOk = true;
  if (preflight !== null) {
    const facts = exactObject(preflight, PREFLIGHT_FIELDS);
    if (facts.schema_version !== 1 ||
        [...PREFLIGHT_FIELDS].some((field) => field !== 'schema_version' && typeof facts[field] !== 'boolean')) {
      throw new WindowsServiceInstallGateError('invalid_preflight');
    }
    // After a successful disposable live cleanup the service must be absent.
    // A present service snapshot is incoherent with the disposable matrix.
    if (facts.authorization_ready === true) {
      throw new WindowsServiceInstallGateError('preflight_authorization_claim');
    }
    preflightOk = facts.service_present === false &&
      facts.snapshot_matches_plan === false &&
      facts.authorization_ready === false;
  }

  const binaryBound = typeof lifecycleGate.binary_binding?.sha256 === 'string' &&
    typeof lifecycleGate.binary_binding?.byte_length === 'number' &&
    lifecycleGate.binary_binding.byte_length > 0;

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
    platform: 'win32',
    disposable_live_denial_verified: live.live_test_verified === true,
    collector_trust_verified: live.collector_trust_verified === true,
    binary_binding_present: binaryBound,
    post_cleanup_preflight_coherent: preflightOk,
    persistent_mutator_absent: true,
    vault_access_forbidden: true,
    install_gate_eligible: eligible,
    authorization_ready: false,
    mutation_authorized: false,
    terminal_code: eligible ? 'install_gate_eligible_disposable_verified' : 'install_gate_ineligible',
  });
  VALID_GATES.add(report);
  return report;
}

export function isWindowsServiceInstallGateReport(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsServiceInstallGateError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsServiceInstallGateError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsServiceInstallGateError();
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
