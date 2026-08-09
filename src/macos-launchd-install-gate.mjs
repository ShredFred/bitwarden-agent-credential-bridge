import { types as utilTypes } from 'node:util';
import { isMacosLaunchdLifecycleGate } from './macos-launchd-lifecycle-gate.mjs';

/**
 * Phase 11a: pure macOS install-gate compiler over branded lifecycle gate +
 * exact live-report schema. Always keeps authorization_ready=false.
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
  'plist_present',
  'binary_present',
  'label_loaded',
  'mach_service_bound',
  'binary_binding_verified',
  'designated_requirement_verified',
  'parent_chain_policy_matched',
  'snapshot_matches_plan',
  'authorization_ready',
]);

const BOOLEAN_LIVE_FIELDS = [...LIVE_REPORT_FIELDS].filter((field) =>
  field !== 'schema_version' && field !== 'terminal_code');

export class MacosLaunchdInstallGateError extends Error {
  constructor(code = 'invalid_install_gate_input') {
    super(`macOS launchd install gate rejected: ${code}`);
    this.name = 'MacosLaunchdInstallGateError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();
const VALID_LIVE_REPORTS = new WeakSet();

/**
 * Brand a synthetic live report for harness tests only. Not live collection.
 */
export function brandMacosLaunchdLifecycleLiveReportForHarness(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new MacosLaunchdInstallGateError('invalid_live_report');
  }
  const branded = Object.freeze({ ...report });
  VALID_LIVE_REPORTS.add(branded);
  return branded;
}

export function isMacosLaunchdLifecycleLiveReport(value) {
  return value !== null && typeof value === 'object' && VALID_LIVE_REPORTS.has(value);
}

export function evaluateMacosLaunchdInstallGate(lifecycleGate, liveReport, preflight = null) {
  if (!isMacosLaunchdLifecycleGate(lifecycleGate)) {
    throw new MacosLaunchdInstallGateError('invalid_lifecycle_gate');
  }
  if (!isMacosLaunchdLifecycleLiveReport(liveReport)) {
    throw new MacosLaunchdInstallGateError('unbranded_live_report');
  }
  const live = exactObject(liveReport, LIVE_REPORT_FIELDS);
  if (live.schema_version !== 1 || typeof live.terminal_code !== 'string' ||
      BOOLEAN_LIVE_FIELDS.some((field) => typeof live[field] !== 'boolean')) {
    throw new MacosLaunchdInstallGateError();
  }

  let preflightOk = true;
  if (preflight !== null) {
    const facts = exactObject(preflight, PREFLIGHT_FIELDS);
    if (facts.schema_version !== 1 ||
        [...PREFLIGHT_FIELDS].some((field) => field !== 'schema_version' && typeof facts[field] !== 'boolean')) {
      throw new MacosLaunchdInstallGateError('invalid_preflight');
    }
    if (facts.authorization_ready === true) {
      throw new MacosLaunchdInstallGateError('preflight_authorization_claim');
    }
    // Post-cleanup disposable matrix must show absence.
    preflightOk = facts.account_present === false &&
      facts.plist_present === false &&
      facts.binary_present === false &&
      facts.label_loaded === false &&
      facts.mach_service_bound === false &&
      facts.snapshot_matches_plan === false &&
      facts.authorization_ready === false;
  }

  const binaryBound = typeof lifecycleGate.reviewed_bindings?.binary_sha256 === 'string' &&
    typeof lifecycleGate.reviewed_bindings?.binary_byte_length === 'number' &&
    lifecycleGate.reviewed_bindings.binary_byte_length > 0 &&
    typeof lifecycleGate.reviewed_bindings?.designated_requirement_sha256 === 'string' &&
    typeof lifecycleGate.reviewed_bindings?.plist_sha256 === 'string';

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
    platform: 'darwin',
    disposable_live_denial_verified: live.live_test_verified === true,
    collector_trust_verified: live.collector_trust_verified === true,
    binary_binding_present: binaryBound,
    post_cleanup_preflight_coherent: preflightOk,
    persistent_mutator_absent: true,
    vault_access_forbidden: true,
    keychain_access_forbidden: true,
    launch_agent_forbidden: true,
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

export function isMacosLaunchdInstallGateReport(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new MacosLaunchdInstallGateError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new MacosLaunchdInstallGateError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new MacosLaunchdInstallGateError();
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
