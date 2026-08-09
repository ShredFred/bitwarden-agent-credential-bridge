import { types as utilTypes } from 'node:util';
import { isLinuxSystemdLifecycleGate } from './linux-systemd-lifecycle-gate.mjs';
import { evaluateLinuxSystemdLifecycleTranscript } from './linux-systemd-lifecycle-evidence.mjs';

/**
 * Phase 12d: pure Linux elevated-collector provenance evaluator.
 */

const PROVENANCE_FIELDS = new Set([
  'schema_version',
  'elevated_token_verified',
  'local_only_collection',
  'retained_handle_binding_complete',
  'path_reacquisition_absent',
  'value_free_emission_verified',
  'stderr_absent',
  'gate_step_surface_matched',
  'cleanup_finally_bound',
  'root_euid_reported',
  'systemd_system_manager_reported',
  'initial_user_namespace_reported',
]);

const REQUIRED_TRUST_FIELDS = Object.freeze([
  'elevated_token_verified',
  'local_only_collection',
  'retained_handle_binding_complete',
  'path_reacquisition_absent',
  'value_free_emission_verified',
  'stderr_absent',
  'gate_step_surface_matched',
  'cleanup_finally_bound',
]);

const DEFENSE_IN_DEPTH_FIELDS = Object.freeze([
  'root_euid_reported',
  'systemd_system_manager_reported',
  'initial_user_namespace_reported',
]);

export class LinuxSystemdLifecycleCollectorTrustError extends Error {
  constructor(code = 'invalid_provenance') {
    super(`Linux systemd lifecycle collector trust rejected: ${code}`);
    this.name = 'LinuxSystemdLifecycleCollectorTrustError';
    this.code = code;
  }
}

const VALID_CONTRACTS = new WeakSet();

export function buildLinuxSystemdLifecycleCollectorContract(gate) {
  if (!isLinuxSystemdLifecycleGate(gate)) {
    throw new LinuxSystemdLifecycleCollectorTrustError('invalid_gate');
  }
  const contract = deepFreeze({
    schema_version: 1,
    platform: 'linux',
    gate_bound: true,
    required_provenance_fields: REQUIRED_TRUST_FIELDS,
    defense_in_depth_only_fields: DEFENSE_IN_DEPTH_FIELDS,
    requirements: {
      branded_gate_required: true,
      transcript_structure_must_be_complete: true,
      retained_handles_required: true,
      path_reacquisition_forbidden: true,
      value_free_stdout_only: true,
      stderr_forbidden: true,
      approval_not_accepted_as_api_input: true,
      defense_in_depth_signals_never_establish_trust_alone: true,
      dynamic_user_forbidden: true,
      systemd_user_manager_forbidden: true,
    },
    mutation_authorized: false,
    live_test_executed: false,
    live_test_verified: false,
    install_gate_eligible: false,
    authorization_ready: false,
  });
  VALID_CONTRACTS.add(contract);
  return contract;
}

export function isLinuxSystemdLifecycleCollectorContract(value) {
  return value !== null && typeof value === 'object' && VALID_CONTRACTS.has(value);
}

export function evaluateLinuxSystemdLifecycleCollectorTrust(gate, transcript, provenance) {
  if (!isLinuxSystemdLifecycleGate(gate)) {
    throw new LinuxSystemdLifecycleCollectorTrustError('invalid_gate');
  }
  const structure = evaluateLinuxSystemdLifecycleTranscript(gate, transcript);
  const facts = exactPlainObject(provenance, PROVENANCE_FIELDS);
  if (facts.schema_version !== 1 ||
      [...REQUIRED_TRUST_FIELDS, ...DEFENSE_IN_DEPTH_FIELDS]
        .some((field) => typeof facts[field] !== 'boolean')) {
    throw new LinuxSystemdLifecycleCollectorTrustError();
  }

  const requiredProvenance = REQUIRED_TRUST_FIELDS.every((field) => facts[field] === true);
  const defenseInDepthOnly = DEFENSE_IN_DEPTH_FIELDS.every((field) => facts[field] === true);
  const collectorTrustVerified = structure.transcript_structure_complete && requiredProvenance;

  return Object.freeze({
    schema_version: 1,
    platform: 'linux',
    preflight_claim_structurally_complete: structure.preflight_claim_structurally_complete,
    mutation_claim_structurally_complete: structure.mutation_claim_structurally_complete,
    denial_claim_structurally_complete: structure.denial_claim_structurally_complete,
    cleanup_claim_structurally_complete: structure.cleanup_claim_structurally_complete,
    final_absence_claim_structurally_complete: structure.final_absence_claim_structurally_complete,
    transcript_structure_complete: structure.transcript_structure_complete,
    required_provenance_complete: requiredProvenance,
    defense_in_depth_signals_complete: defenseInDepthOnly,
    collector_trust_verified: collectorTrustVerified,
    live_test_verified: false,
    mutation_authorized: false,
    install_gate_eligible: false,
    authorization_ready: false,
    terminal_code: collectorTrustVerified
      ? 'collector_trust_schema_satisfied_unlive'
      : (structure.transcript_structure_complete
        ? 'transcript_complete_provenance_incomplete'
        : structure.terminal_code),
  });
}

function exactPlainObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new LinuxSystemdLifecycleCollectorTrustError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new LinuxSystemdLifecycleCollectorTrustError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new LinuxSystemdLifecycleCollectorTrustError();
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
