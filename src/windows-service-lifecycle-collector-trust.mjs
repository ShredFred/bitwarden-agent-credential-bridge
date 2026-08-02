import { types as utilTypes } from 'node:util';
import { isWindowsServiceLifecycleGate } from './windows-service-lifecycle-gate.mjs';
import { evaluateWindowsServiceLifecycleTranscript } from './windows-service-lifecycle-evidence.mjs';

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
  'uac_consent_observed',
  'admin_group_present',
  'high_integrity_reported',
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
  'uac_consent_observed',
  'admin_group_present',
  'high_integrity_reported',
]);

export class WindowsServiceLifecycleCollectorTrustError extends Error {
  constructor(code = 'invalid_provenance') {
    super(`Windows service lifecycle collector trust rejected: ${code}`);
    this.name = 'WindowsServiceLifecycleCollectorTrustError';
    this.code = code;
  }
}

const VALID_CONTRACTS = new WeakSet();

/**
 * Freeze the non-executable collector-trust contract bound to a branded lifecycle
 * gate. This performs no I/O and does not authorize mutation or live collection.
 */
export function buildWindowsServiceLifecycleCollectorContract(gate) {
  if (!isWindowsServiceLifecycleGate(gate)) {
    throw new WindowsServiceLifecycleCollectorTrustError('invalid_gate');
  }
  const contract = deepFreeze({
    schema_version: 1,
    platform: 'win32',
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

export function isWindowsServiceLifecycleCollectorContract(value) {
  return value !== null && typeof value === 'object' && VALID_CONTRACTS.has(value);
}

/**
 * Compile a Phase 5h.16 transcript plus trusted injected collector provenance into
 * a value-free trust report. Synthetic provenance can satisfy the schema in tests;
 * only a later live elevated collector may claim live verification.
 */
export function evaluateWindowsServiceLifecycleCollectorTrust(gate, transcript, provenance) {
  if (!isWindowsServiceLifecycleGate(gate)) {
    throw new WindowsServiceLifecycleCollectorTrustError('invalid_gate');
  }
  const structure = evaluateWindowsServiceLifecycleTranscript(gate, transcript);
  const facts = exactPlainObject(provenance, PROVENANCE_FIELDS);
  if (facts.schema_version !== 1 ||
      [...REQUIRED_TRUST_FIELDS, ...DEFENSE_IN_DEPTH_FIELDS]
        .some((field) => typeof facts[field] !== 'boolean')) {
    throw new WindowsServiceLifecycleCollectorTrustError();
  }

  const requiredProvenance = REQUIRED_TRUST_FIELDS.every((field) => facts[field] === true);
  // UAC consent, admin group membership, and high integrity alone never establish
  // collector trust when retained-handle elevated provenance is incomplete.
  const defenseInDepthOnly = DEFENSE_IN_DEPTH_FIELDS.every((field) => facts[field] === true);
  const collectorTrustVerified = structure.transcript_structure_complete && requiredProvenance;

  return Object.freeze({
    schema_version: 1,
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
    terminal_code: terminalCode(structure, collectorTrustVerified),
  });
}

function terminalCode(structure, collectorTrustVerified) {
  if (collectorTrustVerified) return 'collector_trust_schema_satisfied_unlive';
  if (structure.transcript_structure_complete) return 'transcript_complete_provenance_incomplete';
  return structure.terminal_code;
}

function exactPlainObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsServiceLifecycleCollectorTrustError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsServiceLifecycleCollectorTrustError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsServiceLifecycleCollectorTrustError();
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
