import { timingSafeEqual } from 'node:crypto';
import { types as utilTypes } from 'node:util';

const EVIDENCE_FIELDS = new Set([
  'schema_version',
  'transport_kind',
  'mach_service_bound',
  'xpc_peer_connection_verified',
  'peer_audit_token_verified',
  'peer_audit_token_matches_caller_audit_token',
  'peer_pid_verified',
  'peer_pidversion_verified',
  'helper_pid_verified',
  'helper_pidversion_verified',
  'caller_audit_token_verified',
  'helper_audit_token_verified',
  'caller_euid_verified',
  'helper_euid_verified',
  'audit_token_euid_matches_caller_euid',
  'audit_token_euid_matches_helper_euid',
  'helper_code_identity_verified',
  'helper_code_requirement_satisfied',
  'caller_euid_sha256',
  'helper_euid_sha256',
  'target_access_checked_symlink_safe',
  'access_checks_verified',
  'all_targets_checked',
  'caller_effective_write_denied',
  'helper_required_write_allowed',
  'caller_app_sandbox_active',
  'helper_app_sandbox_active',
  'caller_hardened_runtime',
  'helper_hardened_runtime',
  'caller_code_signature_valid',
  'caller_code_requirement_differs',
  'caller_audit_session_differs',
  'caller_sandbox_blocks_some_writes',
]);
const NON_BOOLEAN_FIELDS = new Set([
  'schema_version',
  'transport_kind',
  'caller_euid_sha256',
  'helper_euid_sha256',
]);
const BOOLEAN_FIELDS = [...EVIDENCE_FIELDS].filter((field) => !NON_BOOLEAN_FIELDS.has(field));

export class MacosHelperEvidenceError extends Error {
  constructor(code = 'peer_identity_unverified') {
    super(`macOS helper evidence rejected: ${code}`);
    this.name = 'MacosHelperEvidenceError';
    this.code = code;
  }
}

/** Compile trusted macOS audit-token/code/access facts without returning values. */
export function evaluateMacosHelperPeerEvidence(raw) {
  const facts = exactPlainObject(raw, EVIDENCE_FIELDS);
  if (facts.schema_version !== 1 || facts.transport_kind !== 'macos_xpc_mach_service' ||
      BOOLEAN_FIELDS.some((field) => typeof facts[field] !== 'boolean') ||
      !isDigest(facts.caller_euid_sha256) || !isDigest(facts.helper_euid_sha256)) {
    throw new MacosHelperEvidenceError();
  }

  const sameEuid = timingSafeEqual(
    Buffer.from(facts.caller_euid_sha256, 'hex'),
    Buffer.from(facts.helper_euid_sha256, 'hex'),
  );
  const identityVerified = facts.peer_audit_token_verified &&
    facts.caller_audit_token_verified && facts.helper_audit_token_verified &&
    facts.peer_audit_token_matches_caller_audit_token &&
    facts.caller_euid_verified && facts.helper_euid_verified &&
    facts.audit_token_euid_matches_caller_euid && facts.audit_token_euid_matches_helper_euid &&
    facts.helper_code_identity_verified &&
    facts.helper_code_requirement_satisfied;
  const accessProofComplete = facts.target_access_checked_symlink_safe &&
    facts.access_checks_verified && facts.all_targets_checked;

  return Object.freeze({
    local_transport: facts.mach_service_bound && facts.xpc_peer_connection_verified &&
      facts.peer_audit_token_verified && facts.peer_audit_token_matches_caller_audit_token &&
      facts.peer_pid_verified && facts.peer_pidversion_verified &&
      facts.helper_pid_verified && facts.helper_pidversion_verified,
    identity_verified: identityVerified,
    different_principal: identityVerified && !sameEuid,
    caller_write_denied: accessProofComplete && facts.caller_effective_write_denied,
    helper_write_allowed: accessProofComplete && facts.helper_required_write_allowed,
  });
}

function exactPlainObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new MacosHelperEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new MacosHelperEvidenceError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new MacosHelperEvidenceError();
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}

function isDigest(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
