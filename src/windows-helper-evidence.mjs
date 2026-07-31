import { timingSafeEqual } from 'node:crypto';
import { types as utilTypes } from 'node:util';

const EVIDENCE_FIELDS = new Set([
  'schema_version',
  'transport_kind',
  'remote_clients_rejected',
  'client_pid_verified',
  'server_pid_verified',
  'caller_token_verified',
  'helper_token_verified',
  'caller_token_user_sha256',
  'helper_token_user_sha256',
  'caller_is_restricted',
  'caller_is_app_container',
  'acl_checks_verified',
  'all_targets_checked',
  'caller_effective_write_denied',
  'helper_required_write_allowed',
]);
const BOOLEAN_FIELDS = [...EVIDENCE_FIELDS].filter((field) => ![
  'schema_version',
  'transport_kind',
  'caller_token_user_sha256',
  'helper_token_user_sha256',
].includes(field));

export class WindowsHelperEvidenceError extends Error {
  constructor(code = 'peer_identity_unverified') {
    super(`Windows helper evidence rejected: ${code}`);
    this.name = 'WindowsHelperEvidenceError';
    this.code = code;
  }
}

/**
 * Compile trusted, value-free Win32 probe facts into the cross-platform helper
 * authorization shape. This function performs no I/O and returns no identities.
 */
export function evaluateWindowsHelperPeerEvidence(raw) {
  const facts = exactPlainObject(raw, EVIDENCE_FIELDS);
  if (facts.schema_version !== 1 || facts.transport_kind !== 'windows_named_pipe' ||
      BOOLEAN_FIELDS.some((field) => typeof facts[field] !== 'boolean') ||
      !isDigest(facts.caller_token_user_sha256) || !isDigest(facts.helper_token_user_sha256)) {
    throw new WindowsHelperEvidenceError();
  }

  const callerDigest = Buffer.from(facts.caller_token_user_sha256, 'hex');
  const helperDigest = Buffer.from(facts.helper_token_user_sha256, 'hex');
  const sameTokenUser = timingSafeEqual(callerDigest, helperDigest);
  const localTransport = facts.remote_clients_rejected &&
    facts.client_pid_verified && facts.server_pid_verified;
  const identityVerified = facts.caller_token_verified && facts.helper_token_verified;

  return Object.freeze({
    local_transport: localTransport,
    identity_verified: identityVerified,
    different_principal: identityVerified && !sameTokenUser,
    caller_write_denied: facts.acl_checks_verified && facts.all_targets_checked &&
      facts.caller_effective_write_denied,
    helper_write_allowed: facts.acl_checks_verified && facts.all_targets_checked &&
      facts.helper_required_write_allowed,
  });
}

function exactPlainObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsHelperEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsHelperEvidenceError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new WindowsHelperEvidenceError();
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}

function isDigest(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
