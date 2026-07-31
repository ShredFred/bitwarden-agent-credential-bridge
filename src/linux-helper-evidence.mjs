import { timingSafeEqual } from 'node:crypto';

const EVIDENCE_FIELDS = new Set([
  'schema_version',
  'transport_kind',
  'peercred_verified',
  'peer_pid_verified',
  'helper_pid_verified',
  'caller_creds_verified',
  'helper_creds_verified',
  'caller_uid_translated_to_init_userns',
  'helper_uid_translated_to_init_userns',
  'helper_user_ns_is_init',
  'peercred_uid_matches_caller_host_uid',
  'caller_host_uid_sha256',
  'helper_host_uid_sha256',
  'caller_user_ns_is_init',
  'caller_appears_uid0_in_own_userns',
  'caller_uid_map_maps_root_to_noninit',
  'target_access_checked_in_helper_mount_ns',
  'access_checks_verified',
  'all_targets_checked',
  'caller_effective_write_denied',
  'helper_required_write_allowed',
  'caller_no_new_privs',
  'helper_no_new_privs',
  'caller_cap_effective_empty',
  'helper_cap_effective_empty',
  'caller_seccomp_mode_filter',
  'helper_seccomp_mode_filter',
  'caller_landlock_active',
  'helper_landlock_active',
]);
const NON_BOOLEAN_FIELDS = new Set([
  'schema_version',
  'transport_kind',
  'caller_host_uid_sha256',
  'helper_host_uid_sha256',
]);
const BOOLEAN_FIELDS = [...EVIDENCE_FIELDS].filter((field) => !NON_BOOLEAN_FIELDS.has(field));

export class LinuxHelperEvidenceError extends Error {
  constructor(code = 'peer_identity_unverified') {
    super(`Linux helper evidence rejected: ${code}`);
    this.name = 'LinuxHelperEvidenceError';
    this.code = code;
  }
}

/** Compile trusted Linux peer/access facts without returning identity values. */
export function evaluateLinuxHelperPeerEvidence(raw) {
  const facts = exactPlainObject(raw, EVIDENCE_FIELDS);
  if (facts.schema_version !== 1 || facts.transport_kind !== 'linux_af_unix' ||
      BOOLEAN_FIELDS.some((field) => typeof facts[field] !== 'boolean') ||
      !isDigest(facts.caller_host_uid_sha256) || !isDigest(facts.helper_host_uid_sha256)) {
    throw new LinuxHelperEvidenceError();
  }

  const callerDigest = Buffer.from(facts.caller_host_uid_sha256, 'hex');
  const helperDigest = Buffer.from(facts.helper_host_uid_sha256, 'hex');
  const sameHostUid = timingSafeEqual(callerDigest, helperDigest);
  const identityVerified = facts.caller_creds_verified && facts.helper_creds_verified &&
    facts.caller_uid_translated_to_init_userns && facts.helper_uid_translated_to_init_userns &&
    facts.helper_user_ns_is_init && facts.peercred_uid_matches_caller_host_uid;
  const accessProofComplete = facts.target_access_checked_in_helper_mount_ns &&
    facts.access_checks_verified && facts.all_targets_checked;

  return Object.freeze({
    local_transport: facts.peercred_verified && facts.peer_pid_verified && facts.helper_pid_verified,
    identity_verified: identityVerified,
    different_principal: identityVerified && !sameHostUid,
    caller_write_denied: accessProofComplete && facts.caller_effective_write_denied,
    helper_write_allowed: accessProofComplete && facts.helper_required_write_allowed,
  });
}

function exactPlainObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new LinuxHelperEvidenceError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new LinuxHelperEvidenceError();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new LinuxHelperEvidenceError();
  }
  return value;
}

function isDigest(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
