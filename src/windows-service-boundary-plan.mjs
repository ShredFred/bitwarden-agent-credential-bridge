const SERVICE_NAME = 'BitwardenAgentCredentialBridgeHelper';
const SERVICE_ACCOUNT = 'NT AUTHORITY\\LocalService';
const PIPE_NAME = 'bitwarden-agent-credential-bridge-helper-v1';
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_BINARY_BYTES = 64 * 1024 * 1024;
const VALID_PLANS = new WeakSet();

export class WindowsServiceBoundaryPlanError extends Error {
  constructor(code) {
    super(`Windows service boundary plan rejected: ${code}`);
    this.name = 'WindowsServiceBoundaryPlanError';
    this.code = code;
  }
}

/**
 * Build a value-free, non-executable contract for a future Windows helper service.
 * This performs no host inspection, account creation, service install, or ACL change.
 */
export function buildWindowsServiceBoundaryPlan(input) {
  const value = exactInput(input);
  if (typeof value.platform !== 'string' || value.platform !== 'win32') {
    throw new WindowsServiceBoundaryPlanError('unsupported_platform');
  }
  if (typeof value.binarySha256 !== 'string' || !SHA256.test(value.binarySha256) ||
      !Number.isSafeInteger(value.binaryByteLength) ||
      value.binaryByteLength < 1 || value.binaryByteLength > MAX_BINARY_BYTES) {
    throw new WindowsServiceBoundaryPlanError('invalid_binary_binding');
  }

  const plan = deepFreeze({
    schema_version: 1,
    platform: 'win32',
    service: {
      name: SERVICE_NAME,
      account: SERVICE_ACCOUNT,
      password_required: false,
      sid_type: 'unrestricted',
      start_type: 'demand',
      network_access_required: false,
      vault_access_required: false,
      token_user_must_be_local_service: true,
      service_sid_token_group_required: true,
      caller_change_config_denied_required: true,
    },
    binary: {
      sha256: value.binarySha256,
      byte_length: value.binaryByteLength,
      signature_policy: 'pinned_digest_and_operator_review',
      installed_digest_reverified_required: true,
      caller_write_denied_required: true,
      parent_chain_reparse_free_required: true,
    },
    ipc: {
      transport: 'windows_named_pipe',
      pipe_name: PIPE_NAME,
      remote_clients_rejected: true,
      first_instance_required: true,
      caller_pid_token_binding_required: true,
      server_pid_token_binding_required: true,
      server_token_user_local_service_required: true,
      server_service_sid_group_required: true,
    },
    target_acl: {
      trusted_or_expected_service_sid_owned_root_required: true,
      shared_local_service_token_user_owner_forbidden: true,
      caller_owner_forbidden: true,
      caller_write_denied_required: true,
      caller_create_denied_required: true,
      caller_write_dac_denied_required: true,
      caller_write_owner_denied_required: true,
      caller_delete_denied_required: true,
      ancestor_delete_child_denied_required: true,
      service_sid_write_allowed_required: true,
      inherited_broad_write_aces_forbidden: true,
      ordinary_user_profile_root_forbidden: true,
    },
    approval_gates: [
      'operator_reviewed_binary',
      'operator_approved_elevation',
      'service_configuration_reverified',
      'service_object_dacl_reverified',
      'binary_path_acl_reverified',
      'target_ownership_and_control_rights_reverified',
      'pipe_acl_reverified',
      'pipe_server_identity_reverified',
      'different_token_user_reverified',
      'disposable_apply_rollback_verified',
      'cleanup_verified',
    ],
  });
  VALID_PLANS.add(plan);
  return plan;
}

export function isWindowsServiceBoundaryPlan(value) {
  return value !== null && typeof value === 'object' && VALID_PLANS.has(value);
}

function exactInput(value) {
  const fields = new Set(['platform', 'binarySha256', 'binaryByteLength']);
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== fields.size ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsServiceBoundaryPlanError('invalid_input');
  }
  const result = {};
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsServiceBoundaryPlanError('invalid_input');
    }
    result[key] = descriptor.value;
  }
  return result;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
