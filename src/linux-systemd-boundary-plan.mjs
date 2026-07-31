import { types as utilTypes } from 'node:util';

const SERVICE_UNIT = 'bitwarden-agent-credential-bridge-helper.service';
const SOCKET_UNIT = 'bitwarden-agent-credential-bridge-helper.socket';
const SERVICE_ACCOUNT = 'bitwarden-agent-bridge';
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_BINARY_BYTES = 64 * 1024 * 1024;
const VALID_PLANS = new WeakSet();

export class LinuxSystemdBoundaryPlanError extends Error {
  constructor(code) {
    super(`Linux systemd boundary plan rejected: ${code}`);
    this.name = 'LinuxSystemdBoundaryPlanError';
    this.code = code;
  }
}

/**
 * Build a value-free, non-executable contract for one future systemd system
 * helper. This performs no host inspection, account/unit install, or mutation.
 */
export function buildLinuxSystemdBoundaryPlan(input) {
  const value = exactInput(input);
  if (value.platform !== 'linux' || value.serviceManager !== 'systemd-system') {
    throw new LinuxSystemdBoundaryPlanError('unsupported_runtime_profile');
  }
  if (typeof value.binarySha256 !== 'string' || !SHA256.test(value.binarySha256) ||
      !Number.isSafeInteger(value.binaryByteLength) || value.binaryByteLength < 1 ||
      value.binaryByteLength > MAX_BINARY_BYTES) {
    throw new LinuxSystemdBoundaryPlanError('invalid_binary_binding');
  }

  const plan = deepFreeze({
    schema_version: 1,
    platform: 'linux',
    runtime_profile: 'systemd-system',
    service: {
      unit_name: SERVICE_UNIT,
      account_name: SERVICE_ACCOUNT,
      account_kind: 'static_system_user',
      password_required: false,
      interactive_login_forbidden: true,
      home_directory_forbidden: true,
      dynamic_user_forbidden: true,
      type_exec_required: true,
      demand_activation_only: true,
      restart_forbidden: true,
      network_access_required: false,
      network_access_forbidden: true,
      vault_access_required: false,
      initial_user_namespace_required: true,
    },
    binary: {
      sha256: value.binarySha256,
      byte_length: value.binaryByteLength,
      signature_policy: 'pinned_digest_and_operator_review',
      root_owned_required: true,
      service_account_write_denied_required: true,
      caller_write_denied_required: true,
      parent_chain_symlink_free_required: true,
      parent_chain_root_owned_required: true,
      parent_chain_caller_write_denied_required: true,
      parent_chain_service_account_write_denied_required: true,
      mount_chain_trusted_required: true,
      retained_readonly_fd_identity_binding_required: true,
      openat2_beneath_no_symlinks_resolution_required: true,
      installed_digest_reverified_required: true,
    },
    units: {
      service_unit_name: SERVICE_UNIT,
      socket_unit_name: SOCKET_UNIT,
      root_owned_required: true,
      caller_write_denied_required: true,
      service_account_write_denied_required: true,
      parent_chain_root_owned_required: true,
      parent_chain_caller_write_denied_required: true,
      parent_chain_service_account_write_denied_required: true,
      mount_chain_trusted_required: true,
      exact_reviewed_content_digest_required: true,
      drop_ins_forbidden: true,
      aliases_forbidden: true,
      daemon_reload_then_fragment_path_reverified_required: true,
      daemon_reload_then_drop_in_paths_empty_reverified_required: true,
      loaded_unit_identity_bound_to_retained_fd_required: true,
    },
    ipc: {
      transport: 'linux_af_unix_stream',
      filesystem_socket_required: true,
      abstract_socket_forbidden: true,
      socket_path_derived_by_unit_required: true,
      root_owned_runtime_directory_required: true,
      caller_connect_only_acl_required: true,
      caller_socket_replace_denied_required: true,
      descriptor_passing_forbidden: true,
      peercred_and_pid_binding_required: true,
      helper_pid_binding_required: true,
      stale_socket_absence_reverified_required: true,
    },
    sandbox: {
      no_new_privileges_required: true,
      empty_capability_bounding_set_required: true,
      empty_ambient_capabilities_required: true,
      private_devices_required: true,
      private_tmp_required: true,
      protect_system_strict_required: true,
      protect_home_required: true,
      restrict_suid_sgid_required: true,
      writable_paths_allowlist_required: true,
      private_network_required: true,
      restrict_address_families_exact_af_unix_required: true,
      ip_address_deny_any_required: true,
      network_sandbox_enforcement_reverified_required: true,
    },
    target_access: {
      caller_owner_forbidden: true,
      caller_write_denied_required: true,
      caller_create_denied_required: true,
      caller_delete_denied_required: true,
      service_account_write_allowed_required: true,
      checks_in_helper_mount_namespace_required: true,
      every_manifest_target_checked_required: true,
      ordinary_user_home_target_forbidden: true,
    },
    approval_gates: [
      'operator_reviewed_binary_and_units',
      'operator_approved_root_scope',
      'systemd_system_manager_reverified',
      'fixed_account_absence_or_exact_identity_reverified',
      'unit_and_binary_ownership_reverified',
      'unit_binary_parent_mount_and_loaded_identity_reverified',
      'sandbox_properties_reverified',
      'socket_peer_and_acl_reverified',
      'different_initial_userns_uid_reverified',
      'disposable_denial_probe_verified',
      'cleanup_verified',
    ],
    mutation_authorized: false,
    live_test_executed: false,
    install_gate_eligible: false,
  });
  VALID_PLANS.add(plan);
  return plan;
}

export function isLinuxSystemdBoundaryPlan(value) {
  return value !== null && typeof value === 'object' && VALID_PLANS.has(value);
}

function exactInput(value) {
  const fields = new Set([
    'platform', 'serviceManager', 'binarySha256', 'binaryByteLength',
  ]);
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new LinuxSystemdBoundaryPlanError('invalid_input');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new LinuxSystemdBoundaryPlanError('invalid_input');
  }
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new LinuxSystemdBoundaryPlanError('invalid_input');
    }
    Object.defineProperty(result, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(result);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
