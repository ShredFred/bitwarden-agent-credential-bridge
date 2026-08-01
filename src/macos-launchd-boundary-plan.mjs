import { types as utilTypes } from 'node:util';

const SERVICE_LABEL = 'de.frederikstadler.bitwarden-agent-credential-bridge.helper';
const MACH_SERVICE = SERVICE_LABEL;
const SERVICE_ACCOUNT = '_bwagentbridge';
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_BINARY_BYTES = 64 * 1024 * 1024;
const VALID_PLANS = new WeakSet();

export class MacosLaunchdBoundaryPlanError extends Error {
  constructor(code) {
    super(`macOS launchd boundary plan rejected: ${code}`);
    this.name = 'MacosLaunchdBoundaryPlanError';
    this.code = code;
  }
}

/**
 * Build a value-free, non-executable contract for one future macOS system helper.
 * This performs no host inspection, signing, account/daemon installation, or mutation.
 */
export function buildMacosLaunchdBoundaryPlan(input) {
  const value = exactInput(input);
  if (value.platform !== 'darwin' || value.serviceManager !== 'launchd-system') {
    throw new MacosLaunchdBoundaryPlanError('unsupported_runtime_profile');
  }
  if (!isDigest(value.binarySha256) || !isDigest(value.designatedRequirementSha256) ||
      !Number.isSafeInteger(value.binaryByteLength) || value.binaryByteLength < 1 ||
      value.binaryByteLength > MAX_BINARY_BYTES) {
    throw new MacosLaunchdBoundaryPlanError('invalid_binary_binding');
  }

  const plan = deepFreeze({
    schema_version: 1,
    platform: 'darwin',
    runtime_profile: 'launchd-system',
    service: {
      label: SERVICE_LABEL,
      domain: 'system',
      account_name: SERVICE_ACCOUNT,
      account_kind: 'static_hidden_nonlogin_user',
      password_required: false,
      launch_agent_forbidden: true,
      gui_domain_forbidden: true,
      demand_activation_only: true,
      keep_alive_forbidden: true,
      stable_distinct_euid_required: true,
      network_access_required: false,
      network_access_forbidden: true,
      vault_access_required: false,
      vault_access_forbidden: true,
      keychain_access_required: false,
      keychain_access_forbidden: true,
    },
    binary: {
      sha256: value.binarySha256,
      byte_length: value.binaryByteLength,
      designated_requirement_sha256: value.designatedRequirementSha256,
      signature_policy: 'pinned_digest_and_designated_requirement',
      root_owned_required: true,
      caller_write_denied_required: true,
      helper_write_denied_required: true,
      parent_chain_symlink_free_required: true,
      parent_chain_root_owned_required: true,
      parent_chain_caller_write_denied_required: true,
      installed_digest_reverified_required: true,
      installed_code_requirement_reverified_required: true,
      retained_readonly_fd_identity_binding_required: true,
    },
    daemon: {
      plist_label: SERVICE_LABEL,
      system_domain_required: true,
      root_owned_required: true,
      caller_write_denied_required: true,
      helper_write_denied_required: true,
      parent_chain_symlink_free_required: true,
      exact_reviewed_content_digest_required: true,
      overrides_forbidden: true,
      loaded_identity_reverified_required: true,
    },
    ipc: {
      transport: 'macos_xpc_mach_service',
      mach_service_name: MACH_SERVICE,
      mach_service_bound_by_launchd_required: true,
      anonymous_listener_forbidden: true,
      peer_audit_token_required: true,
      peer_audit_token_matches_authorizing_caller_required: true,
      peer_pid_and_pidversion_binding_required: true,
      helper_pid_and_pidversion_binding_required: true,
      helper_designated_requirement_reverified_required: true,
      descriptor_passing_forbidden: true,
    },
    target_access: {
      ordinary_user_home_target_forbidden: true,
      caller_owner_forbidden: true,
      caller_write_denied_required: true,
      caller_create_denied_required: true,
      caller_delete_denied_required: true,
      helper_write_allowed_required: true,
      symlink_safe_checks_required: true,
      every_manifest_target_checked_required: true,
    },
    approval_gates: [
      'operator_reviewed_binary_plist_and_requirement',
      'operator_approved_system_scope',
      'static_helper_identity_reverified',
      'daemon_and_binary_ownership_reverified',
      'loaded_daemon_identity_reverified',
      'helper_code_requirement_reverified',
      'xpc_peer_caller_binding_reverified',
      'different_effective_uid_reverified',
      'target_access_reverified',
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

export function isMacosLaunchdBoundaryPlan(value) {
  return value !== null && typeof value === 'object' && VALID_PLANS.has(value);
}

function exactInput(value) {
  const fields = new Set([
    'platform', 'serviceManager', 'binarySha256', 'binaryByteLength', 'designatedRequirementSha256',
  ]);
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new MacosLaunchdBoundaryPlanError('invalid_input');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new MacosLaunchdBoundaryPlanError('invalid_input');
  }
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new MacosLaunchdBoundaryPlanError('invalid_input');
    }
    Object.defineProperty(result, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(result);
}

function isDigest(value) {
  return typeof value === 'string' && SHA256.test(value);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
