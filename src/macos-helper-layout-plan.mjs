import { types as utilTypes } from 'node:util';
import { isMacosLaunchdBoundaryPlan } from './macos-launchd-boundary-plan.mjs';

/**
 * Phase 11b: pure macOS persistent/disposable helper layout contract.
 * Forbids Application Support / home writer roots. Emits no concrete paths.
 */

const INPUT_FIELDS = new Set(['layout_mode']);
const LAYOUT_MODES = new Set(['disposable', 'persistent']);

export class MacosHelperLayoutPlanError extends Error {
  constructor(code) {
    super(`macOS helper layout plan rejected: ${code}`);
    this.name = 'MacosHelperLayoutPlanError';
    this.code = code;
  }
}

const VALID_PLANS = new WeakSet();

export function buildMacosHelperLayoutPlan(boundaryPlan, input) {
  if (!isMacosLaunchdBoundaryPlan(boundaryPlan)) {
    throw new MacosHelperLayoutPlanError('invalid_boundary_plan');
  }
  const value = exactInput(input);
  if (!LAYOUT_MODES.has(value.layout_mode)) {
    throw new MacosHelperLayoutPlanError('unsupported_layout_mode');
  }

  const disposable = value.layout_mode === 'disposable';
  const plan = deepFreeze({
    schema_version: 1,
    platform: 'darwin',
    layout_mode: value.layout_mode,
    service_label_bound: true,
    mach_service_bound: true,
    static_helper_account_ownership_required: true,
    root_owned_required: true,
    distinct_euid_ownership_required: true,
    ordinary_user_profile_root_forbidden: true,
    application_support_root_forbidden: true,
    home_profile_root_forbidden: true,
    privileged_helper_tools_class_root_required: true,
    launch_daemons_class_root_required: true,
    launch_agent_forbidden: true,
    caller_write_denied_required: true,
    helper_write_denied_on_binary_required: true,
    symlink_reparse_forbidden: true,
    disposable_cleanup_required: disposable,
    persistent_uninstall_proof_required: !disposable,
    binary: {
      sha256: boundaryPlan.binary.sha256,
      byte_length: boundaryPlan.binary.byte_length,
      designated_requirement_sha256: boundaryPlan.binary.designated_requirement_sha256,
      relative_name_fixed: true,
    },
    daemon: {
      plist_sha256: boundaryPlan.daemon.sha256,
      relative_name_fixed: true,
    },
    roots: {
      binary_root_kind: disposable
        ? 'disposable_privileged_helper_tools'
        : 'persistent_privileged_helper_tools',
      plist_root_kind: disposable
        ? 'disposable_launch_daemons'
        : 'persistent_launch_daemons',
      user_indirection_read_only: true,
    },
    mutation_authorized: false,
    live_test_executed: false,
    install_gate_eligible: false,
    authorization_ready: false,
  });
  VALID_PLANS.add(plan);
  return plan;
}

export function isMacosHelperLayoutPlan(value) {
  return value !== null && typeof value === 'object' && VALID_PLANS.has(value);
}

function exactInput(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new MacosHelperLayoutPlanError('invalid_input');
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length !== INPUT_FIELDS.size ||
      keys.some((key) => typeof key !== 'string' || !INPUT_FIELDS.has(key))) {
    throw new MacosHelperLayoutPlanError('invalid_input');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new MacosHelperLayoutPlanError('invalid_input');
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
