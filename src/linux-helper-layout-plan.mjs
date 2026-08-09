import { types as utilTypes } from 'node:util';
import { isLinuxSystemdBoundaryPlan } from './linux-systemd-boundary-plan.mjs';

/**
 * Phase 12a: pure Linux persistent/disposable helper layout under systemd
 * system-instance trusted roots. Forbids $HOME / user XDG writer roots.
 */

const INPUT_FIELDS = new Set(['layout_mode']);
const LAYOUT_MODES = new Set(['disposable', 'persistent']);

export class LinuxHelperLayoutPlanError extends Error {
  constructor(code) {
    super(`Linux helper layout plan rejected: ${code}`);
    this.name = 'LinuxHelperLayoutPlanError';
    this.code = code;
  }
}

const VALID_PLANS = new WeakSet();

export function buildLinuxHelperLayoutPlan(boundaryPlan, input) {
  if (!isLinuxSystemdBoundaryPlan(boundaryPlan)) {
    throw new LinuxHelperLayoutPlanError('invalid_boundary_plan');
  }
  const value = exactInput(input);
  if (!LAYOUT_MODES.has(value.layout_mode)) {
    throw new LinuxHelperLayoutPlanError('unsupported_layout_mode');
  }

  const disposable = value.layout_mode === 'disposable';
  const plan = deepFreeze({
    schema_version: 1,
    platform: 'linux',
    layout_mode: value.layout_mode,
    service_unit_bound: true,
    socket_unit_bound: true,
    static_system_user_ownership_required: true,
    dynamic_user_forbidden: true,
    root_owned_required: true,
    ordinary_user_profile_root_forbidden: true,
    home_profile_root_forbidden: true,
    xdg_user_runtime_root_forbidden: true,
    systemd_system_unit_class_root_required: true,
    libexec_or_usr_lib_helper_class_root_required: true,
    filesystem_af_unix_runtime_required: true,
    abstract_socket_forbidden: true,
    caller_write_denied_required: true,
    service_account_write_allowed_on_targets_required: true,
    symlink_forbidden: true,
    disposable_cleanup_required: disposable,
    persistent_uninstall_proof_required: !disposable,
    binary: {
      sha256: boundaryPlan.binary.sha256,
      byte_length: boundaryPlan.binary.byte_length,
      relative_name_fixed: true,
    },
    units: {
      service_unit_name_fixed: true,
      socket_unit_name_fixed: true,
    },
    roots: {
      binary_root_kind: disposable ? 'disposable_system_libexec' : 'persistent_system_libexec',
      unit_root_kind: disposable ? 'disposable_systemd_system' : 'persistent_systemd_system',
      runtime_socket_root_kind: disposable ? 'disposable_run' : 'persistent_run',
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

export function isLinuxHelperLayoutPlan(value) {
  return value !== null && typeof value === 'object' && VALID_PLANS.has(value);
}

function exactInput(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new LinuxHelperLayoutPlanError('invalid_input');
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length !== INPUT_FIELDS.size ||
      keys.some((key) => typeof key !== 'string' || !INPUT_FIELDS.has(key))) {
    throw new LinuxHelperLayoutPlanError('invalid_input');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new LinuxHelperLayoutPlanError('invalid_input');
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
