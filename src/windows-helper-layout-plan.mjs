import { types as utilTypes } from 'node:util';
import { isWindowsServiceBoundaryPlan } from './windows-service-boundary-plan.mjs';

const INPUT_FIELDS = new Set(['layout_mode']);
const LAYOUT_MODES = new Set(['disposable', 'persistent']);

export class WindowsHelperLayoutPlanError extends Error {
  constructor(code) {
    super(`Windows helper layout plan rejected: ${code}`);
    this.name = 'WindowsHelperLayoutPlanError';
    this.code = code;
  }
}

const VALID_PLANS = new WeakSet();

/**
 * Build a pure, non-executable layout contract for LocalService helper artifacts
 * under trusted ProgramData-class roots. Rejects ordinary user-profile roots.
 */
export function buildWindowsHelperLayoutPlan(boundaryPlan, input) {
  if (!isWindowsServiceBoundaryPlan(boundaryPlan)) {
    throw new WindowsHelperLayoutPlanError('invalid_boundary_plan');
  }
  const value = exactInput(input);
  if (!LAYOUT_MODES.has(value.layout_mode)) {
    throw new WindowsHelperLayoutPlanError('unsupported_layout_mode');
  }

  const disposable = value.layout_mode === 'disposable';
  const plan = deepFreeze({
    schema_version: 1,
    platform: 'win32',
    layout_mode: value.layout_mode,
    service_name_bound: true,
    service_sid_ownership_required: true,
    trusted_admin_or_system_ownership_allowed: true,
    shared_local_service_token_user_owner_forbidden: true,
    ordinary_user_profile_root_forbidden: true,
    local_app_data_root_forbidden: true,
    home_profile_root_forbidden: true,
    program_data_class_root_required: true,
    caller_write_denied_required: true,
    caller_create_denied_required: true,
    reparse_points_forbidden: true,
    disposable_cleanup_required: disposable,
    persistent_uninstall_proof_required: !disposable,
    binary: {
      sha256: boundaryPlan.binary.sha256,
      byte_length: boundaryPlan.binary.byte_length,
      relative_name_fixed: true,
    },
    roots: {
      install_root_kind: disposable ? 'disposable_program_data' : 'persistent_program_data',
      config_root_kind: disposable ? 'disposable_program_data' : 'persistent_program_data',
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

export function isWindowsHelperLayoutPlan(value) {
  return value !== null && typeof value === 'object' && VALID_PLANS.has(value);
}

function exactInput(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new WindowsHelperLayoutPlanError('invalid_input');
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length !== INPUT_FIELDS.size ||
      keys.some((key) => typeof key !== 'string' || !INPUT_FIELDS.has(key))) {
    throw new WindowsHelperLayoutPlanError('invalid_input');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsHelperLayoutPlanError('invalid_input');
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
