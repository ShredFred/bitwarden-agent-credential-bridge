import { types as utilTypes } from 'node:util';
import { isWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';
import { isWindowsServiceInstallGateReport } from './windows-service-install-gate.mjs';

export class WindowsPersistentServiceLifecycleError extends Error {
  constructor(code) {
    super(`Windows persistent service lifecycle rejected: ${code}`);
    this.name = 'WindowsPersistentServiceLifecycleError';
    this.code = code;
  }
}

const VALID_PLANS = new WeakSet();

/**
 * Pure persistent install plan. Requires a branded install-gate report that is
 * eligible after disposable live denial verification.
 */
export function buildWindowsPersistentServiceLifecyclePlan(layoutPlan, installGateReport) {
  if (!isWindowsHelperLayoutPlan(layoutPlan) || layoutPlan.layout_mode !== 'persistent') {
    throw new WindowsPersistentServiceLifecycleError('invalid_layout_plan');
  }
  if (!isWindowsServiceInstallGateReport(installGateReport) ||
      installGateReport.install_gate_eligible !== true) {
    throw new WindowsPersistentServiceLifecycleError('install_gate_ineligible');
  }

  const plan = deepFreeze({
    schema_version: 1,
    platform: 'win32',
    layout_mode: 'persistent',
    operations: Object.freeze(['install', 'preflight', 'uninstall', 'prove_absent']),
    service_name_fixed: true,
    program_data_class_root_required: true,
    ordinary_user_profile_root_forbidden: true,
    collision_reacquisition_forbidden: true,
    uninstall_absence_proof_required: true,
    helper_vault_free: true,
    mutation_authorized: false,
    live_test_executed: false,
    install_gate_eligible: true,
    authorization_ready: false,
    terminal_code: 'persistent_lifecycle_plan_ready',
  });
  VALID_PLANS.add(plan);
  return plan;
}

/**
 * Pure uninstall/absence plan for a persistent layout. Does not invent install
 * eligibility from forged live transcripts; cleanup is representable without a
 * prior install-gate report so operators can remove a leftover service.
 */
export function buildWindowsPersistentServiceUninstallPlan(layoutPlan) {
  if (!isWindowsHelperLayoutPlan(layoutPlan) || layoutPlan.layout_mode !== 'persistent') {
    throw new WindowsPersistentServiceLifecycleError('invalid_layout_plan');
  }
  const plan = deepFreeze({
    schema_version: 1,
    platform: 'win32',
    layout_mode: 'persistent',
    operations: Object.freeze(['uninstall', 'prove_absent']),
    service_name_fixed: true,
    program_data_class_root_required: true,
    ordinary_user_profile_root_forbidden: true,
    collision_reacquisition_forbidden: true,
    uninstall_absence_proof_required: true,
    helper_vault_free: true,
    mutation_authorized: false,
    live_test_executed: false,
    install_gate_eligible: false,
    authorization_ready: false,
    terminal_code: 'persistent_uninstall_plan_ready',
  });
  VALID_PLANS.add(plan);
  return plan;
}

export function isWindowsPersistentServiceLifecyclePlan(value) {
  return value !== null && typeof value === 'object' && VALID_PLANS.has(value);
}

/**
 * Evaluate a value-free persistent lifecycle transcript produced by a future
 * elevated collector. Does not mutate the host.
 */
export function evaluateWindowsPersistentServiceLifecycleReport(plan, raw) {
  if (!isWindowsPersistentServiceLifecyclePlan(plan)) {
    throw new WindowsPersistentServiceLifecycleError('invalid_plan');
  }
  const report = exactObject(raw, new Set([
    'schema_version',
    'operation',
    'verified',
    'service_present',
    'absence_proven',
    'collision_detected',
  ]));
  if (report.schema_version !== 1 || !plan.operations.includes(report.operation) ||
      typeof report.verified !== 'boolean' || typeof report.service_present !== 'boolean' ||
      typeof report.absence_proven !== 'boolean' || typeof report.collision_detected !== 'boolean') {
    throw new WindowsPersistentServiceLifecycleError('invalid_report');
  }
  if (report.collision_detected) {
    return Object.freeze({
      schema_version: 1,
      operation: report.operation,
      ok: false,
      authorization_ready: false,
      terminal_code: 'persistent_collision_rejected',
    });
  }
  const ok = report.verified === true && (
    report.operation === 'uninstall' || report.operation === 'prove_absent'
      ? report.absence_proven === true && report.service_present === false
      : report.operation === 'install'
        ? report.service_present === true
        : true
  );
  return Object.freeze({
    schema_version: 1,
    operation: report.operation,
    ok,
    authorization_ready: false,
    terminal_code: ok ? 'persistent_lifecycle_verified' : 'persistent_lifecycle_failed',
  });
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsPersistentServiceLifecycleError('invalid_report');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsPersistentServiceLifecycleError('invalid_report');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsPersistentServiceLifecycleError('invalid_report');
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
