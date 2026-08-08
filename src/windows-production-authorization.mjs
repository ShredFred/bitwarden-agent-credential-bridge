import { types as utilTypes } from 'node:util';
import { isWindowsServiceInstallGateReport } from './windows-service-install-gate.mjs';
import { isWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';

/**
 * Phase 9a: pure Windows production authorization evidence compiler.
 *
 * Sets authorization_ready=true only when branded install-gate eligibility,
 * persistent ProgramData layout, handle-bound installed-service identity,
 * complete target-ACL matrix, and Phase 5h.1 peer five-facts are all true.
 * Path-based advisory preflight alone is never sufficient.
 *
 * This module performs no host I/O, elevation, SCM mutation, pipe open,
 * manifest execution, or Bitwarden access. Synthetic harness branding may
 * exercise the true path in unit tests. Phase 9e wires the operational bridge
 * to consume this report via composeWindowsOperationalAuthorization only.
 */

export class WindowsProductionAuthorizationError extends Error {
  constructor(code = 'invalid_production_authorization_input') {
    super(`Windows production authorization rejected: ${code}`);
    this.name = 'WindowsProductionAuthorizationError';
    this.code = code;
  }
}

const HANDLE_BOUND_FIELDS = new Set([
  'schema_version',
  'pipe_local_only',
  'remote_clients_rejected',
  'server_pid_handle_bound',
  'server_token_user_local_service',
  'server_service_sid_enabled',
  'scm_service_running_same_pid',
  'binary_digest_matched_via_handle',
  'binary_chain_reparse_free',
  'binary_owner_trusted',
  'caller_service_control_denied',
  'service_dacl_caller_change_denied',
  'path_based_preflight_only',
  'collector_value_free',
]);

const TARGET_ACL_FIELDS = new Set([
  'schema_version',
  'all_targets_checked',
  'caller_write_denied',
  'helper_write_allowed',
  'ownership_trusted_not_caller',
  'shared_local_service_token_user_owner_absent',
  'reparse_points_absent',
]);

const PEER_FIELDS = new Set([
  'local_transport',
  'identity_verified',
  'different_principal',
  'caller_write_denied',
  'helper_write_allowed',
]);

const BOOLEAN_HANDLE_BOUND = [...HANDLE_BOUND_FIELDS].filter((f) => f !== 'schema_version');
const BOOLEAN_TARGET_ACL = [...TARGET_ACL_FIELDS].filter((f) => f !== 'schema_version');

const VALID_HANDLE_BOUND = new WeakSet();
const VALID_TARGET_ACL = new WeakSet();
const VALID_REPORTS = new WeakSet();

/**
 * Brand exact handle-bound identity evidence for harness tests only.
 * Live collectors must brand their own in-process objects; clones are rejected.
 */
export function brandWindowsHandleBoundIdentityEvidenceForHarness(raw) {
  const evidence = exactObject(raw, HANDLE_BOUND_FIELDS, 'invalid_handle_bound_evidence');
  if (evidence.schema_version !== 1 ||
      BOOLEAN_HANDLE_BOUND.some((field) => typeof evidence[field] !== 'boolean')) {
    throw new WindowsProductionAuthorizationError('invalid_handle_bound_evidence');
  }
  VALID_HANDLE_BOUND.add(evidence);
  return evidence;
}

/**
 * Brand exact target-ACL matrix evidence for harness tests only.
 */
export function brandWindowsTargetAclEvidenceForHarness(raw) {
  const evidence = exactObject(raw, TARGET_ACL_FIELDS, 'invalid_target_acl_evidence');
  if (evidence.schema_version !== 1 ||
      BOOLEAN_TARGET_ACL.some((field) => typeof evidence[field] !== 'boolean')) {
    throw new WindowsProductionAuthorizationError('invalid_target_acl_evidence');
  }
  VALID_TARGET_ACL.add(evidence);
  return evidence;
}

export function isWindowsHandleBoundIdentityEvidence(value) {
  return value !== null && typeof value === 'object' && VALID_HANDLE_BOUND.has(value);
}

export function isWindowsTargetAclEvidence(value) {
  return value !== null && typeof value === 'object' && VALID_TARGET_ACL.has(value);
}

/**
 * Compile branded Windows production authorization evidence.
 *
 * @param {object} installGateReport branded Phase 5h.46 report
 * @param {object} layoutPlan branded Phase 5h.47 persistent layout plan
 * @param {object} handleBoundEvidence branded handle-bound identity facts
 * @param {object} targetAclEvidence branded target ACL matrix
 * @param {object} peerEvidence Phase 5h.1 five-fact peer evidence (plain exact object)
 */
export function evaluateWindowsProductionAuthorization(
  installGateReport,
  layoutPlan,
  handleBoundEvidence,
  targetAclEvidence,
  peerEvidence,
) {
  if (!isWindowsServiceInstallGateReport(installGateReport)) {
    throw new WindowsProductionAuthorizationError('unbranded_install_gate');
  }
  if (!isWindowsHelperLayoutPlan(layoutPlan) || layoutPlan.layout_mode !== 'persistent') {
    throw new WindowsProductionAuthorizationError('invalid_persistent_layout');
  }
  if (!isWindowsHandleBoundIdentityEvidence(handleBoundEvidence)) {
    throw new WindowsProductionAuthorizationError('unbranded_handle_bound_evidence');
  }
  if (!isWindowsTargetAclEvidence(targetAclEvidence)) {
    throw new WindowsProductionAuthorizationError('unbranded_target_acl_evidence');
  }

  const peer = exactObject(peerEvidence, PEER_FIELDS, 'invalid_peer_evidence');
  for (const field of PEER_FIELDS) {
    if (typeof peer[field] !== 'boolean') {
      throw new WindowsProductionAuthorizationError('invalid_peer_evidence');
    }
  }

  if (handleBoundEvidence.path_based_preflight_only === true) {
    throw new WindowsProductionAuthorizationError('path_based_preflight_insufficient');
  }

  const installEligible = installGateReport.install_gate_eligible === true &&
    installGateReport.authorization_ready === false &&
    installGateReport.mutation_authorized === false &&
    installGateReport.vault_access_forbidden === true;

  const layoutReady = layoutPlan.program_data_class_root_required === true &&
    layoutPlan.ordinary_user_profile_root_forbidden === true &&
    layoutPlan.local_app_data_root_forbidden === true &&
    layoutPlan.home_profile_root_forbidden === true &&
    layoutPlan.shared_local_service_token_user_owner_forbidden === true &&
    layoutPlan.caller_write_denied_required === true &&
    layoutPlan.authorization_ready === false;

  const identityReady = handleBoundEvidence.pipe_local_only === true &&
    handleBoundEvidence.remote_clients_rejected === true &&
    handleBoundEvidence.server_pid_handle_bound === true &&
    handleBoundEvidence.server_token_user_local_service === true &&
    handleBoundEvidence.server_service_sid_enabled === true &&
    handleBoundEvidence.scm_service_running_same_pid === true &&
    handleBoundEvidence.binary_digest_matched_via_handle === true &&
    handleBoundEvidence.binary_chain_reparse_free === true &&
    handleBoundEvidence.binary_owner_trusted === true &&
    handleBoundEvidence.caller_service_control_denied === true &&
    handleBoundEvidence.service_dacl_caller_change_denied === true &&
    handleBoundEvidence.path_based_preflight_only === false &&
    handleBoundEvidence.collector_value_free === true;

  const aclReady = targetAclEvidence.all_targets_checked === true &&
    targetAclEvidence.caller_write_denied === true &&
    targetAclEvidence.helper_write_allowed === true &&
    targetAclEvidence.ownership_trusted_not_caller === true &&
    targetAclEvidence.shared_local_service_token_user_owner_absent === true &&
    targetAclEvidence.reparse_points_absent === true;

  const peerReady = peer.local_transport === true &&
    peer.identity_verified === true &&
    peer.different_principal === true &&
    peer.caller_write_denied === true &&
    peer.helper_write_allowed === true;

  const ready = installEligible && layoutReady && identityReady && aclReady && peerReady;

  const report = Object.freeze({
    schema_version: 1,
    platform: 'win32',
    install_gate_eligible: installEligible,
    persistent_layout_bound: layoutReady,
    handle_bound_identity_verified: identityReady,
    target_acl_evidence_complete: aclReady,
    peer_authorization_complete: peerReady,
    path_based_preflight_insufficient: true,
    helper_vault_free: true,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    mutation_authorized: false,
    install_gate_eligible_alone_insufficient: true,
    persistent_install_alone_insufficient: true,
    disposable_live_alone_insufficient: true,
    operational_bridge_unwired: true,
    authorization_ready: ready,
    terminal_code: ready
      ? 'production_authorization_ready'
      : 'production_authorization_incomplete',
  });
  VALID_REPORTS.add(report);
  return report;
}

export function isWindowsProductionAuthorizationReport(value) {
  return value !== null && typeof value === 'object' && VALID_REPORTS.has(value);
}

function exactObject(value, fields, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsProductionAuthorizationError(code);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsProductionAuthorizationError(code);
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsProductionAuthorizationError(code);
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
