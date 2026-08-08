import { buildWindowsServiceBoundaryPlan } from './windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';
import { buildWindowsServiceLifecycleGate } from './windows-service-lifecycle-gate.mjs';
import {
  brandWindowsServiceLifecycleLiveReportForHarness,
  evaluateLiveCollectorResult,
} from './windows-service-lifecycle-live.mjs';
import { evaluateWindowsServiceInstallGate } from './windows-service-install-gate.mjs';
import {
  brandWindowsHandleBoundIdentityEvidenceForHarness,
  brandWindowsTargetAclEvidenceForHarness,
  evaluateWindowsProductionAuthorization,
  isWindowsHandleBoundIdentityEvidence,
  isWindowsProductionAuthorizationReport,
  isWindowsTargetAclEvidence,
  WindowsProductionAuthorizationError,
} from './windows-production-authorization.mjs';
import {
  brandWindowsPeerAuthorizationEvidence,
  isWindowsPeerAuthorizationEvidence,
} from './windows-persistent-peer-session.mjs';
import { isWindowsServiceInstallGateReport } from './windows-service-install-gate.mjs';
import { isWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';

/**
 * Phase 9e: wire operational readiness to a branded Phase 9a authorization report.
 *
 * authorization_ready is copied only from evaluateWindowsProductionAuthorization
 * output — never a hardcoded true. Forged/unbranded inputs fail closed.
 * Default/absent host evidence evaluates to authorization_ready=false.
 */

export class WindowsOperationalAuthorizationError extends Error {
  constructor(code = 'invalid_operational_authorization') {
    super(`Windows operational authorization rejected: ${code}`);
    this.name = 'WindowsOperationalAuthorizationError';
    this.code = code;
  }
}

const VALID_WIRED = new WeakSet();

const EVIDENCE_KEYS = new Set([
  'installGateReport',
  'layoutPlan',
  'handleBoundEvidence',
  'targetAclEvidence',
  'peerEvidence',
]);

/**
 * Compose a wired readiness report from branded Phase 5h.46/5h.47/9b/9c/9d evidence.
 * Sets operational_bridge_unwired=false; authorization_ready comes only from 9a.
 *
 * @param {{
 *   installGateReport: object,
 *   layoutPlan: object,
 *   handleBoundEvidence: object,
 *   targetAclEvidence: object,
 *   peerEvidence: object,
 * }} evidence
 */
export function composeWindowsOperationalAuthorization(evidence) {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence) ||
      Object.getPrototypeOf(evidence) !== Object.prototype) {
    throw new WindowsOperationalAuthorizationError('invalid_evidence_bundle');
  }
  const keys = Reflect.ownKeys(evidence);
  if (keys.length !== EVIDENCE_KEYS.size ||
      keys.some((key) => typeof key !== 'string' || !EVIDENCE_KEYS.has(key))) {
    throw new WindowsOperationalAuthorizationError('invalid_evidence_bundle');
  }
  if (!isWindowsServiceInstallGateReport(evidence.installGateReport)) {
    throw new WindowsOperationalAuthorizationError('unbranded_install_gate');
  }
  if (!isWindowsHelperLayoutPlan(evidence.layoutPlan) ||
      evidence.layoutPlan.layout_mode !== 'persistent') {
    throw new WindowsOperationalAuthorizationError('invalid_persistent_layout');
  }
  if (!isWindowsHandleBoundIdentityEvidence(evidence.handleBoundEvidence)) {
    throw new WindowsOperationalAuthorizationError('unbranded_handle_bound_evidence');
  }
  if (!isWindowsTargetAclEvidence(evidence.targetAclEvidence)) {
    throw new WindowsOperationalAuthorizationError('unbranded_target_acl_evidence');
  }
  if (!isWindowsPeerAuthorizationEvidence(evidence.peerEvidence)) {
    throw new WindowsOperationalAuthorizationError('unbranded_peer_evidence');
  }

  // Phase 9a accepts plain Object.prototype peer five-facts; 9d brands with a
  // null-prototype snapshot. Project fields only after brand verification.
  const peerFacts = {
    local_transport: evidence.peerEvidence.local_transport,
    identity_verified: evidence.peerEvidence.identity_verified,
    different_principal: evidence.peerEvidence.different_principal,
    caller_write_denied: evidence.peerEvidence.caller_write_denied,
    helper_write_allowed: evidence.peerEvidence.helper_write_allowed,
  };

  let evaluated;
  try {
    evaluated = evaluateWindowsProductionAuthorization(
      evidence.installGateReport,
      evidence.layoutPlan,
      evidence.handleBoundEvidence,
      evidence.targetAclEvidence,
      peerFacts,
    );
  } catch (error) {
    if (error instanceof WindowsProductionAuthorizationError) {
      throw new WindowsOperationalAuthorizationError(error.code);
    }
    throw error;
  }

  return wireProductionAuthorizationReport(evaluated);
}

/**
 * Default operational path: in-process incomplete branded evidence evaluated by 9a.
 * Typical same-user hosts without a live persistent boundary remain false.
 */
export function absentWindowsOperationalAuthorization() {
  const bundle = buildIncompleteOperationalAuthorizationEvidence();
  return composeWindowsOperationalAuthorization(bundle);
}

/**
 * Synthetic complete branded evidence for unit tests only.
 * Not live host proof; never used by the default operational path.
 */
export function buildCompleteOperationalAuthorizationEvidenceForHarness() {
  const boundary = buildWindowsServiceBoundaryPlan({
    platform: 'win32',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
  });
  const layoutPlan = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'persistent' });
  const lifecycleGate = buildWindowsServiceLifecycleGate(boundary);
  const live = brandWindowsServiceLifecycleLiveReportForHarness(evaluateLiveCollectorResult(lifecycleGate, {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [
      ...lifecycleGate.pre_mutation_steps,
      ...lifecycleGate.mutation_steps,
      ...lifecycleGate.always_cleanup_steps,
    ].map((step) => ({ step, status: 'verified' })),
    provenance: {
      schema_version: 1,
      elevated_token_verified: true,
      local_only_collection: true,
      retained_handle_binding_complete: true,
      path_reacquisition_absent: true,
      value_free_emission_verified: true,
      stderr_absent: true,
      gate_step_surface_matched: true,
      cleanup_finally_bound: true,
      uac_consent_observed: true,
      admin_group_present: true,
      high_integrity_reported: true,
    },
  }));
  const installGateReport = evaluateWindowsServiceInstallGate(lifecycleGate, live, {
    schema_version: 1,
    service_present: false,
    account_local_service: false,
    demand_start: false,
    win32_own_process: false,
    service_sid_unrestricted: false,
    caller_service_control_denied: false,
    binary_binding_verified: false,
    binary_chain_reparse_free: false,
    binary_owner_trusted: false,
    caller_binary_control_denied: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  });

  return Object.freeze({
    installGateReport,
    layoutPlan,
    handleBoundEvidence: brandWindowsHandleBoundIdentityEvidenceForHarness({
      schema_version: 1,
      pipe_local_only: true,
      remote_clients_rejected: true,
      server_pid_handle_bound: true,
      server_token_user_local_service: true,
      server_service_sid_enabled: true,
      scm_service_running_same_pid: true,
      binary_digest_matched_via_handle: true,
      binary_chain_reparse_free: true,
      binary_owner_trusted: true,
      caller_service_control_denied: true,
      service_dacl_caller_change_denied: true,
      path_based_preflight_only: false,
      collector_value_free: true,
    }),
    targetAclEvidence: brandWindowsTargetAclEvidenceForHarness({
      schema_version: 1,
      all_targets_checked: true,
      caller_write_denied: true,
      helper_write_allowed: true,
      ownership_trusted_not_caller: true,
      shared_local_service_token_user_owner_absent: true,
      reparse_points_absent: true,
    }),
    peerEvidence: brandWindowsPeerAuthorizationEvidence({
      local_transport: true,
      identity_verified: true,
      different_principal: true,
      caller_write_denied: true,
      helper_write_allowed: true,
    }),
  });
}

/**
 * Build incomplete branded evidence representing an absent/incomplete persistent boundary.
 * Suitable for harness and the default operational bridge path.
 */
export function buildIncompleteOperationalAuthorizationEvidence() {
  const boundary = buildWindowsServiceBoundaryPlan({
    platform: 'win32',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
  });
  const layoutPlan = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'persistent' });
  const lifecycleGate = buildWindowsServiceLifecycleGate(boundary);
  const live = brandWindowsServiceLifecycleLiveReportForHarness(evaluateLiveCollectorResult(lifecycleGate, {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [
      ...lifecycleGate.pre_mutation_steps,
      ...lifecycleGate.mutation_steps,
      ...lifecycleGate.always_cleanup_steps,
    ].map((step) => ({ step, status: 'verified' })),
    provenance: {
      schema_version: 1,
      elevated_token_verified: true,
      local_only_collection: true,
      retained_handle_binding_complete: true,
      path_reacquisition_absent: true,
      value_free_emission_verified: true,
      stderr_absent: true,
      gate_step_surface_matched: true,
      cleanup_finally_bound: true,
      uac_consent_observed: true,
      admin_group_present: true,
      high_integrity_reported: true,
    },
  }));
  const installGateReport = evaluateWindowsServiceInstallGate(lifecycleGate, live, {
    schema_version: 1,
    service_present: false,
    account_local_service: false,
    demand_start: false,
    win32_own_process: false,
    service_sid_unrestricted: false,
    caller_service_control_denied: false,
    binary_binding_verified: false,
    binary_chain_reparse_free: false,
    binary_owner_trusted: false,
    caller_binary_control_denied: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  });

  const handleBoundEvidence = brandWindowsHandleBoundIdentityEvidenceForHarness({
    schema_version: 1,
    pipe_local_only: false,
    remote_clients_rejected: false,
    server_pid_handle_bound: false,
    server_token_user_local_service: false,
    server_service_sid_enabled: false,
    scm_service_running_same_pid: false,
    binary_digest_matched_via_handle: false,
    binary_chain_reparse_free: false,
    binary_owner_trusted: false,
    caller_service_control_denied: false,
    service_dacl_caller_change_denied: false,
    path_based_preflight_only: false,
    collector_value_free: true,
  });
  const targetAclEvidence = brandWindowsTargetAclEvidenceForHarness({
    schema_version: 1,
    all_targets_checked: false,
    caller_write_denied: false,
    helper_write_allowed: false,
    ownership_trusted_not_caller: false,
    shared_local_service_token_user_owner_absent: false,
    reparse_points_absent: false,
  });
  const peerEvidence = brandWindowsPeerAuthorizationEvidence({
    local_transport: false,
    identity_verified: false,
    different_principal: false,
    caller_write_denied: false,
    helper_write_allowed: false,
  });

  return Object.freeze({
    installGateReport,
    layoutPlan,
    handleBoundEvidence,
    targetAclEvidence,
    peerEvidence,
  });
}

export function isWindowsOperationalAuthorizationReport(value) {
  return value !== null && typeof value === 'object' && VALID_WIRED.has(value);
}

/**
 * @param {object} evaluated branded Phase 9a report
 */
function wireProductionAuthorizationReport(evaluated) {
  if (!isWindowsProductionAuthorizationReport(evaluated)) {
    throw new WindowsOperationalAuthorizationError('unbranded_production_report');
  }
  // Copy authorization_ready from the evaluator result only — never invent true.
  const authorizationReady = evaluated.authorization_ready === true;
  const report = Object.freeze({
    schema_version: 1,
    platform: 'win32',
    install_gate_eligible: evaluated.install_gate_eligible === true,
    persistent_layout_bound: evaluated.persistent_layout_bound === true,
    handle_bound_identity_verified: evaluated.handle_bound_identity_verified === true,
    target_acl_evidence_complete: evaluated.target_acl_evidence_complete === true,
    peer_authorization_complete: evaluated.peer_authorization_complete === true,
    path_based_preflight_insufficient: true,
    helper_vault_free: true,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    mutation_authorized: false,
    install_gate_eligible_alone_insufficient: true,
    persistent_install_alone_insufficient: true,
    disposable_live_alone_insufficient: true,
    operational_bridge_unwired: false,
    authorization_ready: authorizationReady,
    terminal_code: evaluated.terminal_code,
  });
  VALID_WIRED.add(report);
  return report;
}
