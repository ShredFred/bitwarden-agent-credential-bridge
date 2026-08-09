import { buildLinuxSystemdBoundaryPlan } from './linux-systemd-boundary-plan.mjs';
import { buildLinuxSystemdLifecycleGate } from './linux-systemd-lifecycle-gate.mjs';
import { buildLinuxHelperLayoutPlan } from './linux-helper-layout-plan.mjs';
import {
  evaluateLinuxSystemdLifecycleCollectorTrust,
} from './linux-systemd-lifecycle-collector-trust.mjs';
import {
  brandLinuxSystemdLifecycleLiveReportForHarness,
  evaluateLinuxSystemdInstallGate,
  isLinuxSystemdInstallGateReport,
} from './linux-systemd-install-gate.mjs';
import { isLinuxHelperLayoutPlan } from './linux-helper-layout-plan.mjs';
import {
  brandLinuxHandleBoundIdentityEvidenceForHarness,
  brandLinuxPeerAuthorizationEvidence,
  brandLinuxTargetAclEvidenceForHarness,
  evaluateLinuxProductionAuthorization,
  isLinuxHandleBoundIdentityEvidence,
  isLinuxPeerAuthorizationEvidence,
  isLinuxProductionAuthorizationReport,
  isLinuxTargetAclEvidence,
  LinuxProductionAuthorizationError,
} from './linux-production-authorization.mjs';

/**
 * Phase 12t: wire operational readiness to branded Linux Phase 12p reports.
 * authorization_ready is copied only from evaluateLinuxProductionAuthorization.
 */

export class LinuxOperationalAuthorizationError extends Error {
  constructor(code = 'invalid_operational_authorization') {
    super(`Linux operational authorization rejected: ${code}`);
    this.name = 'LinuxOperationalAuthorizationError';
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

export function composeLinuxOperationalAuthorization(evidence) {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence) ||
      Object.getPrototypeOf(evidence) !== Object.prototype) {
    throw new LinuxOperationalAuthorizationError('invalid_evidence_bundle');
  }
  const keys = Reflect.ownKeys(evidence);
  if (keys.length !== EVIDENCE_KEYS.size ||
      keys.some((key) => typeof key !== 'string' || !EVIDENCE_KEYS.has(key))) {
    throw new LinuxOperationalAuthorizationError('invalid_evidence_bundle');
  }
  if (!isLinuxSystemdInstallGateReport(evidence.installGateReport)) {
    throw new LinuxOperationalAuthorizationError('unbranded_install_gate');
  }
  if (!isLinuxHelperLayoutPlan(evidence.layoutPlan) ||
      evidence.layoutPlan.layout_mode !== 'persistent') {
    throw new LinuxOperationalAuthorizationError('invalid_persistent_layout');
  }
  if (!isLinuxHandleBoundIdentityEvidence(evidence.handleBoundEvidence)) {
    throw new LinuxOperationalAuthorizationError('unbranded_handle_bound_evidence');
  }
  if (!isLinuxTargetAclEvidence(evidence.targetAclEvidence)) {
    throw new LinuxOperationalAuthorizationError('unbranded_target_acl_evidence');
  }
  if (!isLinuxPeerAuthorizationEvidence(evidence.peerEvidence)) {
    throw new LinuxOperationalAuthorizationError('unbranded_peer_evidence');
  }

  const peerFacts = {
    local_transport: evidence.peerEvidence.local_transport,
    identity_verified: evidence.peerEvidence.identity_verified,
    different_principal: evidence.peerEvidence.different_principal,
    caller_write_denied: evidence.peerEvidence.caller_write_denied,
    helper_write_allowed: evidence.peerEvidence.helper_write_allowed,
  };

  let evaluated;
  try {
    evaluated = evaluateLinuxProductionAuthorization(
      evidence.installGateReport,
      evidence.layoutPlan,
      evidence.handleBoundEvidence,
      evidence.targetAclEvidence,
      peerFacts,
    );
  } catch (error) {
    if (error instanceof LinuxProductionAuthorizationError) {
      throw new LinuxOperationalAuthorizationError(error.code);
    }
    throw error;
  }

  return wireReport(evaluated);
}

export function absentLinuxOperationalAuthorization() {
  return composeLinuxOperationalAuthorization(buildIncompleteLinuxOperationalAuthorizationEvidence());
}

export function buildCompleteLinuxOperationalAuthorizationEvidenceForHarness() {
  const { installGateReport, layoutPlan } = buildEligibleInstallAndLayout();
  return Object.freeze({
    installGateReport,
    layoutPlan,
    handleBoundEvidence: brandLinuxHandleBoundIdentityEvidenceForHarness({
      schema_version: 1,
      af_unix_filesystem_only: true,
      peercred_bound: true,
      unit_pid_bound: true,
      helper_host_uid_matches_static_account: true,
      helper_initial_userns: true,
      binary_digest_matched_via_fd: true,
      parent_chain_symlink_free: true,
      binary_owner_trusted_root: true,
      caller_write_denied_on_binary: true,
      path_based_preflight_only: false,
      collector_value_free: true,
    }),
    targetAclEvidence: brandLinuxTargetAclEvidenceForHarness({
      schema_version: 1,
      all_targets_checked: true,
      caller_write_denied: true,
      helper_write_allowed: true,
      ownership_trusted_not_caller: true,
      checked_in_helper_mount_ns: true,
      ordinary_user_home_target_absent: true,
    }),
    peerEvidence: brandLinuxPeerAuthorizationEvidence({
      local_transport: true,
      identity_verified: true,
      different_principal: true,
      caller_write_denied: true,
      helper_write_allowed: true,
    }),
  });
}

export function buildIncompleteLinuxOperationalAuthorizationEvidence() {
  const { installGateReport, layoutPlan } = buildEligibleInstallAndLayout();
  return Object.freeze({
    installGateReport,
    layoutPlan,
    handleBoundEvidence: brandLinuxHandleBoundIdentityEvidenceForHarness({
      schema_version: 1,
      af_unix_filesystem_only: false,
      peercred_bound: false,
      unit_pid_bound: false,
      helper_host_uid_matches_static_account: false,
      helper_initial_userns: false,
      binary_digest_matched_via_fd: false,
      parent_chain_symlink_free: false,
      binary_owner_trusted_root: false,
      caller_write_denied_on_binary: false,
      path_based_preflight_only: false,
      collector_value_free: true,
    }),
    targetAclEvidence: brandLinuxTargetAclEvidenceForHarness({
      schema_version: 1,
      all_targets_checked: false,
      caller_write_denied: false,
      helper_write_allowed: false,
      ownership_trusted_not_caller: false,
      checked_in_helper_mount_ns: false,
      ordinary_user_home_target_absent: false,
    }),
    peerEvidence: brandLinuxPeerAuthorizationEvidence({
      local_transport: false,
      identity_verified: false,
      different_principal: false,
      caller_write_denied: false,
      helper_write_allowed: false,
    }),
  });
}

export function isLinuxOperationalAuthorizationReport(value) {
  return value !== null && typeof value === 'object' && VALID_WIRED.has(value);
}

function buildEligibleInstallAndLayout() {
  const boundary = buildLinuxSystemdBoundaryPlan({
    platform: 'linux',
    serviceManager: 'systemd-system',
    binarySha256: 'd'.repeat(64),
    binaryByteLength: 8192,
  });
  const layoutPlan = buildLinuxHelperLayoutPlan(boundary, { layout_mode: 'persistent' });
  const lifecycleGate = buildLinuxSystemdLifecycleGate(boundary);
  const trust = evaluateLinuxSystemdLifecycleCollectorTrust(lifecycleGate, {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [
      ...lifecycleGate.pre_mutation_steps,
      ...lifecycleGate.mutation_steps,
      ...lifecycleGate.always_cleanup_steps,
    ].map((step) => ({ step, status: 'verified' })),
  }, {
    schema_version: 1,
    elevated_token_verified: true,
    local_only_collection: true,
    retained_handle_binding_complete: true,
    path_reacquisition_absent: true,
    value_free_emission_verified: true,
    stderr_absent: true,
    gate_step_surface_matched: true,
    cleanup_finally_bound: true,
    root_euid_reported: true,
    systemd_system_manager_reported: true,
    initial_user_namespace_reported: true,
  });
  const live = brandLinuxSystemdLifecycleLiveReportForHarness({
    schema_version: 1,
    preflight_claim_structurally_complete: trust.preflight_claim_structurally_complete,
    mutation_claim_structurally_complete: trust.mutation_claim_structurally_complete,
    denial_claim_structurally_complete: trust.denial_claim_structurally_complete,
    cleanup_claim_structurally_complete: trust.cleanup_claim_structurally_complete,
    final_absence_claim_structurally_complete: trust.final_absence_claim_structurally_complete,
    transcript_structure_complete: trust.transcript_structure_complete,
    required_provenance_complete: trust.required_provenance_complete,
    collector_trust_verified: trust.collector_trust_verified,
    live_test_executed: true,
    live_test_verified: true,
    mutation_authorized: false,
    install_gate_eligible: false,
    authorization_ready: false,
    terminal_code: 'live_denial_verified_cleaned',
  });
  const installGateReport = evaluateLinuxSystemdInstallGate(lifecycleGate, live, {
    schema_version: 1,
    account_present: false,
    service_unit_present: false,
    socket_unit_present: false,
    binary_present: false,
    socket_path_present: false,
    binary_binding_verified: false,
    unit_fragments_match_plan: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  });
  return { installGateReport, layoutPlan };
}

function wireReport(evaluated) {
  if (!isLinuxProductionAuthorizationReport(evaluated)) {
    throw new LinuxOperationalAuthorizationError('unbranded_production_report');
  }
  const authorizationReady = evaluated.authorization_ready === true;
  const report = Object.freeze({
    schema_version: 1,
    platform: 'linux',
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
