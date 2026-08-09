import { buildMacosLaunchdBoundaryPlan } from './macos-launchd-boundary-plan.mjs';
import { buildMacosLaunchdLifecycleGate } from './macos-launchd-lifecycle-gate.mjs';
import { buildMacosHelperLayoutPlan } from './macos-helper-layout-plan.mjs';
import {
  evaluateMacosLaunchdLifecycleCollectorTrust,
} from './macos-launchd-lifecycle-collector-trust.mjs';
import {
  brandMacosLaunchdLifecycleLiveReportForHarness,
  evaluateMacosLaunchdInstallGate,
  isMacosLaunchdInstallGateReport,
} from './macos-launchd-install-gate.mjs';
import { isMacosHelperLayoutPlan } from './macos-helper-layout-plan.mjs';
import {
  brandMacosHandleBoundIdentityEvidenceForHarness,
  brandMacosPeerAuthorizationEvidence,
  brandMacosTargetAclEvidenceForHarness,
  evaluateMacosProductionAuthorization,
  isMacosHandleBoundIdentityEvidence,
  isMacosPeerAuthorizationEvidence,
  isMacosProductionAuthorizationReport,
  isMacosTargetAclEvidence,
  MacosProductionAuthorizationError,
} from './macos-production-authorization.mjs';

/**
 * Phase 11j: wire operational readiness to branded macOS Phase 11e reports.
 * authorization_ready is copied only from evaluateMacosProductionAuthorization.
 */

export class MacosOperationalAuthorizationError extends Error {
  constructor(code = 'invalid_operational_authorization') {
    super(`macOS operational authorization rejected: ${code}`);
    this.name = 'MacosOperationalAuthorizationError';
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

export function composeMacosOperationalAuthorization(evidence) {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence) ||
      Object.getPrototypeOf(evidence) !== Object.prototype) {
    throw new MacosOperationalAuthorizationError('invalid_evidence_bundle');
  }
  const keys = Reflect.ownKeys(evidence);
  if (keys.length !== EVIDENCE_KEYS.size ||
      keys.some((key) => typeof key !== 'string' || !EVIDENCE_KEYS.has(key))) {
    throw new MacosOperationalAuthorizationError('invalid_evidence_bundle');
  }
  if (!isMacosLaunchdInstallGateReport(evidence.installGateReport)) {
    throw new MacosOperationalAuthorizationError('unbranded_install_gate');
  }
  if (!isMacosHelperLayoutPlan(evidence.layoutPlan) ||
      evidence.layoutPlan.layout_mode !== 'persistent') {
    throw new MacosOperationalAuthorizationError('invalid_persistent_layout');
  }
  if (!isMacosHandleBoundIdentityEvidence(evidence.handleBoundEvidence)) {
    throw new MacosOperationalAuthorizationError('unbranded_handle_bound_evidence');
  }
  if (!isMacosTargetAclEvidence(evidence.targetAclEvidence)) {
    throw new MacosOperationalAuthorizationError('unbranded_target_acl_evidence');
  }
  if (!isMacosPeerAuthorizationEvidence(evidence.peerEvidence)) {
    throw new MacosOperationalAuthorizationError('unbranded_peer_evidence');
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
    evaluated = evaluateMacosProductionAuthorization(
      evidence.installGateReport,
      evidence.layoutPlan,
      evidence.handleBoundEvidence,
      evidence.targetAclEvidence,
      peerFacts,
    );
  } catch (error) {
    if (error instanceof MacosProductionAuthorizationError) {
      throw new MacosOperationalAuthorizationError(error.code);
    }
    throw error;
  }

  return wireReport(evaluated);
}

export function absentMacosOperationalAuthorization() {
  return composeMacosOperationalAuthorization(buildIncompleteMacosOperationalAuthorizationEvidence());
}

export function buildCompleteMacosOperationalAuthorizationEvidenceForHarness() {
  const { installGateReport, layoutPlan } = buildEligibleInstallAndLayout();
  return Object.freeze({
    installGateReport,
    layoutPlan,
    handleBoundEvidence: brandMacosHandleBoundIdentityEvidenceForHarness({
      schema_version: 1,
      mach_service_bound: true,
      launchd_system_domain_verified: true,
      helper_pid_generation_bound: true,
      helper_euid_matches_static_account: true,
      designated_requirement_verified_via_fd: true,
      binary_digest_matched_via_fd: true,
      parent_chain_symlink_free: true,
      binary_owner_trusted_root: true,
      caller_write_denied_on_binary: true,
      path_based_preflight_only: false,
      collector_value_free: true,
    }),
    targetAclEvidence: brandMacosTargetAclEvidenceForHarness({
      schema_version: 1,
      all_targets_checked: true,
      caller_write_denied: true,
      helper_write_allowed: true,
      ownership_trusted_not_caller: true,
      symlink_free: true,
      ordinary_user_home_target_absent: true,
    }),
    peerEvidence: brandMacosPeerAuthorizationEvidence({
      local_transport: true,
      identity_verified: true,
      different_principal: true,
      caller_write_denied: true,
      helper_write_allowed: true,
    }),
  });
}

export function buildIncompleteMacosOperationalAuthorizationEvidence() {
  const { installGateReport, layoutPlan } = buildEligibleInstallAndLayout();
  return Object.freeze({
    installGateReport,
    layoutPlan,
    handleBoundEvidence: brandMacosHandleBoundIdentityEvidenceForHarness({
      schema_version: 1,
      mach_service_bound: false,
      launchd_system_domain_verified: false,
      helper_pid_generation_bound: false,
      helper_euid_matches_static_account: false,
      designated_requirement_verified_via_fd: false,
      binary_digest_matched_via_fd: false,
      parent_chain_symlink_free: false,
      binary_owner_trusted_root: false,
      caller_write_denied_on_binary: false,
      path_based_preflight_only: false,
      collector_value_free: true,
    }),
    targetAclEvidence: brandMacosTargetAclEvidenceForHarness({
      schema_version: 1,
      all_targets_checked: false,
      caller_write_denied: false,
      helper_write_allowed: false,
      ownership_trusted_not_caller: false,
      symlink_free: false,
      ordinary_user_home_target_absent: false,
    }),
    peerEvidence: brandMacosPeerAuthorizationEvidence({
      local_transport: false,
      identity_verified: false,
      different_principal: false,
      caller_write_denied: false,
      helper_write_allowed: false,
    }),
  });
}

export function isMacosOperationalAuthorizationReport(value) {
  return value !== null && typeof value === 'object' && VALID_WIRED.has(value);
}

function buildEligibleInstallAndLayout() {
  const boundary = buildMacosLaunchdBoundaryPlan({
    platform: 'darwin',
    serviceManager: 'launchd-system',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
    designatedRequirementSha256: 'b'.repeat(64),
    plistSha256: 'c'.repeat(64),
  });
  const layoutPlan = buildMacosHelperLayoutPlan(boundary, { layout_mode: 'persistent' });
  const lifecycleGate = buildMacosLaunchdLifecycleGate(boundary);
  const trust = evaluateMacosLaunchdLifecycleCollectorTrust(lifecycleGate, {
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
    sudo_consent_observed: true,
    root_euid_reported: true,
    system_domain_reported: true,
  });
  const live = brandMacosLaunchdLifecycleLiveReportForHarness({
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
  const installGateReport = evaluateMacosLaunchdInstallGate(lifecycleGate, live, {
    schema_version: 1,
    account_present: false,
    plist_present: false,
    binary_present: false,
    label_loaded: false,
    mach_service_bound: false,
    binary_binding_verified: false,
    designated_requirement_verified: false,
    parent_chain_policy_matched: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  });
  return { installGateReport, layoutPlan };
}

function wireReport(evaluated) {
  if (!isMacosProductionAuthorizationReport(evaluated)) {
    throw new MacosOperationalAuthorizationError('unbranded_production_report');
  }
  const authorizationReady = evaluated.authorization_ready === true;
  const report = Object.freeze({
    schema_version: 1,
    platform: 'darwin',
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
