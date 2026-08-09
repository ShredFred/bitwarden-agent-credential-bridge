import { types as utilTypes } from 'node:util';
import { isMacosLaunchdInstallGateReport } from './macos-launchd-install-gate.mjs';
import { isMacosHelperLayoutPlan } from './macos-helper-layout-plan.mjs';

/**
 * Phase 11e: pure macOS production authorization evidence compiler.
 * authorization_ready=true only for complete branded evidence; never hardcoded.
 */

export class MacosProductionAuthorizationError extends Error {
  constructor(code = 'invalid_production_authorization_input') {
    super(`macOS production authorization rejected: ${code}`);
    this.name = 'MacosProductionAuthorizationError';
    this.code = code;
  }
}

const HANDLE_BOUND_FIELDS = new Set([
  'schema_version',
  'mach_service_bound',
  'launchd_system_domain_verified',
  'helper_pid_generation_bound',
  'helper_euid_matches_static_account',
  'designated_requirement_verified_via_fd',
  'binary_digest_matched_via_fd',
  'parent_chain_symlink_free',
  'binary_owner_trusted_root',
  'caller_write_denied_on_binary',
  'path_based_preflight_only',
  'collector_value_free',
]);

const TARGET_ACL_FIELDS = new Set([
  'schema_version',
  'all_targets_checked',
  'caller_write_denied',
  'helper_write_allowed',
  'ownership_trusted_not_caller',
  'symlink_free',
  'ordinary_user_home_target_absent',
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
const VALID_PEER = new WeakSet();
const VALID_REPORTS = new WeakSet();

export function brandMacosHandleBoundIdentityEvidenceForHarness(raw) {
  const evidence = exactObject(raw, HANDLE_BOUND_FIELDS, 'invalid_handle_bound_evidence');
  if (evidence.schema_version !== 1 ||
      BOOLEAN_HANDLE_BOUND.some((field) => typeof evidence[field] !== 'boolean')) {
    throw new MacosProductionAuthorizationError('invalid_handle_bound_evidence');
  }
  VALID_HANDLE_BOUND.add(evidence);
  return evidence;
}

export function brandMacosTargetAclEvidenceForHarness(raw) {
  const evidence = exactObject(raw, TARGET_ACL_FIELDS, 'invalid_target_acl_evidence');
  if (evidence.schema_version !== 1 ||
      BOOLEAN_TARGET_ACL.some((field) => typeof evidence[field] !== 'boolean')) {
    throw new MacosProductionAuthorizationError('invalid_target_acl_evidence');
  }
  VALID_TARGET_ACL.add(evidence);
  return evidence;
}

export function brandMacosPeerAuthorizationEvidence(raw) {
  const peer = exactObject(raw, PEER_FIELDS, 'invalid_peer_evidence');
  for (const field of PEER_FIELDS) {
    if (typeof peer[field] !== 'boolean') {
      throw new MacosProductionAuthorizationError('invalid_peer_evidence');
    }
  }
  VALID_PEER.add(peer);
  return peer;
}

export function isMacosHandleBoundIdentityEvidence(value) {
  return value !== null && typeof value === 'object' && VALID_HANDLE_BOUND.has(value);
}

export function isMacosTargetAclEvidence(value) {
  return value !== null && typeof value === 'object' && VALID_TARGET_ACL.has(value);
}

export function isMacosPeerAuthorizationEvidence(value) {
  return value !== null && typeof value === 'object' && VALID_PEER.has(value);
}

export function evaluateMacosProductionAuthorization(
  installGateReport,
  layoutPlan,
  handleBoundEvidence,
  targetAclEvidence,
  peerEvidence,
) {
  if (!isMacosLaunchdInstallGateReport(installGateReport)) {
    throw new MacosProductionAuthorizationError('unbranded_install_gate');
  }
  if (!isMacosHelperLayoutPlan(layoutPlan) || layoutPlan.layout_mode !== 'persistent') {
    throw new MacosProductionAuthorizationError('invalid_persistent_layout');
  }
  if (!isMacosHandleBoundIdentityEvidence(handleBoundEvidence)) {
    throw new MacosProductionAuthorizationError('unbranded_handle_bound_evidence');
  }
  if (!isMacosTargetAclEvidence(targetAclEvidence)) {
    throw new MacosProductionAuthorizationError('unbranded_target_acl_evidence');
  }

  const peer = exactObject(peerEvidence, PEER_FIELDS, 'invalid_peer_evidence');
  for (const field of PEER_FIELDS) {
    if (typeof peer[field] !== 'boolean') {
      throw new MacosProductionAuthorizationError('invalid_peer_evidence');
    }
  }

  if (handleBoundEvidence.path_based_preflight_only === true) {
    throw new MacosProductionAuthorizationError('path_based_preflight_insufficient');
  }

  const installEligible = installGateReport.install_gate_eligible === true &&
    installGateReport.authorization_ready === false &&
    installGateReport.mutation_authorized === false &&
    installGateReport.vault_access_forbidden === true &&
    installGateReport.keychain_access_forbidden === true;

  const layoutReady = layoutPlan.privileged_helper_tools_class_root_required === true &&
    layoutPlan.launch_daemons_class_root_required === true &&
    layoutPlan.application_support_root_forbidden === true &&
    layoutPlan.home_profile_root_forbidden === true &&
    layoutPlan.launch_agent_forbidden === true &&
    layoutPlan.distinct_euid_ownership_required === true &&
    layoutPlan.authorization_ready === false;

  const identityReady = handleBoundEvidence.mach_service_bound === true &&
    handleBoundEvidence.launchd_system_domain_verified === true &&
    handleBoundEvidence.helper_pid_generation_bound === true &&
    handleBoundEvidence.helper_euid_matches_static_account === true &&
    handleBoundEvidence.designated_requirement_verified_via_fd === true &&
    handleBoundEvidence.binary_digest_matched_via_fd === true &&
    handleBoundEvidence.parent_chain_symlink_free === true &&
    handleBoundEvidence.binary_owner_trusted_root === true &&
    handleBoundEvidence.caller_write_denied_on_binary === true &&
    handleBoundEvidence.path_based_preflight_only === false &&
    handleBoundEvidence.collector_value_free === true;

  const aclReady = targetAclEvidence.all_targets_checked === true &&
    targetAclEvidence.caller_write_denied === true &&
    targetAclEvidence.helper_write_allowed === true &&
    targetAclEvidence.ownership_trusted_not_caller === true &&
    targetAclEvidence.symlink_free === true &&
    targetAclEvidence.ordinary_user_home_target_absent === true;

  const peerReady = peer.local_transport === true &&
    peer.identity_verified === true &&
    peer.different_principal === true &&
    peer.caller_write_denied === true &&
    peer.helper_write_allowed === true;

  const ready = installEligible && layoutReady && identityReady && aclReady && peerReady;

  const report = Object.freeze({
    schema_version: 1,
    platform: 'darwin',
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

export function isMacosProductionAuthorizationReport(value) {
  return value !== null && typeof value === 'object' && VALID_REPORTS.has(value);
}

function exactObject(value, fields, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new MacosProductionAuthorizationError(code);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new MacosProductionAuthorizationError(code);
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new MacosProductionAuthorizationError(code);
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
