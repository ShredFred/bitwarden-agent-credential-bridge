import { types as utilTypes } from 'node:util';
import { isLinuxHelperLayoutPlan } from './linux-helper-layout-plan.mjs';
import { isLinuxSystemdInstallGateReport } from './linux-systemd-install-gate.mjs';

/**
 * Phase 12f: pure Linux authorize/apply envelope for vault-free first-install
 * under a disposable layout. Never executes apply; mutation stays unauthorized.
 */

export class LinuxHelperAuthorizeEnvelopeError extends Error {
  constructor(code = 'invalid_authorize_envelope') {
    super(`Linux helper authorize envelope rejected: ${code}`);
    this.name = 'LinuxHelperAuthorizeEnvelopeError';
    this.code = code;
  }
}

const VALID_ENVELOPES = new WeakSet();

/**
 * Bind install-gate eligibility + disposable layout into a non-executable
 * authorize envelope. Persistent layouts are rejected for this first-install
 * envelope; vault/network remain forbidden.
 */
export function buildLinuxHelperAuthorizeEnvelope(installGateReport, layoutPlan) {
  if (!isLinuxSystemdInstallGateReport(installGateReport)) {
    throw new LinuxHelperAuthorizeEnvelopeError('unbranded_install_gate');
  }
  if (!isLinuxHelperLayoutPlan(layoutPlan)) {
    throw new LinuxHelperAuthorizeEnvelopeError('unbranded_layout_plan');
  }
  if (layoutPlan.layout_mode !== 'disposable') {
    throw new LinuxHelperAuthorizeEnvelopeError('persistent_layout_forbidden_for_envelope');
  }
  if (layoutPlan.platform !== 'linux' || installGateReport.platform !== 'linux') {
    throw new LinuxHelperAuthorizeEnvelopeError('platform_mismatch');
  }

  const authorizeEligible = installGateReport.install_gate_eligible === true &&
    installGateReport.authorization_ready === false &&
    installGateReport.vault_access_forbidden === true &&
    layoutPlan.dynamic_user_forbidden === true &&
    layoutPlan.abstract_socket_forbidden === true;

  const envelope = Object.freeze({
    schema_version: 1,
    platform: 'linux',
    layout_mode: 'disposable',
    install_gate_eligible: installGateReport.install_gate_eligible === true,
    authorize_schema_bound: true,
    vault_free_apply_only: true,
    helper_vault_free: true,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    network_access_forbidden: true,
    manifest_executor_absent: true,
    authorize_eligible: authorizeEligible,
    mutation_authorized: false,
    live_apply_executed: false,
    authorization_ready: false,
    terminal_code: authorizeEligible
      ? 'authorize_envelope_ready_unexecuted'
      : 'authorize_envelope_ineligible',
  });
  VALID_ENVELOPES.add(envelope);
  return envelope;
}

export function isLinuxHelperAuthorizeEnvelope(value) {
  return value !== null && typeof value === 'object' && VALID_ENVELOPES.has(value);
}

export function assertLinuxHelperAuthorizeEnvelopePlain(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value)) {
    throw new LinuxHelperAuthorizeEnvelopeError('invalid_envelope');
  }
  if (!isLinuxHelperAuthorizeEnvelope(value)) {
    throw new LinuxHelperAuthorizeEnvelopeError('unbranded_envelope');
  }
  return value;
}
