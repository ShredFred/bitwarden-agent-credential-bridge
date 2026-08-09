import process from 'node:process';
import { types as utilTypes } from 'node:util';
import {
  composeLinuxOperationalAuthorization,
  isLinuxOperationalAuthorizationReport,
  buildIncompleteLinuxOperationalAuthorizationEvidence,
} from './linux-operational-authorization.mjs';

/**
 * Phase 12u: Linux authorization-ready bootstrap (pure/injected collectors).
 * Live Linux collectors remain a host handoff; never hardcodes ready=true.
 */

export class LinuxAuthorizationReadyBootstrapError extends Error {
  constructor(code = 'invalid_authorization_ready_bootstrap') {
    super(`Linux authorization-ready bootstrap rejected: ${code}`);
    this.name = 'LinuxAuthorizationReadyBootstrapError';
    this.code = code;
  }
}

export async function runLinuxAuthorizationReadyBootstrap(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) ||
      utilTypes.isProxy(options)) {
    throw new LinuxAuthorizationReadyBootstrapError('invalid_options');
  }
  const platform = options.platform ?? process.platform;
  if (platform !== 'linux') {
    throw new LinuxAuthorizationReadyBootstrapError('unsupported_platform');
  }
  const collectors = options.collectors;
  if (collectors === null || typeof collectors !== 'object' ||
      typeof collectors.buildInstallGateAndLayout !== 'function' ||
      typeof collectors.collectHandleBound !== 'function' ||
      typeof collectors.collectTargetAcl !== 'function' ||
      typeof collectors.collectPeer !== 'function') {
    throw new LinuxAuthorizationReadyBootstrapError('invalid_collectors');
  }
  const compose = options.compose ?? composeLinuxOperationalAuthorization;

  try {
    const foundation = await collectors.buildInstallGateAndLayout();
    const handleBoundEvidence = await collectors.collectHandleBound();
    const targetAclEvidence = await collectors.collectTargetAcl();
    const peerEvidence = await collectors.collectPeer(targetAclEvidence);
    const evidence = Object.freeze({
      installGateReport: foundation.installGateReport,
      layoutPlan: foundation.layoutPlan,
      handleBoundEvidence,
      targetAclEvidence,
      peerEvidence,
    });
    const report = compose(evidence);
    if (!isLinuxOperationalAuthorizationReport(report)) {
      throw new LinuxAuthorizationReadyBootstrapError('unbranded_compose_report');
    }
    return Object.freeze({
      schema_version: 1,
      platform: 'linux',
      authorization_ready: report.authorization_ready === true,
      terminal_code: report.terminal_code,
      helper_vault_free: true,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
      mutation_authorized: false,
      collector_error: false,
      evidence,
      report,
    });
  } catch (error) {
    if (error instanceof LinuxAuthorizationReadyBootstrapError) throw error;
    const incomplete = buildIncompleteLinuxOperationalAuthorizationEvidence();
    const report = compose(incomplete);
    return Object.freeze({
      schema_version: 1,
      platform: 'linux',
      authorization_ready: false,
      terminal_code: report.terminal_code,
      helper_vault_free: true,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
      mutation_authorized: false,
      collector_error: true,
      evidence: incomplete,
      report,
    });
  }
}
