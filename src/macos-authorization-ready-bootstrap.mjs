import process from 'node:process';
import { types as utilTypes } from 'node:util';
import {
  composeMacosOperationalAuthorization,
  isMacosOperationalAuthorizationReport,
  buildIncompleteMacosOperationalAuthorizationEvidence,
} from './macos-operational-authorization.mjs';

/**
 * Phase 11l: macOS authorization-ready bootstrap (pure/injected collectors).
 * Live Mac collectors remain a host handoff; never hardcodes ready=true.
 */

export class MacosAuthorizationReadyBootstrapError extends Error {
  constructor(code = 'invalid_authorization_ready_bootstrap') {
    super(`macOS authorization-ready bootstrap rejected: ${code}`);
    this.name = 'MacosAuthorizationReadyBootstrapError';
    this.code = code;
  }
}

export async function runMacosAuthorizationReadyBootstrap(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) ||
      utilTypes.isProxy(options)) {
    throw new MacosAuthorizationReadyBootstrapError('invalid_options');
  }
  const platform = options.platform ?? process.platform;
  if (platform !== 'darwin') {
    throw new MacosAuthorizationReadyBootstrapError('unsupported_platform');
  }
  const collectors = options.collectors;
  if (collectors === null || typeof collectors !== 'object' ||
      typeof collectors.buildInstallGateAndLayout !== 'function' ||
      typeof collectors.collectHandleBound !== 'function' ||
      typeof collectors.collectTargetAcl !== 'function' ||
      typeof collectors.collectPeer !== 'function') {
    throw new MacosAuthorizationReadyBootstrapError('invalid_collectors');
  }
  const compose = options.compose ?? composeMacosOperationalAuthorization;

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
    if (!isMacosOperationalAuthorizationReport(report)) {
      throw new MacosAuthorizationReadyBootstrapError('unbranded_compose_report');
    }
    return Object.freeze({
      schema_version: 1,
      platform: 'darwin',
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
    if (error instanceof MacosAuthorizationReadyBootstrapError) throw error;
    const incomplete = buildIncompleteMacosOperationalAuthorizationEvidence();
    const report = compose(incomplete);
    return Object.freeze({
      schema_version: 1,
      platform: 'darwin',
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
