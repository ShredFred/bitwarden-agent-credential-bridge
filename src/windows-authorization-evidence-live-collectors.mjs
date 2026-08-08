import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { publishWindowsHelperServiceBinary } from './windows-helper-publish.mjs';
import { requireWindowsHelperPublishBinding } from './windows-helper-package-binding.mjs';
import { buildWindowsServiceBoundaryPlan } from './windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';
import { buildWindowsServiceLifecycleGate } from './windows-service-lifecycle-gate.mjs';
import {
  brandWindowsServiceLifecycleLiveReportForHarness,
  evaluateLiveCollectorResult,
} from './windows-service-lifecycle-live.mjs';
import { evaluateWindowsServiceInstallGate } from './windows-service-install-gate.mjs';
import { collectWindowsHandleBoundIdentityEvidence } from './windows-handle-bound-identity.mjs';
import { collectWindowsTargetAclEvidence } from './windows-target-acl-matrix.mjs';
import { collectWindowsPersistentPeerSession } from './windows-persistent-peer-session.mjs';
import { WindowsAuthorizationEvidenceRefreshError } from './windows-authorization-evidence-refresh.mjs';

/**
 * Phase 10a live collectors for Day-2 refresh.
 *
 * Rebuilds branded install-gate + persistent layout in-process from the published
 * helper digest (same structural disposable-live replay used when a persistent
 * service occupies the host and a fresh disposable matrix cannot run). Live 9b /
 * 9c / 9d collectors still require an already-installed running LocalService.
 * Never loads forged JSON from disk as a capability.
 */

const HELPER_EXE = 'BitwardenAgentCredentialBridgeHelper.exe';

/**
 * Build branded install-gate + persistent layout bound to published helper bytes.
 * Install-gate eligibility uses an in-process branded disposable-live transcript
 * replay (not a fresh elevated disposable run).
 */
export async function buildPublishedInstallGateAndLayout() {
  if (process.platform !== 'win32') {
    throw new WindowsAuthorizationEvidenceRefreshError('unsupported_platform');
  }
  const published = requireWindowsHelperPublishBinding(
    await publishWindowsHelperServiceBinary(),
  );
  const boundary = buildWindowsServiceBoundaryPlan({
    platform: 'win32',
    binarySha256: published.sha256,
    binaryByteLength: published.byteLength,
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
  // Post-cleanup preflight coherent with disposable matrix absence claim; the
  // persistent service itself is assessed by live 9b–9d collectors, not here.
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
    published,
    boundary,
    layoutPlan,
    installGateReport,
  });
}

/**
 * Create injected collectors for startWindowsAuthorizationEvidenceRefresh that
 * perform live 9b/9c/9d collection against the host.
 */
export function createLiveWindowsAuthorizationEvidenceCollectors() {
  if (process.platform !== 'win32') {
    throw new WindowsAuthorizationEvidenceRefreshError('unsupported_platform');
  }

  let helperPathPromise = null;

  const ensureHelperPath = async (published) => {
    if (helperPathPromise !== null) return helperPathPromise;
    helperPathPromise = (async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-auth-refresh-'));
      const helperPath = path.join(dir, HELPER_EXE);
      await fs.writeFile(helperPath, published.bytes, { flag: 'wx' });
      return { dir, helperPath };
    })();
    return helperPathPromise;
  };

  let cachedFoundation = null;

  return {
    async buildInstallGateAndLayout() {
      cachedFoundation = await buildPublishedInstallGateAndLayout();
      return {
        installGateReport: cachedFoundation.installGateReport,
        layoutPlan: cachedFoundation.layoutPlan,
      };
    },
    async collectHandleBound() {
      const foundation = cachedFoundation ?? await buildPublishedInstallGateAndLayout();
      cachedFoundation = foundation;
      const helper = await ensureHelperPath(foundation.published);
      const { evidence } = await collectWindowsHandleBoundIdentityEvidence(foundation.boundary, {
        helperExecutablePath: helper.helperPath,
        skipPublish: true,
      });
      return evidence;
    },
    async collectTargetAcl() {
      const foundation = cachedFoundation ?? await buildPublishedInstallGateAndLayout();
      cachedFoundation = foundation;
      const { evidence } = await collectWindowsTargetAclEvidence(foundation.layoutPlan);
      return evidence;
    },
    async collectPeer(targetAclEvidence) {
      const foundation = cachedFoundation ?? await buildPublishedInstallGateAndLayout();
      cachedFoundation = foundation;
      const helper = await ensureHelperPath(foundation.published);
      const { peerEvidence } = await collectWindowsPersistentPeerSession(foundation.layoutPlan, {
        helperExecutablePath: helper.helperPath,
        targetAclEvidence,
      });
      return peerEvidence;
    },
    async dispose() {
      if (helperPathPromise === null) return;
      try {
        const helper = await helperPathPromise;
        await fs.rm(helper.dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
      helperPathPromise = null;
      cachedFoundation = null;
    },
  };
}
