import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { types as utilTypes } from 'node:util';
import {
  composeWindowsOperationalAuthorization,
  isWindowsOperationalAuthorizationReport,
} from './windows-operational-authorization.mjs';
import { refreshWindowsAuthorizationEvidenceOnce } from './windows-authorization-evidence-refresh.mjs';
import { createLiveWindowsAuthorizationEvidenceCollectors } from './windows-authorization-evidence-live-collectors.mjs';
import { publishWindowsHelperServiceBinary } from './windows-helper-publish.mjs';
import { requireWindowsHelperPublishBinding } from './windows-helper-package-binding.mjs';

/**
 * Phase 10b: operator bootstrap to authorization_ready from branded live evidence.
 *
 * Never hardcodes authorization_ready=true. Optional vault-free first-install
 * apply runs only when initial target-ACL evidence is incomplete. Personal/
 * company Bitwarden remains forbidden; helper stays vault-free.
 */

export class WindowsAuthorizationReadyBootstrapError extends Error {
  constructor(code = 'invalid_authorization_ready_bootstrap') {
    super(`Windows authorization-ready bootstrap rejected: ${code}`);
    this.name = 'WindowsAuthorizationReadyBootstrapError';
    this.code = code;
  }
}

const HELPER_EXE = 'BitwardenAgentCredentialBridgeHelper.exe';

/**
 * @param {{
 *   platform?: string,
 *   collectors?: object,
 *   compose?: Function,
 *   applyFirstInstall?: () => Promise<{ applied: boolean, paths_created?: number }>,
 *   skipApply?: boolean,
 * }} [options]
 */
export async function runWindowsAuthorizationReadyBootstrap(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) ||
      utilTypes.isProxy(options)) {
    throw new WindowsAuthorizationReadyBootstrapError('invalid_options');
  }

  const platform = options.platform ?? process.platform;
  if (platform !== 'win32') {
    throw new WindowsAuthorizationReadyBootstrapError('unsupported_platform');
  }

  let collectors = options.collectors;
  let disposeCollectors = async () => {};
  if (collectors === undefined) {
    collectors = createLiveWindowsAuthorizationEvidenceCollectors();
    disposeCollectors = async () => {
      if (typeof collectors.dispose === 'function') await collectors.dispose();
    };
  }

  const compose = options.compose ?? composeWindowsOperationalAuthorization;
  const skipApply = options.skipApply === true;
  const applyFirstInstall = options.applyFirstInstall ?? defaultVaultFreeFirstInstallApply;
  if (typeof applyFirstInstall !== 'function') {
    throw new WindowsAuthorizationReadyBootstrapError('invalid_apply');
  }

  try {
    let cycle = await refreshWindowsAuthorizationEvidenceOnce(collectors, compose);
    let applyAttempted = false;
    let applyResult = null;

    // Apply once when compose says target ACL is incomplete. Do not apply when
    // already ready, when ACL evidence is complete (other gates failing), or when
    // the first cycle failed closed via collector_error (service likely absent).
    const shouldApply = !skipApply &&
      cycle.report.authorization_ready !== true &&
      cycle.report.target_acl_evidence_complete !== true &&
      cycle.collector_error !== true;

    if (shouldApply) {
      applyAttempted = true;
      applyResult = await applyFirstInstall();
      cycle = await refreshWindowsAuthorizationEvidenceOnce(collectors, compose);
    }

    if (!isWindowsOperationalAuthorizationReport(cycle.report)) {
      throw new WindowsAuthorizationReadyBootstrapError('unbranded_compose_report');
    }

    return Object.freeze({
      schema_version: 1,
      platform: 'win32',
      authorization_ready: cycle.report.authorization_ready === true,
      terminal_code: cycle.report.terminal_code,
      evidence_complete: cycle.report.authorization_ready === true,
      helper_vault_free: cycle.report.helper_vault_free === true,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
      mutation_authorized: false,
      operational_bridge_unwired: cycle.report.operational_bridge_unwired === true,
      apply_attempted: applyAttempted,
      apply_succeeded: applyResult?.applied === true,
      collector_error: cycle.collector_error === true,
      evidence: cycle.evidence,
      report: cycle.report,
    });
  } finally {
    await disposeCollectors();
  }
}

/**
 * Vault-free LocalService first-install apply via native pipe client.
 * Creates the five ProgramData targets when absent.
 */
export async function defaultVaultFreeFirstInstallApply() {
  if (process.platform !== 'win32') {
    throw new WindowsAuthorizationReadyBootstrapError('unsupported_platform');
  }
  const published = requireWindowsHelperPublishBinding(
    await publishWindowsHelperServiceBinary(),
  );
  const staging = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-ready-apply-'));
  const helperPath = path.join(staging, HELPER_EXE);
  const launcherPath = path.join(staging, 'launcher.bin');
  try {
    await fs.writeFile(helperPath, published.bytes, { flag: 'wx' });
    // Non-secret launcher bytes for digest/length binding only.
    const launcherBytes = Buffer.from(
      `bw-launcher-v1\n${published.sha256}\n${published.byteLength}\n`,
      'utf8',
    );
    await fs.writeFile(launcherPath, launcherBytes, { flag: 'wx' });
    const nonce = randomBytes(32).toString('hex');
    const result = await execCapture(helperPath, [
      '--self-test-pipe-client', 'service-apply', nonce, launcherPath,
    ], 120000, 8192);
    const stdout = result.stdout || '';
    const applied = result.code === 0 &&
      stdout.includes('"applied":true') &&
      stdout.includes('"helper_vault_free":true');
    return Object.freeze({
      applied,
      paths_created: applied ? 5 : 0,
      exit_code: result.code,
    });
  } finally {
    await fs.rm(staging, { recursive: true, force: true }).catch(() => {});
  }
}

function execCapture(executable, args, timeoutMs, maxBuffer) {
  return new Promise((resolve) => {
    execFile(executable, args, {
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer,
      encoding: 'utf8',
      env: {
        SystemRoot: process.env.SystemRoot,
        WINDIR: process.env.WINDIR || process.env.SystemRoot,
        TEMP: os.tmpdir(),
        TMP: os.tmpdir(),
        PATH: process.env.PATH,
      },
    }, (error, stdout, stderr) => {
      resolve({
        code: error && typeof error.code === 'number' ? error.code : (error ? 1 : 0),
        stdout: stdout || '',
        stderr: stderr || '',
      });
    });
  });
}
