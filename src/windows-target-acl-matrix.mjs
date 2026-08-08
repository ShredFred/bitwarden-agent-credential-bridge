import { execFile } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';
import { isWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';
import { brandWindowsTargetAclEvidenceForHarness } from './windows-production-authorization.mjs';

/**
 * Phase 9c: collect a complete AccessCheck matrix over the five persistent
 * ProgramData-class helper targets (config dir/file, install root, bin dir,
 * launcher). Brands the exact Phase 9a target-ACL evidence schema.
 *
 * Read-only: no elevation, install, ACL mutation, manifest execution, or
 * Bitwarden access. authorization_ready stays false; operational wire-up is 9e.
 */

const PROBE_SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'windows-target-acl-matrix-probe.ps1',
);

const PROBE_FIELDS = new Set([
  'schema_version',
  'persistent_root_present',
  'service_running',
  'helper_token_bound',
  'all_targets_checked',
  'caller_write_denied',
  'helper_write_allowed',
  'ownership_trusted_not_caller',
  'shared_local_service_token_user_owner_absent',
  'reparse_points_absent',
  'authorization_ready',
]);

const BOOLEAN_PROBE = [...PROBE_FIELDS].filter((field) => field !== 'schema_version');

export class WindowsTargetAclMatrixError extends Error {
  constructor(code = 'invalid_target_acl_matrix') {
    super(`Windows target ACL matrix rejected: ${code}`);
    this.name = 'WindowsTargetAclMatrixError';
    this.code = code;
  }
}

const VALID_REPORTS = new WeakSet();

/** Brand collector evidence for production authorization (same WeakSet as harness). */
export function brandWindowsTargetAclEvidence(raw) {
  return brandWindowsTargetAclEvidenceForHarness(raw);
}

export function parseWindowsTargetAclMatrixProbeResult(stdout, stderr = '') {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr.trim() !== '') {
    throw new WindowsTargetAclMatrixError('invalid_probe_output');
  }
  let value;
  try {
    const normalized = stdout.startsWith('\uFEFF') ? stdout.slice(1) : stdout;
    value = JSON.parse(normalized.trim());
  } catch {
    throw new WindowsTargetAclMatrixError('invalid_probe_output');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsTargetAclMatrixError('invalid_probe_output');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== PROBE_FIELDS.size ||
      keys.some((key) => typeof key !== 'string' || !PROBE_FIELDS.has(key)) ||
      value.schema_version !== 1 ||
      BOOLEAN_PROBE.some((field) => typeof value[field] !== 'boolean')) {
    throw new WindowsTargetAclMatrixError('invalid_probe_output');
  }
  if (value.authorization_ready !== false) {
    throw new WindowsTargetAclMatrixError('probe_authorization_claim');
  }
  // Completing the matrix requires a live helper token and all five checks.
  if (value.all_targets_checked === true &&
      (value.service_running !== true || value.helper_token_bound !== true ||
        value.persistent_root_present !== true)) {
    throw new WindowsTargetAclMatrixError('incoherent_complete_matrix');
  }
  if (value.all_targets_checked !== true && (
    value.caller_write_denied === true ||
    value.helper_write_allowed === true ||
    value.ownership_trusted_not_caller === true ||
    value.shared_local_service_token_user_owner_absent === true ||
    value.reparse_points_absent === true
  )) {
    throw new WindowsTargetAclMatrixError('incoherent_incomplete_matrix');
  }
  return Object.freeze({ ...value });
}

/**
 * Map a validated probe result into the exact Phase 9a target-ACL evidence object.
 */
export function mapWindowsTargetAclMatrixProbeToEvidence(probe) {
  const parsed = parseWindowsTargetAclMatrixProbeResult(
    `${JSON.stringify(probe)}\n`,
    '',
  );
  return Object.freeze({
    schema_version: 1,
    all_targets_checked: parsed.all_targets_checked === true,
    caller_write_denied: parsed.caller_write_denied === true,
    helper_write_allowed: parsed.helper_write_allowed === true,
    ownership_trusted_not_caller: parsed.ownership_trusted_not_caller === true,
    shared_local_service_token_user_owner_absent:
      parsed.shared_local_service_token_user_owner_absent === true,
    reparse_points_absent: parsed.reparse_points_absent === true,
  });
}

/**
 * Collect live target-ACL evidence for a branded persistent helper layout plan.
 *
 * @param {object} layoutPlan branded Phase 5h.47 plan with layout_mode persistent
 */
export async function collectWindowsTargetAclEvidence(layoutPlan) {
  if (process.platform !== 'win32') {
    throw new WindowsTargetAclMatrixError('unsupported_platform');
  }
  if (!isWindowsHelperLayoutPlan(layoutPlan) || layoutPlan.layout_mode !== 'persistent') {
    throw new WindowsTargetAclMatrixError('invalid_persistent_layout');
  }

  const probe = await runProbe();
  const evidence = brandWindowsTargetAclEvidence(mapWindowsTargetAclMatrixProbeToEvidence(probe));
  const complete = evidence.all_targets_checked === true &&
    evidence.caller_write_denied === true &&
    evidence.helper_write_allowed === true &&
    evidence.ownership_trusted_not_caller === true &&
    evidence.shared_local_service_token_user_owner_absent === true &&
    evidence.reparse_points_absent === true;

  const report = Object.freeze({
    schema_version: 1,
    platform: 'win32',
    collector: 'persistent_target_acl_matrix',
    target_acl_evidence_complete: complete,
    persistent_root_present: probe.persistent_root_present,
    service_running: probe.service_running,
    helper_token_bound: probe.helper_token_bound,
    helper_vault_free: true,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    mutation_authorized: false,
    operational_bridge_unwired: true,
    authorization_ready: false,
    terminal_code: complete
      ? 'target_acl_matrix_complete'
      : 'target_acl_matrix_incomplete',
  });
  VALID_REPORTS.add(report);
  return Object.freeze({ evidence, report });
}

export function isWindowsTargetAclMatrixReport(value) {
  return value !== null && typeof value === 'object' && VALID_REPORTS.has(value);
}

async function runProbe() {
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || !path.win32.isAbsolute(systemRoot)) {
    throw new WindowsTargetAclMatrixError('invalid_system_root');
  }
  const powershell = path.win32.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  const result = await new Promise((resolve, reject) => {
    execFile(powershell, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', PROBE_SCRIPT,
    ], {
      windowsHide: true,
      timeout: 20000,
      maxBuffer: 4096,
      encoding: 'utf8',
      env: {
        SystemRoot: systemRoot,
        WINDIR: systemRoot,
        TEMP: os.tmpdir(),
        TMP: os.tmpdir(),
        ProgramData: process.env.ProgramData,
      },
    }, (error, stdout, stderr) => {
      if (error && error.killed) {
        reject(new WindowsTargetAclMatrixError('timeout_or_terminated'));
        return;
      }
      resolve({
        code: error && typeof error.code === 'number' ? error.code : 0,
        stdout: typeof stdout === 'string' ? stdout : '',
        stderr: typeof stderr === 'string' ? stderr : '',
      });
    });
  });
  if (result.code !== 0) {
    throw new WindowsTargetAclMatrixError('probe_failed');
  }
  return parseWindowsTargetAclMatrixProbeResult(result.stdout, result.stderr);
}
