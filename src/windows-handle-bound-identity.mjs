import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';
import { isWindowsServiceBoundaryPlan } from './windows-service-boundary-plan.mjs';
import { publishWindowsHelperServiceBinary } from './windows-helper-publish.mjs';
import { requireWindowsHelperPublishBinding } from './windows-helper-package-binding.mjs';
import { brandWindowsHandleBoundIdentityEvidenceForHarness } from './windows-production-authorization.mjs';

/**
 * Phase 9b: collect handle-bound installed-service identity evidence.
 *
 * Composes the native Phase 5h.13 pipe/SCM/token verifier with a handle-open
 * binary + service-object ACL probe. Path-based Phase 5h.9 preflight alone is
 * never sufficient and never sets path_based_preflight_only=true here.
 *
 * Performs no elevation, service install/start, manifest execution, or
 * Bitwarden access. authorization_ready remains false on the public report;
 * operational bridge wiring is Phase 9e.
 */

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROBE_SCRIPT = path.join(ROOT, 'scripts', 'windows-handle-bound-identity-probe.ps1');
const HELPER_EXE = 'BitwardenAgentCredentialBridgeHelper.exe';

const PROBE_FIELDS = new Set([
  'schema_version',
  'service_present',
  'binary_digest_matched_via_handle',
  'binary_chain_reparse_free',
  'binary_owner_trusted',
  'caller_binary_control_denied',
  'caller_service_control_denied',
  'service_dacl_caller_change_denied',
  'handle_open_used',
  'path_hash_used',
  'authorization_ready',
]);

const IDENTITY_FIELDS = new Set([
  'schema_version',
  'local_pipe_connected',
  'server_pid_bound',
  'scm_service_running',
  'scm_server_pid_match',
  'server_token_bound',
  'server_token_user_local_service',
  'service_sid_group_enabled',
  'server_identity_verified',
  'request_sent',
  'authorization_denied',
]);

const BOOLEAN_PROBE = [...PROBE_FIELDS].filter((field) => field !== 'schema_version');
const BOOLEAN_IDENTITY = [...IDENTITY_FIELDS].filter((field) => field !== 'schema_version');

export class WindowsHandleBoundIdentityError extends Error {
  constructor(code = 'invalid_handle_bound_identity') {
    super(`Windows handle-bound identity rejected: ${code}`);
    this.name = 'WindowsHandleBoundIdentityError';
    this.code = code;
  }
}

const VALID_REPORTS = new WeakSet();

/** Brand collector evidence for production authorization (same WeakSet as harness). */
export function brandWindowsHandleBoundIdentityEvidence(raw) {
  return brandWindowsHandleBoundIdentityEvidenceForHarness(raw);
}

export function parseWindowsHandleBoundBinaryProbeResult(stdout, stderr = '') {
  const value = parseExactJson(stdout, stderr, PROBE_FIELDS, BOOLEAN_PROBE, 'invalid_binary_probe');
  if (value.authorization_ready !== false || value.path_hash_used !== false) {
    throw new WindowsHandleBoundIdentityError('invalid_binary_probe');
  }
  if (value.binary_digest_matched_via_handle === true && value.handle_open_used !== true) {
    throw new WindowsHandleBoundIdentityError('invalid_binary_probe');
  }
  if (!value.service_present && BOOLEAN_PROBE.some((field) =>
    field !== 'service_present' && field !== 'authorization_ready' && field !== 'path_hash_used' &&
    field !== 'handle_open_used' && value[field] === true)) {
    throw new WindowsHandleBoundIdentityError('invalid_binary_probe');
  }
  return value;
}

export function parseWindowsServerIdentityVerifierResult(stdout, stderr = '') {
  const value = parseExactJson(stdout, stderr, IDENTITY_FIELDS, BOOLEAN_IDENTITY, 'invalid_identity_verifier');
  if (value.request_sent !== false || value.authorization_denied !== true) {
    throw new WindowsHandleBoundIdentityError('invalid_identity_verifier');
  }
  return value;
}

export function absentWindowsServerIdentityFacts() {
  return Object.freeze({
    schema_version: 1,
    local_pipe_connected: false,
    server_pid_bound: false,
    scm_service_running: false,
    scm_server_pid_match: false,
    server_token_bound: false,
    server_token_user_local_service: false,
    service_sid_group_enabled: false,
    server_identity_verified: false,
    request_sent: false,
    authorization_denied: true,
  });
}

/**
 * Merge native identity verifier facts with handle-bound binary/service probe facts
 * into the exact Phase 9a handle-bound evidence object (unbranded).
 */
export function mergeWindowsHandleBoundIdentityEvidence(identityFacts, binaryProbe) {
  const identity = identityFacts === null
    ? absentWindowsServerIdentityFacts()
    : parseWindowsServerIdentityVerifierResult(
      `${JSON.stringify(identityFacts)}\n`,
      '',
    );
  const probe = parseWindowsHandleBoundBinaryProbeResult(`${JSON.stringify(binaryProbe)}\n`, '');

  return Object.freeze({
    schema_version: 1,
    pipe_local_only: identity.local_pipe_connected === true,
    remote_clients_rejected: identity.local_pipe_connected === true,
    server_pid_handle_bound: identity.server_pid_bound === true,
    server_token_user_local_service: identity.server_token_user_local_service === true,
    server_service_sid_enabled: identity.service_sid_group_enabled === true,
    scm_service_running_same_pid: identity.scm_service_running === true &&
      identity.scm_server_pid_match === true,
    binary_digest_matched_via_handle: probe.binary_digest_matched_via_handle === true &&
      probe.handle_open_used === true &&
      probe.path_hash_used === false,
    binary_chain_reparse_free: probe.binary_chain_reparse_free === true,
    binary_owner_trusted: probe.binary_owner_trusted === true,
    caller_service_control_denied: probe.caller_service_control_denied === true,
    service_dacl_caller_change_denied: probe.service_dacl_caller_change_denied === true,
    path_based_preflight_only: false,
    collector_value_free: true,
  });
}

/**
 * Collect live handle-bound identity evidence for a branded Phase 5h.8 boundary plan.
 * Returns branded evidence plus a value-free public report that never authorizes.
 *
 * @param {object} boundaryPlan branded Windows service boundary plan
 * @param {{ helperExecutablePath?: string, skipPublish?: boolean }} [options]
 */
export async function collectWindowsHandleBoundIdentityEvidence(boundaryPlan, options = {}) {
  if (process.platform !== 'win32') {
    throw new WindowsHandleBoundIdentityError('unsupported_platform');
  }
  if (!isWindowsServiceBoundaryPlan(boundaryPlan)) {
    throw new WindowsHandleBoundIdentityError('invalid_boundary_plan');
  }
  if (options !== null && typeof options === 'object' && !Array.isArray(options) &&
      utilTypes.isProxy(options)) {
    throw new WindowsHandleBoundIdentityError('invalid_options');
  }

  const expectedSha256 = boundaryPlan.binary.sha256;
  const expectedByteLength = boundaryPlan.binary.byte_length;
  let helperPath = typeof options.helperExecutablePath === 'string'
    ? options.helperExecutablePath
    : null;
  let cleanupDir = null;

  if (helperPath === null) {
    if (options.skipPublish === true) {
      throw new WindowsHandleBoundIdentityError('helper_executable_required');
    }
    const published = requireWindowsHelperPublishBinding(
      await publishWindowsHelperServiceBinary(),
    );
    if (published.sha256 !== expectedSha256 || published.byteLength !== expectedByteLength) {
      throw new WindowsHandleBoundIdentityError('binary_binding_mismatch');
    }
    cleanupDir = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-hbi-'));
    helperPath = path.join(cleanupDir, HELPER_EXE);
    await fs.writeFile(helperPath, published.bytes, { flag: 'wx' });
  }

  try {
    const identity = await runNativeIdentityVerifier(helperPath);
    const binaryProbe = await runBinaryProbe(expectedSha256, expectedByteLength);
    const merged = mergeWindowsHandleBoundIdentityEvidence(identity, binaryProbe);
    const evidence = brandWindowsHandleBoundIdentityEvidence(merged);
    const complete = evidence.pipe_local_only &&
      evidence.remote_clients_rejected &&
      evidence.server_pid_handle_bound &&
      evidence.server_token_user_local_service &&
      evidence.server_service_sid_enabled &&
      evidence.scm_service_running_same_pid &&
      evidence.binary_digest_matched_via_handle &&
      evidence.binary_chain_reparse_free &&
      evidence.binary_owner_trusted &&
      evidence.caller_service_control_denied &&
      evidence.service_dacl_caller_change_denied &&
      evidence.path_based_preflight_only === false &&
      evidence.collector_value_free === true;

    const report = Object.freeze({
      schema_version: 1,
      platform: 'win32',
      collector: 'handle_bound_installed_service_identity',
      handle_bound_identity_complete: complete,
      path_based_preflight_only: false,
      helper_vault_free: true,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
      mutation_authorized: false,
      operational_bridge_unwired: true,
      authorization_ready: false,
      terminal_code: complete
        ? 'handle_bound_identity_complete'
        : 'handle_bound_identity_incomplete',
    });
    VALID_REPORTS.add(report);
    return Object.freeze({ evidence, report });
  } finally {
    if (cleanupDir !== null) {
      await fs.rm(cleanupDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

export function isWindowsHandleBoundIdentityReport(value) {
  return value !== null && typeof value === 'object' && VALID_REPORTS.has(value);
}

async function runNativeIdentityVerifier(helperPath) {
  const result = await execCapture(helperPath, ['--verify-fixed-server-identity'], 8000, 4096);
  if (result.stderr.trim() !== '') {
    throw new WindowsHandleBoundIdentityError('identity_verifier_failed');
  }
  if (result.stdout.trim() === '') {
    // Exit 20/30 when the fixed pipe is absent: honest incomplete facts.
    return absentWindowsServerIdentityFacts();
  }
  return parseWindowsServerIdentityVerifierResult(result.stdout, result.stderr);
}

async function runBinaryProbe(sha256, byteLength) {
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || !path.win32.isAbsolute(systemRoot)) {
    throw new WindowsHandleBoundIdentityError('invalid_system_root');
  }
  const powershell = path.win32.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  const result = await execCapture(powershell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', PROBE_SCRIPT, sha256, String(byteLength),
  ], 60000, 8192, {
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    SystemDrive: process.env.SystemDrive || path.win32.parse(systemRoot).root.replace(/\\$/, ''),
    // Probe joins $env:ProgramData for the trusted install-root stop; omit and the
    // chain walk throws under $ErrorActionPreference Stop, collapsing to incomplete.
    ProgramData: process.env.ProgramData || path.win32.join(systemRoot, 'ProgramData'),
    ALLUSERSPROFILE: process.env.ALLUSERSPROFILE ||
      process.env.ProgramData ||
      path.win32.join(systemRoot, 'ProgramData'),
    ComSpec: path.win32.join(systemRoot, 'System32', 'cmd.exe'),
    // sc.exe (sdshow) needs a normal system PATH; System32-only yields empty output.
    PATH: [
      path.win32.join(systemRoot, 'System32'),
      path.win32.join(systemRoot, 'System32', 'Wbem'),
      path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0'),
      systemRoot,
    ].join(path.win32.delimiter),
    PATHEXT: process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WSF;.WSH;.MSC',
    USERNAME: process.env.USERNAME || 'bridge-probe',
    USERDOMAIN: process.env.USERDOMAIN || 'BRIDGE',
    TEMP: os.tmpdir(),
    TMP: os.tmpdir(),
  });
  if (result.code !== 0) {
    throw new WindowsHandleBoundIdentityError('binary_probe_failed');
  }
  return parseWindowsHandleBoundBinaryProbeResult(result.stdout, result.stderr);
}

function execCapture(executable, args, timeoutMs, maxBuffer, env) {
  return new Promise((resolve, reject) => {
    execFile(executable, args, {
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer,
      encoding: 'utf8',
      env: env ?? {
        SystemRoot: process.env.SystemRoot,
        WINDIR: process.env.SystemRoot,
        TEMP: os.tmpdir(),
        TMP: os.tmpdir(),
      },
    }, (error, stdout, stderr) => {
      if (error && error.killed) {
        reject(new WindowsHandleBoundIdentityError('timeout_or_terminated'));
        return;
      }
      resolve({
        code: error && typeof error.code === 'number' ? error.code : 0,
        stdout: typeof stdout === 'string' ? stdout : '',
        stderr: typeof stderr === 'string' ? stderr : '',
      });
    });
  });
}

function parseExactJson(stdout, stderr, fields, booleanFields, code) {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr.trim() !== '') {
    throw new WindowsHandleBoundIdentityError(code);
  }
  let value;
  try {
    const normalized = stdout.startsWith('\uFEFF') ? stdout.slice(1) : stdout;
    value = JSON.parse(normalized.trim());
  } catch {
    throw new WindowsHandleBoundIdentityError(code);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsHandleBoundIdentityError(code);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size ||
      keys.some((key) => typeof key !== 'string' || !fields.has(key)) ||
      value.schema_version !== 1 ||
      booleanFields.some((field) => typeof value[field] !== 'boolean')) {
    throw new WindowsHandleBoundIdentityError(code);
  }
  return Object.freeze({ ...value });
}
