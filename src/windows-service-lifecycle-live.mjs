import { randomBytes } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { types as utilTypes } from 'node:util';
import { publishWindowsHelperServiceBinary } from './windows-helper-publish.mjs';
import { requireWindowsHelperPublishBinding } from './windows-helper-package-binding.mjs';
import { buildWindowsServiceBoundaryPlan } from './windows-service-boundary-plan.mjs';
import { buildWindowsServiceLifecycleGate } from './windows-service-lifecycle-gate.mjs';
import { evaluateWindowsServiceLifecycleTranscript } from './windows-service-lifecycle-evidence.mjs';
import { evaluateWindowsServiceLifecycleCollectorTrust } from './windows-service-lifecycle-collector-trust.mjs';

const execFileAsync = promisify(execFile);
const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'windows-service-lifecycle-live-collector.ps1',
);
const RESULT_FIELDS = new Set(['schema_version', 'terminal_outcome', 'events', 'provenance']);
const TERMINAL_OUTCOMES = new Set([
  'denial_verified', 'preflight_failed', 'mutation_failed', 'cleanup_failed',
]);

const VALID_LIVE_REPORTS = new WeakSet();

export class WindowsServiceLifecycleLiveError extends Error {
  constructor(code) {
    super(`Windows service lifecycle live test failed: ${code}`);
    this.name = 'WindowsServiceLifecycleLiveError';
    this.code = code;
  }
}

/**
 * Run the operator-approved disposable elevated LocalService install/start/deny/
 * stop/delete lifecycle on this host. Approval is out-of-band for this task and is
 * never accepted as an API field. Rebuilds the branded plan/gate in-process from
 * the freshly published reviewed binary. Only this path brands a live report.
 */
export async function runOperatorApprovedWindowsServiceLifecycleLiveTest() {
  if (process.platform !== 'win32') {
    throw new WindowsServiceLifecycleLiveError('unsupported_platform');
  }
  const published = requireWindowsHelperPublishBinding(
    await publishWindowsHelperServiceBinary(),
  );
  const plan = buildWindowsServiceBoundaryPlan({
    platform: 'win32',
    binarySha256: published.sha256,
    binaryByteLength: published.byteLength,
  });
  const gate = buildWindowsServiceLifecycleGate(plan);
  const staging = await prepareStaging(published);
  try {
    await launchCollector(staging, published);
    const raw = await readCollectorResult(staging.root, staging.completionNonce);
    return brandLiveReport(evaluateLiveCollectorResult(gate, raw));
  } finally {
    await fs.rm(staging.root, { recursive: true, force: true }).catch(() => {});
  }
}

export function isWindowsServiceLifecycleLiveReport(value) {
  return value !== null && typeof value === 'object' && VALID_LIVE_REPORTS.has(value);
}

/**
 * Structurally evaluate a collector payload. The returned object is not branded
 * and cannot satisfy install-gate eligibility. Only
 * `runOperatorApprovedWindowsServiceLifecycleLiveTest` brands reports.
 */
export function evaluateLiveCollectorResult(gate, raw) {
  const payload = exactObject(raw, RESULT_FIELDS);
  if (payload.schema_version !== 1 || !TERMINAL_OUTCOMES.has(payload.terminal_outcome) ||
      !Array.isArray(payload.events)) {
    throw new WindowsServiceLifecycleLiveError('invalid_collector_result');
  }
  const transcript = {
    schema_version: 1,
    terminal_outcome: payload.terminal_outcome,
    events: payload.events,
  };
  const structure = evaluateWindowsServiceLifecycleTranscript(gate, transcript);
  const trust = evaluateWindowsServiceLifecycleCollectorTrust(gate, transcript, payload.provenance);
  const liveVerified = trust.collector_trust_verified === true &&
    structure.transcript_structure_complete === true &&
    payload.terminal_outcome === 'denial_verified';

  return Object.freeze({
    schema_version: 1,
    preflight_claim_structurally_complete: structure.preflight_claim_structurally_complete,
    mutation_claim_structurally_complete: structure.mutation_claim_structurally_complete,
    denial_claim_structurally_complete: structure.denial_claim_structurally_complete,
    cleanup_claim_structurally_complete: structure.cleanup_claim_structurally_complete,
    final_absence_claim_structurally_complete: structure.final_absence_claim_structurally_complete,
    transcript_structure_complete: structure.transcript_structure_complete,
    required_provenance_complete: trust.required_provenance_complete,
    collector_trust_verified: trust.collector_trust_verified,
    live_test_executed: true,
    live_test_verified: liveVerified,
    mutation_authorized: false,
    install_gate_eligible: false,
    authorization_ready: false,
    terminal_code: liveVerified ? 'live_denial_verified_cleaned' : trust.terminal_code,
  });
}

/**
 * Brand a live report for harness unit tests that exercise install-gate wiring.
 * Production eligibility still requires an operator-approved live run; forged
 * clones of branded objects remain unrecognized.
 */
export function brandWindowsServiceLifecycleLiveReportForHarness(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report) ||
      utilTypes.isProxy(report)) {
    throw new WindowsServiceLifecycleLiveError('invalid_live_report');
  }
  return brandLiveReport(report);
}

function brandLiveReport(report) {
  VALID_LIVE_REPORTS.add(report);
  return report;
}

async function prepareStaging(published) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-live-stage-'));
  const nonce = randomBytes(32).toString('hex');
  const denialNonce = randomBytes(32).toString('hex');
  const completionNonce = randomBytes(32).toString('hex');
  await fs.writeFile(path.join(root, 'marker'), nonce, { encoding: 'ascii', flag: 'wx' });
  await fs.writeFile(path.join(root, 'payload.exe'), published.bytes, { flag: 'wx' });
  await fs.writeFile(path.join(root, 'params.json'), `${JSON.stringify({
    marker_nonce: nonce,
    expected_sha256: published.sha256,
    expected_byte_length: published.byteLength,
    denial_nonce: denialNonce,
    completion_nonce: completionNonce,
  })}\n`, { encoding: 'utf8', flag: 'wx' });
  await hardenStagingAcl(root);
  return {
    root,
    nonce,
    denialNonce,
    completionNonce,
    expectedSha256: published.sha256,
    expectedByteLength: published.byteLength,
  };
}

async function hardenStagingAcl(root) {
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string') return;
  const powershell = path.win32.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  try {
    await execFileAsync(powershell, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      `$p = '${root.replace(/'/g, "''")}';` +
      '$acl = Get-Acl -LiteralPath $p;' +
      '$acl.SetAccessRuleProtection($true, $false);' +
      '$ids = @(' +
      "  (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18'))," +
      "  (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))," +
      '  [Security.Principal.WindowsIdentity]::GetCurrent().User' +
      ');' +
      'foreach ($id in $ids) {' +
      "  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')));" +
      '};' +
      'Set-Acl -LiteralPath $p -AclObject $acl',
    ], {
      windowsHide: true, timeout: 15000, maxBuffer: 4096, encoding: 'utf8',
      env: { SystemRoot: systemRoot, WINDIR: systemRoot },
    });
  } catch {
    // Best-effort ACL harden; CLI-authoritative digests remain the TOCTOU control.
  }
}

async function launchCollector(staging, published) {
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || !path.win32.isAbsolute(systemRoot)) {
    throw new WindowsServiceLifecycleLiveError('invalid_system_root');
  }
  const powershell = path.win32.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  const args = [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', SCRIPT_PATH,
    '-StagingRoot', staging.root,
    '-ExpectedBinarySha256', staging.expectedSha256,
    '-ExpectedBinaryByteLength', String(staging.expectedByteLength),
    '-MarkerNonce', staging.nonce,
    '-DenialNonce', staging.denialNonce,
    '-CompletionNonce', staging.completionNonce,
  ];
  const elevated = await isProcessElevated(powershell, systemRoot);
  if (elevated) {
    const child = spawn(powershell, args, {
      windowsHide: true,
      stdio: 'ignore',
      env: {
        SystemRoot: systemRoot,
        WINDIR: systemRoot,
        TEMP: os.tmpdir(),
        TMP: os.tmpdir(),
      },
    });
    child.unref();
    await waitForCollectorResult(staging.root);
    return;
  }
  await runElevatedPowerShell(powershell, args, systemRoot, staging.root);
  void published;
}

async function runElevatedPowerShell(powershell, args, systemRoot, stagingRoot) {
  const argLine = args.map((value) => {
    const text = String(value);
    return /\s/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }).join(' ');

  const vbs = [
    'Set sh = CreateObject("Shell.Application")',
    `sh.ShellExecute ${vbsQuote(powershell)}, ${vbsQuote(argLine)}, "", "runas", 1`,
  ].join('\r\n');
  const vbsPath = path.join(stagingRoot, 'elevate.vbs');
  await fs.writeFile(vbsPath, vbs, { encoding: 'utf8', flag: 'wx' });

  await execFileAsync(path.win32.join(systemRoot, 'System32', 'wscript.exe'), [
    '//B', '//Nologo', vbsPath,
  ], {
    windowsHide: false,
    timeout: 30000,
    maxBuffer: 1024,
    encoding: 'utf8',
    env: {
      SystemRoot: systemRoot,
      WINDIR: systemRoot,
      TEMP: os.tmpdir(),
      TMP: os.tmpdir(),
    },
  });

  await waitForCollectorResult(stagingRoot);
}

async function waitForCollectorResult(stagingRoot) {
  const resultPath = path.join(stagingRoot, 'result.json');
  const deadline = Date.now() + 540000;
  while (Date.now() < deadline) {
    try {
      await fs.access(resultPath);
      await new Promise((resolve) => setTimeout(resolve, 750));
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new WindowsServiceLifecycleLiveError('elevation_timeout');
}

function vbsQuote(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

async function isProcessElevated(powershell, systemRoot) {
  try {
    const { stdout } = await execFileAsync(powershell, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
    ], {
      windowsHide: true, timeout: 10000, maxBuffer: 1024, encoding: 'utf8',
      env: { SystemRoot: systemRoot, WINDIR: systemRoot },
    });
    return stdout.trim().toLowerCase() === 'true';
  } catch {
    return false;
  }
}

async function readCollectorResult(stagingRoot, expectedCompletionNonce) {
  const resultPath = path.join(stagingRoot, 'result.json');
  let text;
  try {
    text = await fs.readFile(resultPath, 'utf8');
  } catch {
    throw new WindowsServiceLifecycleLiveError('collector_result_missing');
  }
  if (text.length > 64 * 1024) {
    throw new WindowsServiceLifecycleLiveError('collector_result_too_large');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new WindowsServiceLifecycleLiveError('collector_result_invalid_json');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) ||
      typeof parsed.completion_nonce !== 'string' ||
      parsed.completion_nonce !== expectedCompletionNonce) {
    throw new WindowsServiceLifecycleLiveError('completion_nonce_mismatch');
  }
  const { completion_nonce: _ignored, ...rest } = parsed;
  return rest;
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsServiceLifecycleLiveError('invalid_collector_result');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsServiceLifecycleLiveError('invalid_collector_result');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsServiceLifecycleLiveError('invalid_collector_result');
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
