import { execFile } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { isWindowsServiceBoundaryPlan } from './windows-service-boundary-plan.mjs';

const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'windows-service-boundary-probe.ps1',
);
const BOOLEAN_FIELDS = [
  'service_present',
  'account_local_service',
  'demand_start',
  'win32_own_process',
  'service_sid_unrestricted',
  'caller_service_control_denied',
  'binary_binding_verified',
  'binary_chain_reparse_free',
  'binary_owner_trusted',
  'caller_binary_control_denied',
  'snapshot_matches_plan',
  'authorization_ready',
];
const RESULT_FIELDS = new Set(['schema_version', ...BOOLEAN_FIELDS]);

export class WindowsServiceBoundaryPreflightError extends Error {
  constructor(code) {
    super(`Windows service boundary preflight failed: ${code}`);
    this.name = 'WindowsServiceBoundaryPreflightError';
    this.code = code;
  }
}

export async function inspectWindowsServiceBoundary(plan) {
  const binary = validatePlan(plan);
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || !path.win32.isAbsolute(systemRoot)) {
    throw new WindowsServiceBoundaryPreflightError('invalid_system_root');
  }
  const powershellPath = path.win32.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  const result = await executeProbe(execFile, powershellPath, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', SCRIPT_PATH, binary.sha256, String(binary.byte_length),
  ], 10000, {
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    TEMP: os.tmpdir(),
    TMP: os.tmpdir(),
  });
  return parseWindowsServiceBoundaryResult(result.stdout, result.stderr);
}

function validatePlan(plan) {
  if (!isWindowsServiceBoundaryPlan(plan)) {
    throw new WindowsServiceBoundaryPreflightError('invalid_plan');
  }
  return plan.binary;
}

function executeProbe(execFileImpl, executable, args, timeoutMs, env) {
  return new Promise((resolve, reject) => {
    execFileImpl(executable, args, {
      windowsHide: true, timeout: timeoutMs, maxBuffer: 4096, encoding: 'utf8', env,
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new WindowsServiceBoundaryPreflightError(
          error.killed ? 'timeout_or_terminated' : 'process_failed',
        ));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

export function parseWindowsServiceBoundaryResult(stdout, stderr = '') {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr.trim() !== '') {
    throw new WindowsServiceBoundaryPreflightError('invalid_output');
  }
  let value;
  try {
    const normalized = stdout.startsWith('\uFEFF') ? stdout.slice(1) : stdout;
    value = JSON.parse(normalized.trim());
  } catch {
    throw new WindowsServiceBoundaryPreflightError('invalid_output');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Reflect.ownKeys(value).length !== RESULT_FIELDS.size ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !RESULT_FIELDS.has(key)) ||
      value.schema_version !== 1 || BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean')) {
    throw new WindowsServiceBoundaryPreflightError('invalid_output');
  }
  const evidenceFields = BOOLEAN_FIELDS.slice(0, -2);
  const expectedSnapshot = evidenceFields.every((field) => value[field]);
  const impossibleAbsentEvidence = !value.service_present &&
    evidenceFields.slice(1).some((field) => value[field]);
  if (value.snapshot_matches_plan !== expectedSnapshot || value.authorization_ready !== false) {
    throw new WindowsServiceBoundaryPreflightError('invalid_output');
  }
  if (impossibleAbsentEvidence) throw new WindowsServiceBoundaryPreflightError('invalid_output');
  return Object.freeze({ ...value });
}
