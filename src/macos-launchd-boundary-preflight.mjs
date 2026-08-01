import { execFile } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { isMacosLaunchdBoundaryPlan } from './macos-launchd-boundary-plan.mjs';

const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'macos-launchd-boundary-probe.mjs',
);
const BOOLEAN_FIELDS = [
  'service_present',
  'account_static_helper',
  'system_domain_plist',
  'plist_binding_verified',
  'demand_activation_only',
  'mach_service_declared',
  'binary_binding_verified',
  'designated_requirement_path_snapshot_matches_plan',
  'designated_requirement_verified',
  'binary_chain_symlink_free',
  'plist_chain_symlink_free',
  'binary_and_plist_owner_trusted',
  'caller_plist_and_binary_control_denied',
  'snapshot_matches_plan',
  'authorization_ready',
];
const RESULT_FIELDS = new Set(['schema_version', ...BOOLEAN_FIELDS]);

export class MacosLaunchdBoundaryPreflightError extends Error {
  constructor(code) {
    super(`macOS launchd boundary preflight failed: ${code}`);
    this.name = 'MacosLaunchdBoundaryPreflightError';
    this.code = code;
  }
}

export async function inspectMacosLaunchdBoundary(plan) {
  const binary = validatePlan(plan);
  if (process.platform !== 'darwin') {
    throw new MacosLaunchdBoundaryPreflightError('unsupported_platform');
  }
  const result = await executeProbe(execFile, process.execPath, [
    SCRIPT_PATH,
    binary.sha256,
    String(binary.byte_length),
    binary.designated_requirement_sha256,
    plan.daemon.sha256,
  ], 10000, {
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: 'C',
    LC_ALL: 'C',
  });
  return parseMacosLaunchdBoundaryResult(result.stdout, result.stderr);
}

function validatePlan(plan) {
  if (!isMacosLaunchdBoundaryPlan(plan)) {
    throw new MacosLaunchdBoundaryPreflightError('invalid_plan');
  }
  return plan.binary;
}

function executeProbe(execFileImpl, executable, args, timeoutMs, env) {
  return new Promise((resolve, reject) => {
    execFileImpl(executable, args, {
      timeout: timeoutMs,
      maxBuffer: 4096,
      encoding: 'utf8',
      env,
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new MacosLaunchdBoundaryPreflightError(
          error.killed ? 'timeout_or_terminated' : 'process_failed',
        ));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

export function parseMacosLaunchdBoundaryResult(stdout, stderr = '') {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr.trim() !== '') {
    throw new MacosLaunchdBoundaryPreflightError('invalid_output');
  }
  let value;
  try {
    value = JSON.parse(stdout.trim());
  } catch {
    throw new MacosLaunchdBoundaryPreflightError('invalid_output');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Reflect.ownKeys(value).length !== RESULT_FIELDS.size ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !RESULT_FIELDS.has(key)) ||
      value.schema_version !== 1 || BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean')) {
    throw new MacosLaunchdBoundaryPreflightError('invalid_output');
  }
  const evidenceFields = BOOLEAN_FIELDS.slice(0, -2);
  const expectedSnapshot = evidenceFields.every((field) => value[field]);
  const impossibleAbsentEvidence = !value.service_present &&
    evidenceFields.slice(1).some((field) => value[field]);
  if (value.snapshot_matches_plan !== expectedSnapshot || value.authorization_ready !== false ||
      impossibleAbsentEvidence) {
    throw new MacosLaunchdBoundaryPreflightError('invalid_output');
  }
  return Object.freeze({ ...value });
}
