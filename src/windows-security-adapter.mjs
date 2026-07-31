import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'windows-security-probe.ps1',
);
const RESULT_FIELDS = new Set([
  'reparsePoint',
  'ownerCurrentUser',
  'writableByOtherUsers',
]);

export class WindowsSecurityProbeError extends Error {
  constructor(code) {
    super(`windows security probe failed: ${code}`);
    this.name = 'WindowsSecurityProbeError';
    this.code = code;
  }
}

/**
 * Create the value-free adapter consumed by auditBootstrapHost.
 * @param {{execFileImpl?: typeof execFile, powershellPath?: string, scriptPath?: string, timeoutMs?: number}} [options]
 */
export function createWindowsSecurityAdapter(options = {}) {
  const execFileImpl = options.execFileImpl ?? execFile;
  const powershellPath = options.powershellPath ?? 'powershell.exe';
  const scriptPath = options.scriptPath ?? SCRIPT_PATH;
  const timeoutMs = options.timeoutMs ?? 5000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) {
    throw new WindowsSecurityProbeError('invalid_timeout');
  }

  return async function inspectWindowsSecurity(targetPath) {
    if (typeof targetPath !== 'string' || targetPath.length === 0) {
      throw new WindowsSecurityProbeError('invalid_target');
    }
    const result = await executeProbe(execFileImpl, powershellPath, [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      scriptPath,
      targetPath,
    ], timeoutMs);
    return parseProbeResult(result.stdout, result.stderr);
  };
}

function executeProbe(execFileImpl, executable, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFileImpl(
      executable,
      args,
      {
        windowsHide: true,
        timeout: timeoutMs,
        maxBuffer: 4096,
        encoding: 'utf8',
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(new WindowsSecurityProbeError(error.killed ? 'timeout_or_terminated' : 'process_failed'));
          return;
        }
        resolve({ stdout, stderr });
      },
    );
  });
}

export function parseProbeResult(stdout, stderr = '') {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr.trim() !== '') {
    throw new WindowsSecurityProbeError('invalid_output');
  }
  let value;
  try {
    const normalized = stdout.startsWith('\uFEFF') ? stdout.slice(1) : stdout;
    value = JSON.parse(normalized.trim());
  } catch {
    throw new WindowsSecurityProbeError('invalid_output');
  }
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== RESULT_FIELDS.size ||
    Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !RESULT_FIELDS.has(key)) ||
    [...RESULT_FIELDS].some((key) => typeof value[key] !== 'boolean')
  ) {
    throw new WindowsSecurityProbeError('invalid_output');
  }
  return Object.freeze({
    reparsePoint: value.reparsePoint,
    ownerCurrentUser: value.ownerCurrentUser,
    writableByOtherUsers: value.writableByOtherUsers,
  });
}
