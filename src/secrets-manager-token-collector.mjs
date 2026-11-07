import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  assertSecretsManagerLiveScope,
  evaluateSecretsManagerEvidence,
  SecretsManagerLiveGateError,
} from './secrets-manager-live-gate.mjs';
import {
  loadSecretsManagerAllowConfig,
  SecretsManagerAllowConfigError,
} from './secrets-manager-allow-config.mjs';
import {
  MacosSmKeychainError,
  readMacosKeychainToken,
} from './macos-sm-keychain.mjs';
import {
  LinuxSmTokenFileError,
  readLinuxOwnerOnlyToken,
} from './linux-sm-token-file.mjs';

const execFileAsync = promisify(execFile);

/** Fixed Windows DPAPI store basename (not a secret). */
export const SM_MACHINE_TOKEN_STORE_BASENAME =
  'bitwarden-agent-sm-machine.credential.xml';

/** Purpose string for the SM machine token store; probe pins by SHA-256. */
export const SM_MACHINE_TOKEN_PURPOSE =
  'bitwarden-agent-credential-bridge-sm-machine-token-v1';

export const SM_MACHINE_TOKEN_PURPOSE_SHA256 = createHash('sha256')
  .update(SM_MACHINE_TOKEN_PURPOSE, 'utf8')
  .digest('hex');

const WINDOWS_SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'secrets-manager-token-dpapi-probe.ps1',
);

export class SecretsManagerTokenCollectorError extends Error {
  /**
   * @param {string} code
   * @param {string} [reason] non-secret classification (timeout, exit_<n>,
   *   stderr, spawn_<code>) -- never stdout or stderr content.
   */
  constructor(code, reason) {
    super(reason
      ? `Secrets Manager token collector rejected: ${code} reason=${reason}`
      : `Secrets Manager token collector rejected: ${code}`);
    this.name = 'SecretsManagerTokenCollectorError';
    this.code = code;
    if (reason) this.reason = reason;
  }
}

/**
 * Default child timeout for the DPAPI token probe. 15 s was too short under
 * memory pressure (2026-11-06: Windows PowerShell cold start took longer while
 * free RAM was below 1 GB, every abort surfaced as an opaque
 * token_probe_failed). Override with BWS_BRIDGE_SM_TOKEN_PROBE_TIMEOUT_MS.
 */
export const DEFAULT_TOKEN_PROBE_TIMEOUT_MS = 60000;

export function resolveTokenProbeTimeoutMs(env = process.env) {
  const raw = Number(env?.BWS_BRIDGE_SM_TOKEN_PROBE_TIMEOUT_MS);
  if (Number.isInteger(raw) && raw >= 1000 && raw <= 600000) return raw;
  return DEFAULT_TOKEN_PROBE_TIMEOUT_MS;
}

/** Classify an execFile failure without touching its output. */
export function classifyExecFailure(error) {
  if (error?.killed === true || error?.signal === 'SIGTERM' || error?.code === 'ETIMEDOUT') {
    return 'timeout';
  }
  if (typeof error?.code === 'number') return `exit_${error.code}`;
  if (typeof error?.code === 'string' && /^[A-Z0-9_]{1,32}$/.test(error.code)) {
    return `spawn_${error.code}`;
  }
  return 'unknown';
}

export function defaultMacSecretsManagerTokenPath() {
  return path.join(
    os.homedir(),
    'Library',
    'Application Support',
    'BitwardenAgentCredentialBridge',
    'sm-machine.token',
  );
}

export async function readWindowsDpapiToken(options = {}) {
  const platform = options.platform ?? process.platform;
  const run = typeof options.execFile === 'function' ? options.execFile : execFileAsync;
  const env = options.env ?? process.env;
  const timeoutMs = options.timeoutMs ?? resolveTokenProbeTimeoutMs();
  if (platform !== 'win32') {
    throw new SecretsManagerTokenCollectorError('unsupported_platform');
  }
  const systemRoot = env.SystemRoot;
  if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
    throw new SecretsManagerTokenCollectorError('system_root_absent');
  }
  const powershell = path.join(
    systemRoot,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );

  let stdout = '';
  let stderr = '';
  let code = 1;
  let reason = null;
  try {
    const result = await run(powershell, [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      WINDOWS_SCRIPT,
      '-ExpectedPurposeSha256',
      SM_MACHINE_TOKEN_PURPOSE_SHA256,
    ], {
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 64 * 1024,
      encoding: 'utf8',
      env: {
        SystemRoot: systemRoot,
        USERPROFILE: env.USERPROFILE,
        LOCALAPPDATA: env.LOCALAPPDATA,
        windir: env.windir,
        PATH: env.PATH,
      },
    });
    stdout = result.stdout;
    stderr = result.stderr;
    code = 0;
  } catch (error) {
    code = typeof error?.code === 'number' ? error.code : 1;
    stdout = typeof error?.stdout === 'string' ? error.stdout : '';
    stderr = typeof error?.stderr === 'string' ? error.stderr : '';
    reason = classifyExecFailure(error);
  }

  if (code !== 0) {
    throw new SecretsManagerTokenCollectorError('token_probe_failed', reason ?? `exit_${code}`);
  }
  if (typeof stderr === 'string' && stderr.length > 0) {
    throw new SecretsManagerTokenCollectorError('token_probe_failed', 'stderr');
  }
  if (typeof stdout !== 'string' || stdout.length < 16 || stdout.length > 8192) {
    throw new SecretsManagerTokenCollectorError('invalid_token');
  }
  return stdout;
}

/**
 * Collect machine allowlist + short-lived access token under a branded scope.
 * Never logs the token.
 *
 * @param {unknown} scope
 * @param {{
 *   allowConfigPath?: string,
 *   readToken?: () => Promise<string>,
 *   runSecurity?: (script: string) => Promise<{ code: number, stdout: string, stderr: string }>,
 * }} [options]
 */
export async function collectSecretsManagerMachineBundle(scope, options = {}) {
  try {
    assertSecretsManagerLiveScope(scope);
  } catch (error) {
    if (error instanceof SecretsManagerLiveGateError) {
      throw new SecretsManagerTokenCollectorError('invalid_scope');
    }
    throw error;
  }

  let allow;
  try {
    allow = await loadSecretsManagerAllowConfig(options.allowConfigPath);
  } catch (error) {
    if (error instanceof SecretsManagerAllowConfigError) {
      throw new SecretsManagerTokenCollectorError(error.code);
    }
    throw new SecretsManagerTokenCollectorError('allow_config_absent');
  }

  const tokenReader = typeof options.readToken === 'function'
    ? options.readToken
    : async () => {
      if (process.platform === 'win32') {
        return readWindowsDpapiToken();
      }
      if (process.platform === 'darwin') {
        try {
          return await readMacosKeychainToken(allow.machine_id, {
            runSecurity: options.runSecurity,
          });
        } catch (error) {
          if (error instanceof MacosSmKeychainError) {
            throw new SecretsManagerTokenCollectorError(error.code);
          }
          throw new SecretsManagerTokenCollectorError('token_probe_failed');
        }
      }
      if (process.platform === 'linux') {
        try {
          return await readLinuxOwnerOnlyToken();
        } catch (error) {
          if (error instanceof LinuxSmTokenFileError) {
            throw new SecretsManagerTokenCollectorError(error.code);
          }
          throw new SecretsManagerTokenCollectorError('token_probe_failed');
        }
      }
      throw new SecretsManagerTokenCollectorError('unsupported_platform');
    };

  let accessToken;
  try {
    accessToken = await tokenReader();
  } catch (error) {
    if (error instanceof SecretsManagerTokenCollectorError) throw error;
    throw new SecretsManagerTokenCollectorError('token_probe_failed');
  }

  const evidence = evaluateSecretsManagerEvidence(scope, {
    machine_config_loaded: true,
    token_present: typeof accessToken === 'string' && accessToken.length >= 16,
    adapter_fixed: true,
    projects_allowlisted: allow.allowed_project_ids.length >= 1,
  });
  if (!evidence.sm_preflight_passed) {
    throw new SecretsManagerTokenCollectorError('preflight_failed');
  }

  return {
    evidence,
    allow,
    accessToken,
    machine_id: allow.machine_id,
  };
}
