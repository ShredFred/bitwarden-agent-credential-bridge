import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
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
  constructor(code) {
    super(`Secrets Manager token collector rejected: ${code}`);
    this.name = 'SecretsManagerTokenCollectorError';
    this.code = code;
  }
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

async function readWindowsDpapiToken() {
  if (process.platform !== 'win32') {
    throw new SecretsManagerTokenCollectorError('unsupported_platform');
  }
  const systemRoot = process.env.SystemRoot;
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
  try {
    const result = await execFileAsync(powershell, [
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
      timeout: 15000,
      maxBuffer: 64 * 1024,
      encoding: 'utf8',
      env: {
        SystemRoot: systemRoot,
        USERPROFILE: process.env.USERPROFILE,
        LOCALAPPDATA: process.env.LOCALAPPDATA,
        windir: process.env.windir,
        PATH: process.env.PATH,
      },
    });
    stdout = result.stdout;
    stderr = result.stderr;
    code = 0;
  } catch (error) {
    code = typeof error?.code === 'number' ? error.code : 1;
    stdout = typeof error?.stdout === 'string' ? error.stdout : '';
    stderr = typeof error?.stderr === 'string' ? error.stderr : '';
  }

  if (code !== 0 || (typeof stderr === 'string' && stderr.length > 0)) {
    throw new SecretsManagerTokenCollectorError('token_probe_failed');
  }
  if (typeof stdout !== 'string' || stdout.length < 16 || stdout.length > 8192) {
    throw new SecretsManagerTokenCollectorError('invalid_token');
  }
  return stdout;
}

async function readMacTokenFile(tokenPath = defaultMacSecretsManagerTokenPath()) {
  let raw;
  try {
    raw = await fs.readFile(tokenPath, { encoding: 'utf8' });
  } catch {
    throw new SecretsManagerTokenCollectorError('token_absent');
  }
  const token = raw.replace(/^\uFEFF/, '').trim();
  if (token.length < 16 || token.length > 8192) {
    throw new SecretsManagerTokenCollectorError('invalid_token');
  }
  // Reject obvious multiline leaks / accidental JSON dumps.
  if (token.includes('\n') || token.includes('\r')) {
    throw new SecretsManagerTokenCollectorError('invalid_token');
  }
  return token;
}

/**
 * Collect machine allowlist + short-lived access token under a branded scope.
 * Never logs the token.
 *
 * @param {unknown} scope
 * @param {{
 *   allowConfigPath?: string,
 *   readToken?: () => Promise<string>,
 *   macTokenPath?: string,
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
        return readMacTokenFile(options.macTokenPath);
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
