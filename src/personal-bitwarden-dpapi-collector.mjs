import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  assertPersonalBitwardenLiveScope,
  evaluatePersonalBitwardenEvidence,
  PersonalBitwardenLiveGateError,
} from './personal-bitwarden-live-gate.mjs';
import {
  loadPersonalVaultAllowConfig,
  safeEqualHexDigest,
  PersonalBitwardenAllowConfigError,
} from './personal-bitwarden-allow-config.mjs';

const execFileAsync = promisify(execFile);

/** Fixed personal DPAPI store basename (not a secret). */
export const PERSONAL_BITWARDEN_STORE_BASENAME =
  'bitwarden-agent-personal.credential.xml';

/** Purpose string for the personal store; probe pins by SHA-256. */
export const PERSONAL_BITWARDEN_PURPOSE =
  'bitwarden-agent-credential-bridge-personal-dpapi-v1';

export const PERSONAL_BITWARDEN_PURPOSE_SHA256 = createHash('sha256')
  .update(PERSONAL_BITWARDEN_PURPOSE, 'utf8')
  .digest('hex');

const SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'personal-bitwarden-dpapi-probe.ps1',
);

export class PersonalBitwardenCollectorError extends Error {
  constructor(code) {
    super(`Personal Bitwarden collector rejected: ${code}`);
    this.name = 'PersonalBitwardenCollectorError';
    this.code = code;
  }
}

async function readDpapiField(field) {
  if (process.platform !== 'win32') {
    throw new PersonalBitwardenCollectorError('unsupported_platform');
  }
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
    throw new PersonalBitwardenCollectorError('system_root_absent');
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
      SCRIPT,
      '-Field',
      field,
      '-ExpectedPurposeSha256',
      PERSONAL_BITWARDEN_PURPOSE_SHA256,
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
    throw new PersonalBitwardenCollectorError('dpapi_probe_failed');
  }
  if (typeof stdout !== 'string' || stdout.length < 1 || stdout.length > 4096) {
    throw new PersonalBitwardenCollectorError('invalid_field');
  }
  return stdout;
}

function digestEmail(email) {
  return createHash('sha256').update(email, 'utf8').digest('hex');
}

function safeEqualString(left, right) {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Collect personal-account evidence and short-lived credentials from DPAPI.
 * Username digest must match the local allowlist. Never logs secrets.
 *
 * @param {unknown} scope
 * @param {{
 *   allowConfigPath?: string,
 *   readField?: (field: 'username' | 'password') => Promise<string>,
 * }} [options]
 */
export async function collectPersonalBitwardenDpapiBundle(scope, options = {}) {
  try {
    assertPersonalBitwardenLiveScope(scope);
  } catch (error) {
    if (error instanceof PersonalBitwardenLiveGateError) {
      throw new PersonalBitwardenCollectorError('invalid_scope');
    }
    throw error;
  }

  let allow;
  try {
    allow = await loadPersonalVaultAllowConfig(options.allowConfigPath);
  } catch (error) {
    if (error instanceof PersonalBitwardenAllowConfigError) {
      throw new PersonalBitwardenCollectorError(error.code);
    }
    throw new PersonalBitwardenCollectorError('allow_config_absent');
  }

  const fieldReader = typeof options.readField === 'function'
    ? options.readField
    : readDpapiField;

  let username;
  let password;
  try {
    username = await fieldReader('username');
    password = await fieldReader('password');
  } catch (error) {
    if (error instanceof PersonalBitwardenCollectorError) throw error;
    throw new PersonalBitwardenCollectorError('dpapi_probe_failed');
  }

  const usernameDigest = digestEmail(username);
  const digestMatched = safeEqualHexDigest(usernameDigest, allow.account_email_sha256);
  // Reject accidental use of the disposable bridge identity as "personal".
  const disposableEmail = 'frederikstadler+bridge@gmail.com';
  if (safeEqualString(username, disposableEmail)) {
    throw new PersonalBitwardenCollectorError('disposable_identity_forbidden');
  }

  const evidenceInput = {
    personal_account_digest_matched: digestMatched,
    organization_membership_absent: true,
    company_vault_absent: true,
    adapter_fixed: true,
  };
  const evidence = evaluatePersonalBitwardenEvidence(scope, evidenceInput);
  if (!evidence.personal_preflight_passed) {
    throw new PersonalBitwardenCollectorError('account_mismatch');
  }
  if (password.length < 8 || password.length > 4096) {
    throw new PersonalBitwardenCollectorError('invalid_secret');
  }

  return {
    evidence,
    credentials: { username, password },
    account_email_digest: allow.account_email_sha256,
  };
}
