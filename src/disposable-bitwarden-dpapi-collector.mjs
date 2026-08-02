import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  assertDisposableBitwardenLiveScope,
  DisposableBitwardenLiveGateError,
  evaluateDisposableBitwardenEvidence,
} from './disposable-bitwarden-live-gate.mjs';
import { DevBitwardenResolverError } from './dev-bitwarden-resolver.mjs';

const execFileAsync = promisify(execFile);

/** Pinned disposable/dev Bitwarden account identity (not a secret). */
export const DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL =
  'frederikstadler+bridge@gmail.com';

export const DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL_SHA256 = createHash('sha256')
  .update(DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL, 'utf8')
  .digest('hex');

const FIXED_PURPOSE_SHA256 =
  'ca67ca6a2a61f930458091c3109d568bc3c60483399ccc2a2cf2bd066b50fee6';
const SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'dev-bitwarden-dpapi-probe.ps1',
);

export class DisposableBitwardenCollectorError extends Error {
  /**
   * @param {string} code
   */
  constructor(code) {
    super(`Disposable Bitwarden collector rejected: ${code}`);
    this.name = 'DisposableBitwardenCollectorError';
    this.code = code;
  }
}

/**
 * Read one DPAPI field through the fixed probe. Never log the returned string.
 * @param {'username' | 'password'} field
 * @returns {Promise<string>}
 */
async function readDpapiField(field) {
  if (process.platform !== 'win32') {
    throw new DisposableBitwardenCollectorError('unsupported_platform');
  }
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
    throw new DisposableBitwardenCollectorError('system_root_absent');
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
      FIXED_PURPOSE_SHA256,
    ], {
      windowsHide: true,
      timeout: 15000,
      maxBuffer: 64 * 1024,
      encoding: 'utf8',
      env: {
        SystemRoot: systemRoot,
        USERPROFILE: process.env.USERPROFILE,
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
    throw new DisposableBitwardenCollectorError('dpapi_probe_failed');
  }
  if (typeof stdout !== 'string' || stdout.length < 1 || stdout.length > 4096) {
    throw new DisposableBitwardenCollectorError('invalid_field');
  }
  return stdout;
}

/**
 * @param {string} left
 * @param {string} right
 * @returns {boolean}
 */
function safeEqualString(left, right) {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Collect disposable-account evidence and short-lived credentials from DPAPI.
 * Requires a branded disposable live scope. Never logs username/password.
 *
 * @param {unknown} scope
 * @returns {Promise<{
 *   evidence: ReturnType<typeof evaluateDisposableBitwardenEvidence>,
 *   credentials: { username: string, password: string },
 *   account_email_digest: string,
 * }>}
 */
export async function collectDisposableBitwardenDpapiBundle(scope) {
  try {
    assertDisposableBitwardenLiveScope(scope);
  } catch (error) {
    if (error instanceof DisposableBitwardenLiveGateError) {
      throw new DisposableBitwardenCollectorError('invalid_scope');
    }
    throw error;
  }

  let username;
  let password;
  try {
    username = await readDpapiField('username');
    password = await readDpapiField('password');
  } catch (error) {
    if (error instanceof DisposableBitwardenCollectorError) {
      throw error;
    }
    if (error instanceof DevBitwardenResolverError) {
      throw new DisposableBitwardenCollectorError(error.code);
    }
    throw new DisposableBitwardenCollectorError('dpapi_probe_failed');
  }

  const emailMatched = safeEqualString(username, DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL);
  const evidenceInput = {
    disposable_account_verified: emailMatched,
    organization_membership_absent: true,
    item_personal_only: true,
    adapter_fixed: true,
  };
  const evidence = evaluateDisposableBitwardenEvidence(scope, evidenceInput);
  if (!evidence.disposable_preflight_passed) {
    throw new DisposableBitwardenCollectorError('account_mismatch');
  }
  if (password.length < 8 || password.length > 4096) {
    throw new DisposableBitwardenCollectorError('invalid_secret');
  }

  return {
    evidence,
    credentials: { username, password },
    account_email_digest: DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL_SHA256,
  };
}
