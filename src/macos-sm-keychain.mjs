import { spawn } from 'node:child_process';
import process from 'node:process';

/** Must match SM_MACHINE_TOKEN_PURPOSE in the token collector. */
export const MACOS_SM_KEYCHAIN_SERVICE =
  'bitwarden-agent-credential-bridge-sm-machine-token-v1';

/**
 * Same-user Keychain store for the SM machine access token.
 * `-A` (allow any application) matches Windows DPAPI: any same-user process
 * may read the item. This is not a distinct-writer claim.
 *
 * Commands go through `security -i` so the token is not on `ps` argv.
 */

export class MacosSmKeychainError extends Error {
  constructor(code) {
    super(`macOS SM keychain rejected: ${code}`);
    this.name = 'MacosSmKeychainError';
    this.code = code;
  }
}

const MACHINE_ID = /^[a-z][a-z0-9_-]{0,63}$/;
const SECURITY_BIN = '/usr/bin/security';

export function macosSmKeychainServiceName() {
  return MACOS_SM_KEYCHAIN_SERVICE;
}

function quoteSecurityWord(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * @param {string} script
 * @param {{
 *   runSecurity?: (script: string) => Promise<{ code: number, stdout: string, stderr: string }>,
 *   timeoutMs?: number,
 * }} [options]
 */
export async function runMacosSecurityInteractive(script, options = {}) {
  if (typeof options.runSecurity === 'function') {
    return options.runSecurity(script);
  }
  if (process.platform !== 'darwin') {
    throw new MacosSmKeychainError('unsupported_platform');
  }
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : 15000;
  return new Promise((resolve) => {
    const child = spawn(SECURITY_BIN, ['-i'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ code: 1, stdout, stderr: 'timeout' });
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve({ code: 1, stdout, stderr: 'spawn_failed' });
    });
    child.stdin.write(`${script}\n`);
    child.stdin.end();
  });
}

function assertMachineId(machineId) {
  if (typeof machineId !== 'string' || !MACHINE_ID.test(machineId)) {
    throw new MacosSmKeychainError('invalid_machine_id');
  }
}

function assertToken(token) {
  if (typeof token !== 'string' ||
      token.length < 16 ||
      token.length > 8192 ||
      /[\r\n]/.test(token)) {
    throw new MacosSmKeychainError('invalid_token');
  }
}

/**
 * @param {string} accessToken
 * @param {string} machineId
 * @param {{ runSecurity?: Function }} [options]
 */
export async function storeMacosKeychainToken(accessToken, machineId, options = {}) {
  assertToken(accessToken);
  assertMachineId(machineId);
  const service = quoteSecurityWord(macosSmKeychainServiceName());
  const account = quoteSecurityWord(machineId);
  const password = quoteSecurityWord(accessToken);
  const script = `add-generic-password -s ${service} -a ${account} -U -A -w ${password}`;
  let result;
  try {
    result = await runMacosSecurityInteractive(script, options);
  } catch {
    throw new MacosSmKeychainError('token_store_failed');
  }
  if (result.code !== 0) {
    throw new MacosSmKeychainError('token_store_failed');
  }
}

/**
 * @param {string} machineId
 * @param {{ runSecurity?: Function }} [options]
 * @returns {Promise<string>}
 */
export async function readMacosKeychainToken(machineId, options = {}) {
  assertMachineId(machineId);
  const service = quoteSecurityWord(macosSmKeychainServiceName());
  const account = quoteSecurityWord(machineId);
  const script = `find-generic-password -s ${service} -a ${account} -w`;
  let result;
  try {
    result = await runMacosSecurityInteractive(script, options);
  } catch {
    throw new MacosSmKeychainError('token_probe_failed');
  }
  if (result.code !== 0) {
    throw new MacosSmKeychainError('token_absent');
  }
  const token = String(result.stdout || '').replace(/^\uFEFF/, '').replace(/\r?\n$/, '');
  if (token.length < 16 || token.length > 8192 || /[\r\n]/.test(token)) {
    throw new MacosSmKeychainError('invalid_token');
  }
  return token;
}

/**
 * @param {string} machineId
 * @param {{ runSecurity?: Function }} [options]
 */
export async function deleteMacosKeychainToken(machineId, options = {}) {
  assertMachineId(machineId);
  const service = quoteSecurityWord(macosSmKeychainServiceName());
  const account = quoteSecurityWord(machineId);
  const script = `delete-generic-password -s ${service} -a ${account}`;
  let result;
  try {
    result = await runMacosSecurityInteractive(script, options);
  } catch {
    throw new MacosSmKeychainError('token_delete_failed');
  }
  // Absent item is success for uninstall (security uses 44 for not found).
  if (result.code !== 0 && result.code !== 44) {
    throw new MacosSmKeychainError('token_delete_failed');
  }
}

/**
 * Presence only. Never returns the password.
 * @param {string} machineId
 * @param {{ runSecurity?: Function }} [options]
 */
export async function macosKeychainTokenPresent(machineId, options = {}) {
  assertMachineId(machineId);
  const service = quoteSecurityWord(macosSmKeychainServiceName());
  const account = quoteSecurityWord(machineId);
  const script = `find-generic-password -s ${service} -a ${account}`;
  let result;
  try {
    result = await runMacosSecurityInteractive(script, options);
  } catch {
    return false;
  }
  return result.code === 0;
}
