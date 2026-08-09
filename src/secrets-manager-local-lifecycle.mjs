import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  defaultSecretsManagerAllowPath,
} from './secrets-manager-allow-config.mjs';
import {
  SM_MACHINE_TOKEN_PURPOSE,
  SM_MACHINE_TOKEN_STORE_BASENAME,
  defaultMacSecretsManagerTokenPath,
} from './secrets-manager-token-collector.mjs';
import { SM_DEFAULT_ALLOWED_PROJECT_IDS } from './secrets-manager-defaults.mjs';

const execFileAsync = promisify(execFile);

export class SecretsManagerLifecycleError extends Error {
  constructor(code) {
    super(`Secrets Manager local lifecycle rejected: ${code}`);
    this.name = 'SecretsManagerLifecycleError';
    this.code = code;
  }
}

const MACHINE_ID = /^[a-z][a-z0-9_-]{0,63}$/;

export function defaultWindowsTokenStorePath() {
  const home = process.env.USERPROFILE || os.homedir();
  return path.join(home, '.codex', 'secrets', SM_MACHINE_TOKEN_STORE_BASENAME);
}

/**
 * @param {{
 *   machine_id: string,
 *   allowed_project_ids?: string[],
 *   server_url?: string,
 *   api_url?: string,
 *   identity_url?: string,
 * }} input
 * @param {{ allowPath?: string }} [options]
 */
export async function writeSecretsManagerAllowConfig(input, options = {}) {
  if (typeof input.machine_id !== 'string' || !MACHINE_ID.test(input.machine_id)) {
    throw new SecretsManagerLifecycleError('invalid_machine_id');
  }
  const projectIds = Array.isArray(input.allowed_project_ids) &&
    input.allowed_project_ids.length > 0
    ? input.allowed_project_ids
    : [...SM_DEFAULT_ALLOWED_PROJECT_IDS];
  if (projectIds.length < 1 || projectIds.length > 16) {
    throw new SecretsManagerLifecycleError('invalid_project_ids');
  }
  /** @type {Record<string, unknown>} */
  const payload = {
    schema_version: 1,
    machine_id: input.machine_id,
    allowed_project_ids: projectIds.map((id) => id.toLowerCase()),
  };
  if (typeof input.server_url === 'string' && input.server_url.length > 0) {
    payload.server_url = input.server_url;
  }
  if (typeof input.api_url === 'string' && typeof input.identity_url === 'string') {
    payload.api_url = input.api_url;
    payload.identity_url = input.identity_url;
  } else if (input.api_url !== undefined || input.identity_url !== undefined) {
    throw new SecretsManagerLifecycleError('invalid_endpoints');
  }
  // Validate by round-tripping through loader rules via JSON write + parse path.
  const allowPath = options.allowPath ?? defaultSecretsManagerAllowPath();
  await fs.mkdir(path.dirname(allowPath), { recursive: true });
  const body = `${JSON.stringify(payload, null, 2)}\n`;
  await fs.writeFile(allowPath, body, { encoding: 'utf8', mode: 0o600 });
  try {
    const { loadSecretsManagerAllowConfig } = await import('./secrets-manager-allow-config.mjs');
    await loadSecretsManagerAllowConfig(allowPath);
  } catch {
    await fs.unlink(allowPath).catch(() => {});
    throw new SecretsManagerLifecycleError('invalid_endpoints');
  }
  return {
    path: allowPath,
    machine_id: input.machine_id,
    project_count: projectIds.length,
    cloud_default: payload.server_url === undefined && payload.api_url === undefined,
  };
}

/**
 * Store access token locally. Never logs the token.
 * Windows: DPAPI Clixml via repo probe. macOS: owner-only token file.
 *
 * @param {{
 *   accessToken: string,
 *   machine_id: string,
 *   storeToken?: (token: string, machineId: string) => Promise<void>,
 * }} options
 */
export async function storeSecretsManagerAccessToken(options) {
  if (typeof options.accessToken !== 'string' ||
      options.accessToken.length < 16 ||
      options.accessToken.length > 8192 ||
      /[\r\n]/.test(options.accessToken)) {
    throw new SecretsManagerLifecycleError('invalid_token');
  }
  if (typeof options.machine_id !== 'string' || !MACHINE_ID.test(options.machine_id)) {
    throw new SecretsManagerLifecycleError('invalid_machine_id');
  }
  if (typeof options.storeToken === 'function') {
    await options.storeToken(options.accessToken, options.machine_id);
    return { stored: true, platform: process.platform };
  }
  if (process.platform === 'win32') {
    await storeWindowsDpapiToken(options.accessToken, options.machine_id);
    return { stored: true, platform: 'win32' };
  }
  if (process.platform === 'darwin') {
    await storeMacTokenFile(options.accessToken);
    return { stored: true, platform: 'darwin' };
  }
  throw new SecretsManagerLifecycleError('unsupported_platform');
}

async function storeWindowsDpapiToken(accessToken, machineId) {
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
    throw new SecretsManagerLifecycleError('system_root_absent');
  }
  const powershell = path.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  const script = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'scripts',
    'secrets-manager-token-dpapi-store.ps1',
  );
  const result = await new Promise((resolve) => {
    const child = spawn(powershell, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', script,
      '-MachineId', machineId,
      '-Purpose', SM_MACHINE_TOKEN_PURPOSE,
    ], {
      windowsHide: true,
      env: {
        SystemRoot: systemRoot,
        USERPROFILE: process.env.USERPROFILE,
        LOCALAPPDATA: process.env.LOCALAPPDATA,
        windir: process.env.windir,
        PATH: process.env.PATH,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ code: 1, stdout, stderr: 'timeout' });
    }, 20000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    child.stdin.write(`${accessToken}\n`);
    child.stdin.end();
  });
  if (result.code !== 0 ||
      (typeof result.stderr === 'string' && result.stderr.trim().length > 0) ||
      (typeof result.stdout === 'string' && result.stdout.trim().length > 0)) {
    throw new SecretsManagerLifecycleError('token_store_failed');
  }
}

async function storeMacTokenFile(accessToken) {
  const tokenPath = defaultMacSecretsManagerTokenPath();
  await fs.mkdir(path.dirname(tokenPath), { recursive: true, mode: 0o700 });
  await fs.writeFile(tokenPath, `${accessToken}\n`, { encoding: 'utf8', mode: 0o600 });
}

/**
 * Remove local SM allowlist + token artifacts. Continues after individual misses.
 */
export async function uninstallSecretsManagerLocalState(options = {}) {
  const allowPath = options.allowPath ?? defaultSecretsManagerAllowPath();
  const tokenPath = options.tokenPath ?? (
    process.platform === 'darwin'
      ? defaultMacSecretsManagerTokenPath()
      : defaultWindowsTokenStorePath()
  );
  const removed = {
    allow_config_removed: false,
    token_store_removed: false,
  };
  try {
    await fs.unlink(allowPath);
    removed.allow_config_removed = true;
  } catch {
    // absent is success for uninstall
  }
  try {
    await fs.unlink(tokenPath);
    removed.token_store_removed = true;
  } catch {
    // absent is success
  }
  // Prove absence
  const allowAbsent = !(await pathExists(allowPath));
  const tokenAbsent = !(await pathExists(tokenPath));
  return Object.freeze({
    ...removed,
    allow_config_absent: allowAbsent,
    token_store_absent: tokenAbsent,
    uninstall_complete: allowAbsent && tokenAbsent,
    helper_vault_free: true,
    authorization_ready: false,
  });
}

export async function inspectSecretsManagerLocalState(options = {}) {
  const allowPath = options.allowPath ?? defaultSecretsManagerAllowPath();
  const tokenPath = options.tokenPath ?? (
    process.platform === 'darwin'
      ? defaultMacSecretsManagerTokenPath()
      : defaultWindowsTokenStorePath()
  );
  return Object.freeze({
    allow_config_present: await pathExists(allowPath),
    token_store_present: await pathExists(tokenPath),
    platform: process.platform,
    authorization_ready: false,
    helper_vault_free: true,
  });
}

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check that `bws` is runnable. Never returns token/secret data.
 */
export async function checkBwsAvailable(options = {}) {
  const bwsPath = options.bwsPath ?? 'bws';
  const run = typeof options.runCommand === 'function'
    ? options.runCommand
    : async (exe, args) => {
      const result = await execFileAsync(exe, args, {
        windowsHide: true,
        timeout: 10000,
        maxBuffer: 64 * 1024,
        encoding: 'utf8',
        env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
      });
      return result.stdout;
    };
  try {
    await run(bwsPath, ['--version']);
    return Object.freeze({ bws_available: true });
  } catch {
    return Object.freeze({ bws_available: false });
  }
}
