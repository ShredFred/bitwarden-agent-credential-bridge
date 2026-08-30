import { execFile, execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  defaultSecretsManagerAllowPath,
  loadSecretsManagerAllowConfig,
  SecretsManagerAllowConfigError,
} from './secrets-manager-allow-config.mjs';
import {
  SM_MACHINE_TOKEN_PURPOSE,
  SM_MACHINE_TOKEN_STORE_BASENAME,
  defaultMacSecretsManagerTokenPath,
} from './secrets-manager-token-collector.mjs';
import {
  MacosSmKeychainError,
  deleteMacosKeychainToken,
  macosKeychainTokenPresent,
  readMacosKeychainToken,
  storeMacosKeychainToken,
} from './macos-sm-keychain.mjs';
import {
  LinuxSmTokenFileError,
  defaultLinuxSecretsManagerTokenPath,
  deleteLinuxOwnerOnlyToken,
  linuxOwnerOnlyTokenPresent,
  storeLinuxOwnerOnlyToken,
} from './linux-sm-token-file.mjs';
import { SM_DEFAULT_ALLOWED_PROJECT_IDS } from './secrets-manager-defaults.mjs';
import { linuxBwsCandidatePaths, macosBwsCandidatePaths, resolveBwsExecutable } from './secrets-manager-bws-adapter.mjs';

const execFileAsync = promisify(execFile);

export class SecretsManagerLifecycleError extends Error {
  constructor(code) {
    super(`Secrets Manager local lifecycle rejected: ${code}`);
    this.name = 'SecretsManagerLifecycleError';
    this.code = code;
  }
}

const MACHINE_ID = /^[a-z][a-z0-9_-]{0,63}$/;

/** DHCP/ISP labels that must not become a machine id. */
const ISP_MACHINE_LABELS = new Set([
  'vodafone', 'telekom', 'unitymedia', 'kabelbw', 'o2', '1und1', 'easybox',
  'fritz', 'fritzbox', 'dhcp', 'gateway', 'router',
  'local', 'lan', 'home', 'corp', 'internal',
]);

/**
 * Build a local machine_id from a user-facing name, never from ISP DNS.
 * @param {string} raw
 * @returns {string} slug without `pc-` prefix, possibly empty
 */
export function slugSecretsManagerMachineLabel(raw) {
  if (typeof raw !== 'string' || raw.length < 1) return '';
  const parts = raw
    .toLowerCase()
    .replace(/[''`]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .split('-')
    .filter((part) => part.length > 0 && !ISP_MACHINE_LABELS.has(part));
  return parts.join('-').replace(/^-+|-+$/g, '').slice(0, 48);
}

function readMacosScutilName(key) {
  try {
    const out = execFileSync('/usr/sbin/scutil', ['--get', key], {
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return typeof out === 'string' ? out.trim() : '';
  } catch {
    return '';
  }
}

/**
 * Suggested same-user machine_id. Prefers the Mac ComputerName over DHCP
 * hostnames such as `*.home.vodafone`.
 *
 * @param {{
 *   platform?: NodeJS.Platform,
 *   computerName?: string,
 *   localHostName?: string,
 *   hostname?: string,
 * }} [options]
 */
export function defaultSecretsManagerMachineId(options = {}) {
  const platform = options.platform ?? process.platform;
  const hints = [];
  if (typeof options.computerName === 'string') hints.push(options.computerName);
  if (typeof options.localHostName === 'string') hints.push(options.localHostName);
  if (typeof options.hostname === 'string') hints.push(options.hostname);
  if (hints.length === 0) {
    if (platform === 'darwin') {
      hints.push(readMacosScutilName('ComputerName'));
      hints.push(readMacosScutilName('LocalHostName'));
    }
    if (platform === 'win32' && typeof process.env.COMPUTERNAME === 'string') {
      hints.push(process.env.COMPUTERNAME);
    }
    if (platform === 'linux' && typeof process.env.HOSTNAME === 'string') {
      hints.push(process.env.HOSTNAME);
    }
    hints.push(os.hostname() || '');
  }
  for (const hint of hints) {
    const slug = slugSecretsManagerMachineLabel(hint);
    if (slug.length > 0) {
      const id = `pc-${slug}`.slice(0, 64);
      if (MACHINE_ID.test(id)) return id;
    }
  }
  return 'pc-local';
}

export function defaultWindowsTokenStorePath() {
  const home = process.env.USERPROFILE || os.homedir();
  return path.join(home, '.codex', 'secrets', SM_MACHINE_TOKEN_STORE_BASENAME);
}

function defaultTokenStorePath() {
  if (process.platform === 'darwin') {
    return defaultMacSecretsManagerTokenPath();
  }
  if (process.platform === 'linux') {
    return defaultLinuxSecretsManagerTokenPath();
  }
  return defaultWindowsTokenStorePath();
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
 * Windows: DPAPI Clixml via repo probe. macOS: same-user Keychain item.
 * Linux: owner-only 0600 file under XDG config.
 *
 * @param {{
 *   accessToken: string,
 *   machine_id: string,
 *   storeToken?: (token: string, machineId: string) => Promise<void>,
 *   runSecurity?: Function,
 *   tokenPath?: string,
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
    try {
      await storeMacosKeychainToken(options.accessToken, options.machine_id, {
        runSecurity: options.runSecurity,
      });
    } catch (error) {
      if (error instanceof MacosSmKeychainError) {
        throw new SecretsManagerLifecycleError(error.code);
      }
      throw new SecretsManagerLifecycleError('token_store_failed');
    }
    return { stored: true, platform: 'darwin' };
  }
  if (process.platform === 'linux') {
    try {
      await storeLinuxOwnerOnlyToken(options.accessToken, {
        tokenPath: options.tokenPath,
      });
    } catch (error) {
      if (error instanceof LinuxSmTokenFileError) {
        throw new SecretsManagerLifecycleError(error.code);
      }
      throw new SecretsManagerLifecycleError('token_store_failed');
    }
    return { stored: true, platform: 'linux' };
  }
  throw new SecretsManagerLifecycleError('unsupported_platform');
}

/**
 * Rename the local machine_id. macOS re-homes the Keychain item. Linux keeps
 * the owner-only token file and rewrites the allowlist id. Never prints the token.
 *
 * @param {string} newMachineId
 * @param {{
 *   allowPath?: string,
 *   runSecurity?: Function,
 *   platform?: NodeJS.Platform,
 *   tokenPath?: string,
 * }} [options]
 */
export async function renameSecretsManagerMachineId(newMachineId, options = {}) {
  if (typeof newMachineId !== 'string' || !MACHINE_ID.test(newMachineId)) {
    throw new SecretsManagerLifecycleError('invalid_machine_id');
  }
  const platform = options.platform ?? process.platform;
  if (platform !== 'darwin' && platform !== 'linux') {
    throw new SecretsManagerLifecycleError('unsupported_platform');
  }
  const allowPath = options.allowPath ?? defaultSecretsManagerAllowPath();
  let allow;
  try {
    allow = await loadSecretsManagerAllowConfig(allowPath);
  } catch (error) {
    if (error instanceof SecretsManagerAllowConfigError) {
      throw new SecretsManagerLifecycleError(error.code);
    }
    throw new SecretsManagerLifecycleError('allow_config_absent');
  }
  const previous = allow.machine_id;
  if (previous === newMachineId) {
    return Object.freeze({
      ok: true,
      renamed: false,
      machine_id: previous,
      authorization_ready: false,
    });
  }
  /** @type {Record<string, unknown>} */
  const next = {
    machine_id: newMachineId,
    allowed_project_ids: [...allow.allowed_project_ids],
  };
  if (typeof allow.server_url === 'string') next.server_url = allow.server_url;
  if (typeof allow.api_url === 'string' && typeof allow.identity_url === 'string') {
    next.api_url = allow.api_url;
    next.identity_url = allow.identity_url;
  }

  if (platform === 'linux') {
    const tokenPath = options.tokenPath ?? defaultLinuxSecretsManagerTokenPath();
    const present = await linuxOwnerOnlyTokenPresent({ tokenPath });
    if (!present) {
      throw new SecretsManagerLifecycleError('token_store_absent');
    }
    await writeSecretsManagerAllowConfig(next, { allowPath });
    return Object.freeze({
      ok: true,
      renamed: true,
      machine_id: newMachineId,
      previous_machine_id: previous,
      authorization_ready: false,
      helper_vault_free: true,
    });
  }

  let token;
  try {
    token = await readMacosKeychainToken(previous, { runSecurity: options.runSecurity });
  } catch (error) {
    if (error instanceof MacosSmKeychainError) {
      throw new SecretsManagerLifecycleError(error.code);
    }
    throw new SecretsManagerLifecycleError('token_probe_failed');
  }
  await writeSecretsManagerAllowConfig(next, { allowPath });
  try {
    await storeMacosKeychainToken(token, newMachineId, { runSecurity: options.runSecurity });
  } catch (error) {
    await writeSecretsManagerAllowConfig({
      ...next,
      machine_id: previous,
    }, { allowPath }).catch(() => {});
    throw error instanceof MacosSmKeychainError
      ? new SecretsManagerLifecycleError(error.code)
      : new SecretsManagerLifecycleError('token_store_failed');
  }
  await deleteMacosKeychainToken(previous, { runSecurity: options.runSecurity }).catch(() => {});
  return Object.freeze({
    ok: true,
    renamed: true,
    machine_id: newMachineId,
    previous_machine_id: previous,
    authorization_ready: false,
    helper_vault_free: true,
  });
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

/**
 * Remove local SM allowlist + token artifacts. Continues after individual misses.
 * macOS deletes the Keychain item and any leftover 0600 token file.
 * Linux deletes the owner-only XDG token file.
 */
export async function uninstallSecretsManagerLocalState(options = {}) {
  const allowPath = options.allowPath ?? defaultSecretsManagerAllowPath();
  const leftoverPath = options.tokenPath ?? defaultTokenStorePath();
  const useKeychain = process.platform === 'darwin' && options.tokenPath === undefined;
  const useLinuxFile = process.platform === 'linux' && options.tokenPath === undefined;

  let machineId = typeof options.machine_id === 'string' ? options.machine_id : null;
  if (!machineId) {
    try {
      const allow = await loadSecretsManagerAllowConfig(allowPath);
      machineId = allow.machine_id;
    } catch {
      machineId = null;
    }
  }

  const removed = {
    allow_config_removed: false,
    token_store_removed: false,
  };

  let skipAllowUnlink = false;
  if (typeof options.machine_id === 'string') {
    try {
      const existing = await loadSecretsManagerAllowConfig(allowPath);
      if (existing.machine_id !== options.machine_id) {
        skipAllowUnlink = true;
      }
    } catch {
      // absent or invalid allowlist: safe to unlink
    }
  }

  if (useKeychain && typeof machineId === 'string') {
    try {
      await deleteMacosKeychainToken(machineId, { runSecurity: options.runSecurity });
      removed.token_store_removed = true;
    } catch {
      // continue; leftover file and allowlist still removed
    }
  }
  if (useLinuxFile) {
    try {
      await deleteLinuxOwnerOnlyToken();
      removed.token_store_removed = true;
    } catch {
      // continue
    }
  }

  try {
    if (!skipAllowUnlink) {
      await fs.unlink(allowPath);
      removed.allow_config_removed = true;
    }
  } catch {
    // absent is success for uninstall
  }
  try {
    await fs.unlink(leftoverPath);
    if (!useKeychain && !useLinuxFile) {
      removed.token_store_removed = true;
    }
  } catch {
    // absent is success
  }

  const allowAbsent = !(await pathExists(allowPath));
  let tokenAbsent = !(await pathExists(leftoverPath));
  if (useKeychain && typeof machineId === 'string') {
    const keychainPresent = await macosKeychainTokenPresent(machineId, {
      runSecurity: options.runSecurity,
    });
    tokenAbsent = tokenAbsent && !keychainPresent;
  }
  if (useLinuxFile) {
    tokenAbsent = tokenAbsent && !(await linuxOwnerOnlyTokenPresent());
  }
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
  const leftoverPath = options.tokenPath ?? defaultTokenStorePath();
  const useKeychain = process.platform === 'darwin' && options.tokenPath === undefined;
  const useLinuxFile = process.platform === 'linux' && options.tokenPath === undefined;
  let tokenStorePresent = await pathExists(leftoverPath);
  if (useKeychain) {
    let machineId = typeof options.machine_id === 'string' ? options.machine_id : null;
    if (!machineId) {
      try {
        const allow = await loadSecretsManagerAllowConfig(allowPath);
        machineId = allow.machine_id;
      } catch {
        machineId = null;
      }
    }
    if (typeof machineId === 'string') {
      tokenStorePresent = await macosKeychainTokenPresent(machineId, {
        runSecurity: options.runSecurity,
      });
    } else {
      tokenStorePresent = false;
    }
  }
  if (useLinuxFile) {
    tokenStorePresent = await linuxOwnerOnlyTokenPresent();
  }
  return Object.freeze({
    allow_config_present: await pathExists(allowPath),
    token_store_present: tokenStorePresent,
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
  const bwsPath = resolveBwsExecutable(options);
  const run = typeof options.runCommand === 'function'
    ? options.runCommand
    : async (exe, args) => {
      const result = await execFileAsync(exe, args, {
        windowsHide: true,
        timeout: 10000,
        maxBuffer: 64 * 1024,
        encoding: 'utf8',
        env: {
          Path: process.env.Path || process.env.PATH,
          PATH: process.platform === 'darwin' || process.platform === 'linux'
            ? `${[...macosBwsCandidatePaths(), ...linuxBwsCandidatePaths()]
              .map((filePath) => path.dirname(filePath))
              .join(':')}:${process.env.PATH || ''}`
            : (process.env.PATH || process.env.Path),
          HOME: process.env.HOME,
          SystemRoot: process.env.SystemRoot,
        },
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
