/**
 * Agent-blind local secret → Secrets Manager import.
 *
 * Reads DPAPI / ConvertFrom-SecureString / .env sources via a bounded probe,
 * upserts into allowlisted SM projects, and never returns secret values.
 * Local purge is deliberately disabled until digest-verified apply succeeds
 * under a separate future flag.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { isProjectAllowed } from './secrets-manager-allow-config.mjs';
import {
  fetchSecretsManagerSecretValue,
  upsertSecretsManagerSecret,
  SecretsManagerBwsAdapterError,
} from './secrets-manager-bws-adapter.mjs';
import {
  SM_DEFAULT_PROJECTS,
  SM_WRITE_APPROVAL_FLAG,
} from './secrets-manager-defaults.mjs';

const execFileAsync = promisify(execFile);

const PROBE_SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'local-secret-extract-probe.ps1',
);

const SECRET_KEY = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;
const ENTRY_ID = /^[a-z][a-z0-9_]{1,127}$/;
const EXTRACT_MODES = new Set([
  'api_key_password',
  'api_secret_password',
  'account_username',
  'account_password',
  'top_username',
  'top_password',
  'nested_username',
  'nested_password',
  'secure_string_file',
  'env_var',
]);

export class LocalSecretToSmError extends Error {
  constructor(code) {
    super(`Local secret→SM import rejected: ${code}`);
    this.name = 'LocalSecretToSmError';
    this.code = code;
  }
}

/**
 * @param {unknown} raw
 */
export function validateLocalToSmImportManifest(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new LocalSecretToSmError('manifest_invalid');
  }
  const obj = /** @type {Record<string, unknown>} */ (raw);
  if (obj.version !== 1) {
    throw new LocalSecretToSmError('manifest_version');
  }
  if (!Array.isArray(obj.entries) || obj.entries.length < 1 || obj.entries.length > 512) {
    throw new LocalSecretToSmError('manifest_entries');
  }

  const ids = new Set();
  const smKeysByProject = new Map();
  /** @type {object[]} */
  const entries = [];

  for (const entry of obj.entries) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new LocalSecretToSmError('entry_invalid');
    }
    const e = /** @type {Record<string, unknown>} */ (entry);
    if (typeof e.id !== 'string' || !ENTRY_ID.test(e.id)) {
      throw new LocalSecretToSmError('entry_id_invalid');
    }
    if (ids.has(e.id)) {
      throw new LocalSecretToSmError('entry_id_duplicate');
    }
    ids.add(e.id);

    if (e.project !== 'mivia' && e.project !== 'private-hq') {
      throw new LocalSecretToSmError('entry_project_invalid');
    }
    if (typeof e.sm_secret_key !== 'string' || !SECRET_KEY.test(e.sm_secret_key)) {
      throw new LocalSecretToSmError('entry_sm_key_invalid');
    }

    const projectId = e.project === 'mivia'
      ? SM_DEFAULT_PROJECTS.mivia
      : SM_DEFAULT_PROJECTS.private_hq;
    if (!smKeysByProject.has(projectId)) smKeysByProject.set(projectId, new Set());
    const keySet = smKeysByProject.get(projectId);
    if (keySet.has(e.sm_secret_key)) {
      throw new LocalSecretToSmError('entry_sm_key_duplicate');
    }
    keySet.add(e.sm_secret_key);

    if (e.source === null || typeof e.source !== 'object' || Array.isArray(e.source)) {
      throw new LocalSecretToSmError('entry_source_invalid');
    }
    const source = /** @type {Record<string, unknown>} */ (e.source);
    if (source.kind !== 'clixml' && source.kind !== 'secure_string_file' && source.kind !== 'env_file') {
      throw new LocalSecretToSmError('entry_source_kind');
    }
    if (typeof source.extract !== 'string' || !EXTRACT_MODES.has(source.extract)) {
      throw new LocalSecretToSmError('entry_extract_invalid');
    }
    if (source.kind === 'env_file') {
      if (source.extract !== 'env_var') {
        throw new LocalSecretToSmError('entry_extract_invalid');
      }
      if (typeof source.path !== 'string' || source.path.length < 1 || source.path.length > 512) {
        throw new LocalSecretToSmError('entry_source_path');
      }
      if (typeof source.var !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(source.var)) {
        throw new LocalSecretToSmError('entry_env_var');
      }
    } else {
      if (typeof source.basename !== 'string' ||
          source.basename.length < 1 ||
          source.basename.length > 256 ||
          source.basename.includes('/') ||
          source.basename.includes('\\') ||
          source.basename.includes('..')) {
        throw new LocalSecretToSmError('entry_basename_invalid');
      }
      if (source.kind === 'secure_string_file' && source.extract !== 'secure_string_file') {
        throw new LocalSecretToSmError('entry_extract_invalid');
      }
      if (source.kind === 'clixml' && source.extract === 'secure_string_file') {
        throw new LocalSecretToSmError('entry_extract_invalid');
      }
      if (source.kind === 'clixml' && source.extract === 'env_var') {
        throw new LocalSecretToSmError('entry_extract_invalid');
      }
    }
    if (source.expected_purpose !== undefined &&
        (typeof source.expected_purpose !== 'string' ||
          source.expected_purpose.length < 1 ||
          source.expected_purpose.length > 256)) {
      throw new LocalSecretToSmError('entry_purpose_invalid');
    }

    entries.push(Object.freeze({
      id: e.id,
      project: e.project,
      project_id: projectId,
      sm_secret_key: e.sm_secret_key,
      source: Object.freeze({ ...source }),
    }));
  }

  return Object.freeze({
    version: 1,
    entries: Object.freeze(entries),
  });
}

export async function loadLocalToSmImportManifest(filePath) {
  let raw;
  try {
    raw = JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch {
    throw new LocalSecretToSmError('manifest_unreadable');
  }
  return validateLocalToSmImportManifest(raw);
}

function defaultSecretsDir() {
  return path.join(os.homedir(), '.codex', 'secrets');
}

/**
 * @param {object} entry
 * @param {{ secretsDir?: string }} [options]
 */
export function resolveLocalSecretSourcePath(entry, options = {}) {
  const secretsDir = typeof options.secretsDir === 'string' && options.secretsDir.length > 0
    ? options.secretsDir
    : defaultSecretsDir();
  if (entry.source.kind === 'env_file') {
    return path.resolve(entry.source.path);
  }
  return path.join(secretsDir, entry.source.basename);
}

async function readEnvFileVar(filePath, varName) {
  let text;
  try {
    text = await fs.readFile(filePath, 'utf8');
  } catch {
    throw new LocalSecretToSmError('store_absent');
  }
  if (text.length > 256 * 1024) {
    throw new LocalSecretToSmError('store_unreadable');
  }
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length < 1 || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 1) continue;
    const key = trimmed.slice(0, eq).trim();
    if (key !== varName) continue;
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (value.length < 1 || value.length > 4096) {
      throw new LocalSecretToSmError('value_empty');
    }
    return value;
  }
  throw new LocalSecretToSmError('field_absent');
}

/**
 * @param {object} entry
 * @param {{ secretsDir?: string, probeScript?: string }} [options]
 * @returns {Promise<string>}
 */
export async function extractLocalSecretValue(entry, options = {}) {
  const storePath = resolveLocalSecretSourcePath(entry, options);
  if (entry.source.kind === 'env_file') {
    return readEnvFileVar(storePath, entry.source.var);
  }

  if (process.platform !== 'win32') {
    throw new LocalSecretToSmError('unsupported_platform');
  }
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
    throw new LocalSecretToSmError('system_root_absent');
  }
  const powershell = path.join(
    systemRoot,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
  const script = typeof options.probeScript === 'string' && options.probeScript.length > 0
    ? options.probeScript
    : PROBE_SCRIPT;

  const args = [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    script,
    '-StorePath',
    storePath,
    '-Extract',
    entry.source.extract,
  ];
  if (typeof entry.source.expected_purpose === 'string' &&
      entry.source.expected_purpose.length > 0) {
    args.push('-ExpectedPurpose', entry.source.expected_purpose);
  }

  let stdout = '';
  let stderr = '';
  let code = 1;
  try {
    const result = await execFileAsync(powershell, args, {
      windowsHide: true,
      timeout: 20000,
      maxBuffer: 16 * 1024,
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

  if (code !== 0) {
    const mapped = typeof stderr === 'string' && /^[a-z_]+$/.test(stderr.trim())
      ? stderr.trim()
      : 'probe_failed';
    throw new LocalSecretToSmError(mapped);
  }
  if (typeof stderr === 'string' && stderr.length > 0) {
    throw new LocalSecretToSmError('probe_failed');
  }
  if (typeof stdout !== 'string' || stdout.length < 1 || stdout.length > 4096) {
    throw new LocalSecretToSmError('value_empty');
  }
  return stdout;
}

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * @param {{
 *   manifest: ReturnType<typeof validateLocalToSmImportManifest>,
 *   mode: 'dry_run' | 'apply',
 *   accessToken?: string,
 *   allowConfig?: object,
 *   secretsDir?: string,
 *   extractValue?: typeof extractLocalSecretValue,
 *   upsertSecret?: typeof upsertSecretsManagerSecret,
 *   fetchSecret?: typeof fetchSecretsManagerSecretValue,
 *   purgeLocal?: boolean,
 * }} options
 */
export async function runLocalToSmImport(options) {
  if (options.mode !== 'dry_run' && options.mode !== 'apply') {
    throw new LocalSecretToSmError('mode_invalid');
  }
  if (options.purgeLocal === true) {
    // Purge is intentionally unavailable until a later hardened gate.
    throw new LocalSecretToSmError('purge_disabled');
  }

  const extract = typeof options.extractValue === 'function'
    ? options.extractValue
    : extractLocalSecretValue;
  const upsert = typeof options.upsertSecret === 'function'
    ? options.upsertSecret
    : upsertSecretsManagerSecret;
  const fetchSecret = typeof options.fetchSecret === 'function'
    ? options.fetchSecret
    : fetchSecretsManagerSecretValue;

  if (options.mode === 'apply') {
    if (typeof options.accessToken !== 'string' || options.accessToken.length < 16) {
      throw new LocalSecretToSmError('token_required');
    }
    if (options.allowConfig === null || typeof options.allowConfig !== 'object') {
      throw new LocalSecretToSmError('allow_required');
    }
  }

  /** @type {object[]} */
  const results = [];
  let ready = 0;
  let written = 0;
  let verified = 0;
  let failed = 0;

  for (const entry of options.manifest.entries) {
    const storePath = resolveLocalSecretSourcePath(entry, {
      secretsDir: options.secretsDir,
    });
    /** @type {Record<string, unknown>} */
    const row = {
      id: entry.id,
      project: entry.project,
      sm_secret_key: entry.sm_secret_key,
      source_kind: entry.source.kind,
      source_basename: entry.source.basename ?? null,
      source_present: false,
      extract_ok: false,
      would_write: false,
      written: false,
      digest_match: false,
      purge_eligible: false,
      local_deleted: false,
      code: 'ok',
    };

    try {
      await fs.access(storePath);
      row.source_present = true;
    } catch {
      row.code = 'store_absent';
      failed += 1;
      results.push(Object.freeze(row));
      continue;
    }

    let value;
    try {
      value = await extract(entry, { secretsDir: options.secretsDir });
      row.extract_ok = true;
      row.would_write = true;
    } catch (error) {
      row.code = error instanceof LocalSecretToSmError ? error.code : 'extract_failed';
      failed += 1;
      results.push(Object.freeze(row));
      continue;
    }

    if (options.mode === 'dry_run') {
      ready += 1;
      // Never retain extracted values beyond the presence check.
      value = undefined;
      results.push(Object.freeze(row));
      continue;
    }

    if (!isProjectAllowed(options.allowConfig, entry.project_id)) {
      row.code = 'project_not_allowed';
      failed += 1;
      value = undefined;
      results.push(Object.freeze(row));
      continue;
    }

    try {
      await upsert({
        accessToken: options.accessToken,
        projectId: entry.project_id,
        secretKey: entry.sm_secret_key,
        secretValue: value,
        allowConfig: options.allowConfig,
      });
      row.written = true;
      written += 1;
    } catch (error) {
      row.code = error instanceof SecretsManagerBwsAdapterError
        ? error.code
        : 'upsert_failed';
      failed += 1;
      value = undefined;
      results.push(Object.freeze(row));
      continue;
    }

    try {
      const remote = await fetchSecret({
        accessToken: options.accessToken,
        projectId: entry.project_id,
        secretKey: entry.sm_secret_key,
        allowConfig: options.allowConfig,
      });
      row.digest_match = sha256Hex(value) === sha256Hex(remote);
      if (row.digest_match) {
        verified += 1;
        row.purge_eligible = true;
        ready += 1;
      } else {
        row.code = 'digest_mismatch';
        failed += 1;
      }
    } catch (error) {
      row.code = error instanceof SecretsManagerBwsAdapterError
        ? error.code
        : 'verify_failed';
      failed += 1;
    }

    value = undefined;
    results.push(Object.freeze(row));
  }

  return Object.freeze({
    ok: failed === 0,
    mode: options.mode,
    entry_count: options.manifest.entries.length,
    ready,
    written,
    verified,
    failed,
    purge_disabled: true,
    local_deleted_count: 0,
    authorization_ready: false,
    helper_vault_free: true,
    env_inject_forbidden: true,
    agent_secret_visible: false,
    required_write_flag: SM_WRITE_APPROVAL_FLAG,
    results: Object.freeze(results),
  });
}
