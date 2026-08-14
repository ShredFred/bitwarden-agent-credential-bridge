import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import { resolveBwsServerOptions } from './secrets-manager-allow-config.mjs';

const execFileAsync = promisify(execFile);

/**
 * Phase 14/15: bounded bws CLI adapter for Secrets Manager.
 * Access token is passed only as --access-token argv to the child, never via
 * agent-readable process environment. Optional --server-url for self-host.
 */

export class SecretsManagerBwsAdapterError extends Error {
  constructor(code) {
    super(`Secrets Manager bws adapter rejected: ${code}`);
    this.name = 'SecretsManagerBwsAdapterError';
    this.code = code;
  }
}

export const BWS_MISSING_HINT =
  'Install Bitwarden Secrets Manager CLI (bws). Windows default is LocalAppData\\Programs\\Bitwarden\\bws.exe; PATH is not required if that file exists. authorization_ready is LocalService writer evidence, not this error.';

/**
 * Prefer an explicit path, then the well-known Windows install location, then
 * PATH lookup via the bare `bws` name. Never returns host usernames or expands
 * LocalAppData into agent-readable error payloads.
 *
 * @param {{
 *   bwsPath?: string,
 *   platform?: NodeJS.Platform,
 *   env?: NodeJS.ProcessEnv,
 *   pathExists?: (filePath: string) => boolean,
 * }} [options]
 * @returns {string}
 */
export function resolveBwsExecutable(options = {}) {
  if (typeof options.bwsPath === 'string' && options.bwsPath.length > 0) {
    return options.bwsPath;
  }
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const exists = typeof options.pathExists === 'function'
    ? options.pathExists
    : defaultBwsPathExists;
  if (platform === 'win32') {
    const local = env.LOCALAPPDATA;
    if (typeof local === 'string' && local.length > 0) {
      const candidate = path.join(local, 'Programs', 'Bitwarden', 'bws.exe');
      if (exists(candidate)) {
        return candidate;
      }
    }
  }
  return 'bws';
}

function defaultBwsPathExists(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function bwsExecutableFromOptions(options) {
  return resolveBwsExecutable(options);
}

/**
 * Attach a value-free hint when the failure is missing bws, without treating
 * authorization_ready as the primary error code.
 * @param {Record<string, unknown>} payload
 */
export function withBwsDiagnostic(payload) {
  if (!payload || payload.code !== 'bws_missing') {
    return payload;
  }
  return {
    ...payload,
    hint: typeof payload.hint === 'string' && payload.hint.length > 0
      ? payload.hint
      : BWS_MISSING_HINT,
    bws_available: false,
  };
}

const SECRET_KEY = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function withServerArgs(args, serverUrl) {
  if (typeof serverUrl === 'string' && serverUrl.length > 0) {
    return [...args, '--server-url', serverUrl];
  }
  return args;
}

function serverUrlFromOptions(options) {
  if (typeof options.serverUrl === 'string' && options.serverUrl.length > 0) {
    return options.serverUrl;
  }
  if (options.allowConfig) {
    return resolveBwsServerOptions(options.allowConfig).serverUrlArg;
  }
  return null;
}

/**
 * @param {{
 *   accessToken: string,
 *   projectId: string,
 *   secretKey: string,
 *   bwsPath?: string,
 *   serverUrl?: string,
 *   allowConfig?: object,
 *   runCommand?: typeof defaultRunCommand,
 * }} options
 * @returns {Promise<string>}
 */
export async function fetchSecretsManagerSecretValue(options) {
  if (typeof options.accessToken !== 'string' ||
      options.accessToken.length < 16 ||
      options.accessToken.length > 8192) {
    throw new SecretsManagerBwsAdapterError('invalid_token');
  }
  if (typeof options.projectId !== 'string' || !UUID.test(options.projectId)) {
    throw new SecretsManagerBwsAdapterError('invalid_project_id');
  }
  if (typeof options.secretKey !== 'string' || !SECRET_KEY.test(options.secretKey)) {
    throw new SecretsManagerBwsAdapterError('invalid_secret_key');
  }

  const run = typeof options.runCommand === 'function'
    ? options.runCommand
    : defaultRunCommand;
  const bwsPath = bwsExecutableFromOptions(options);
  const serverUrl = serverUrlFromOptions(options);

  // bws 2.x: PROJECT_ID is a positional argument (not --project-id).
  const listed = await run(bwsPath, withServerArgs([
    'secret', 'list',
    options.projectId.toLowerCase(),
    '--output', 'json',
    '--access-token', options.accessToken,
  ], serverUrl));

  let secrets;
  try {
    secrets = JSON.parse(listed);
  } catch {
    throw new SecretsManagerBwsAdapterError('list_parse_failed');
  }
  if (!Array.isArray(secrets)) {
    throw new SecretsManagerBwsAdapterError('list_parse_failed');
  }

  const matches = secrets.filter((entry) =>
    entry !== null &&
    typeof entry === 'object' &&
    typeof entry.key === 'string' &&
    entry.key === options.secretKey &&
    typeof entry.id === 'string' &&
    UUID.test(entry.id),
  );
  if (matches.length !== 1) {
    throw new SecretsManagerBwsAdapterError(
      matches.length < 1 ? 'secret_not_found' : 'secret_ambiguous',
    );
  }

  const got = await run(bwsPath, withServerArgs([
    'secret', 'get', matches[0].id,
    '--output', 'json',
    '--access-token', options.accessToken,
  ], serverUrl));

  let secret;
  try {
    secret = JSON.parse(got);
  } catch {
    throw new SecretsManagerBwsAdapterError('get_parse_failed');
  }
  if (
    secret === null ||
    typeof secret !== 'object' ||
    typeof secret.value !== 'string' ||
    secret.value.length < 1 ||
    secret.value.length > 4096
  ) {
    throw new SecretsManagerBwsAdapterError('invalid_secret_value');
  }
  return secret.value;
}

/**
 * @param {{
 *   accessToken: string,
 *   projectId: string,
 *   secretKey: string,
 *   secretValue: string,
 *   note?: string,
 *   bwsPath?: string,
 *   serverUrl?: string,
 *   allowConfig?: object,
 *   runCommand?: typeof defaultRunCommand,
 * }} options
 */
export async function upsertSecretsManagerSecret(options) {
  if (typeof options.accessToken !== 'string' ||
      options.accessToken.length < 16 ||
      options.accessToken.length > 8192) {
    throw new SecretsManagerBwsAdapterError('invalid_token');
  }
  if (typeof options.projectId !== 'string' || !UUID.test(options.projectId)) {
    throw new SecretsManagerBwsAdapterError('invalid_project_id');
  }
  if (typeof options.secretKey !== 'string' || !SECRET_KEY.test(options.secretKey)) {
    throw new SecretsManagerBwsAdapterError('invalid_secret_key');
  }
  if (typeof options.secretValue !== 'string' ||
      options.secretValue.length < 1 ||
      options.secretValue.length > 4096) {
    throw new SecretsManagerBwsAdapterError('invalid_secret_value');
  }
  if (options.note !== undefined &&
      (typeof options.note !== 'string' || options.note.length > 512)) {
    throw new SecretsManagerBwsAdapterError('invalid_note');
  }

  const run = typeof options.runCommand === 'function'
    ? options.runCommand
    : defaultRunCommand;
  const bwsPath = bwsExecutableFromOptions(options);
  const projectId = options.projectId.toLowerCase();
  const serverUrl = serverUrlFromOptions(options);

  const listed = await run(bwsPath, withServerArgs([
    'secret', 'list',
    projectId,
    '--output', 'json',
    '--access-token', options.accessToken,
  ], serverUrl));
  let secrets;
  try {
    secrets = JSON.parse(listed);
  } catch {
    throw new SecretsManagerBwsAdapterError('list_parse_failed');
  }
  if (!Array.isArray(secrets)) {
    throw new SecretsManagerBwsAdapterError('list_parse_failed');
  }
  const matches = secrets.filter((entry) =>
    entry !== null &&
    typeof entry === 'object' &&
    typeof entry.key === 'string' &&
    entry.key === options.secretKey &&
    typeof entry.id === 'string' &&
    UUID.test(entry.id),
  );
  if (matches.length > 1) {
    throw new SecretsManagerBwsAdapterError('secret_ambiguous');
  }

  if (matches.length === 1) {
    const editArgs = [
      'secret', 'edit', matches[0].id,
      '--key', options.secretKey,
      '--value', options.secretValue,
      '--output', 'json',
      '--access-token', options.accessToken,
    ];
    if (typeof options.note === 'string') {
      editArgs.splice(6, 0, '--note', options.note);
    }
    await run(bwsPath, withServerArgs(editArgs, serverUrl));
    return Object.freeze({ ok: true, action: 'updated' });
  }

  await run(bwsPath, withServerArgs([
    'secret', 'create',
    options.secretKey,
    options.secretValue,
    projectId,
    '--output', 'json',
    '--access-token', options.accessToken,
  ], serverUrl));
  return Object.freeze({ ok: true, action: 'created' });
}

/**
 * List secret keys (and ids) for one project. Never returns secret values.
 * @param {{
 *   accessToken: string,
 *   projectId: string,
 *   bwsPath?: string,
 *   serverUrl?: string,
 *   allowConfig?: object,
 *   runCommand?: typeof defaultRunCommand,
 * }} options
 * @returns {Promise<Array<{ id: string, key: string }>>}
 */
export async function listSecretsManagerSecretKeys(options) {
  if (typeof options.accessToken !== 'string' ||
      options.accessToken.length < 16 ||
      options.accessToken.length > 8192) {
    throw new SecretsManagerBwsAdapterError('invalid_token');
  }
  if (typeof options.projectId !== 'string' || !UUID.test(options.projectId)) {
    throw new SecretsManagerBwsAdapterError('invalid_project_id');
  }
  const run = typeof options.runCommand === 'function'
    ? options.runCommand
    : defaultRunCommand;
  const bwsPath = bwsExecutableFromOptions(options);
  const serverUrl = serverUrlFromOptions(options);
  const listed = await run(bwsPath, withServerArgs([
    'secret', 'list',
    options.projectId.toLowerCase(),
    '--output', 'json',
    '--access-token', options.accessToken,
  ], serverUrl));
  let secrets;
  try {
    secrets = JSON.parse(listed);
  } catch {
    throw new SecretsManagerBwsAdapterError('list_parse_failed');
  }
  if (!Array.isArray(secrets)) {
    throw new SecretsManagerBwsAdapterError('list_parse_failed');
  }
  /** @type {Array<{ id: string, key: string }>} */
  const out = [];
  for (const entry of secrets) {
    if (entry === null || typeof entry !== 'object') continue;
    if (typeof entry.id !== 'string' || !UUID.test(entry.id)) continue;
    if (typeof entry.key !== 'string' || !SECRET_KEY.test(entry.key)) continue;
    out.push({ id: entry.id.toLowerCase(), key: entry.key });
  }
  return out;
}

/**
 * Delete one secret by id. Value-free.
 * @param {{
 *   accessToken: string,
 *   secretId: string,
 *   bwsPath?: string,
 *   serverUrl?: string,
 *   allowConfig?: object,
 *   runCommand?: typeof defaultRunCommand,
 * }} options
 */
export async function deleteSecretsManagerSecret(options) {
  if (typeof options.accessToken !== 'string' ||
      options.accessToken.length < 16 ||
      options.accessToken.length > 8192) {
    throw new SecretsManagerBwsAdapterError('invalid_token');
  }
  if (typeof options.secretId !== 'string' || !UUID.test(options.secretId)) {
    throw new SecretsManagerBwsAdapterError('invalid_secret_id');
  }
  const run = typeof options.runCommand === 'function'
    ? options.runCommand
    : defaultRunCommand;
  const bwsPath = bwsExecutableFromOptions(options);
  const serverUrl = serverUrlFromOptions(options);
  await run(bwsPath, withServerArgs([
    'secret', 'delete',
    options.secretId.toLowerCase(),
    '--output', 'none',
    '--access-token', options.accessToken,
  ], serverUrl), { allowEmptyStdout: true });
  return Object.freeze({ ok: true, action: 'deleted' });
}

async function defaultRunCommand(executable, args, runOptions = {}) {
  let stdout = '';
  let stderr = '';
  let code = 1;
  try {
    const result = await execFileAsync(executable, args, {
      windowsHide: true,
      timeout: 30000,
      maxBuffer: 1024 * 1024,
      encoding: 'utf8',
      env: {
        Path: process.env.Path || process.env.PATH,
        PATH: process.env.PATH || process.env.Path,
        SystemRoot: process.env.SystemRoot,
        windir: process.env.windir,
        HOME: process.env.HOME,
        USERPROFILE: process.env.USERPROFILE,
        LOCALAPPDATA: process.env.LOCALAPPDATA,
        TMP: process.env.TMP,
        TEMP: process.env.TEMP,
        TMPDIR: process.env.TMPDIR,
      },
    });
    stdout = result.stdout;
    stderr = result.stderr;
    code = 0;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new SecretsManagerBwsAdapterError('bws_missing');
    }
    code = typeof error?.code === 'number' ? error.code : 1;
    stdout = typeof error?.stdout === 'string' ? error.stdout : '';
    stderr = typeof error?.stderr === 'string' ? error.stderr : '';
  }
  if (code !== 0) {
    throw new SecretsManagerBwsAdapterError('bws_failed');
  }
  if (typeof stderr === 'string' && stderr.trim().length > 0) {
    throw new SecretsManagerBwsAdapterError('bws_stderr');
  }
  if (runOptions.allowEmptyStdout === true) {
    if (typeof stdout !== 'string' || stdout.length > 1024 * 1024) {
      throw new SecretsManagerBwsAdapterError('bws_output_invalid');
    }
    return stdout;
  }
  if (typeof stdout !== 'string' || stdout.length < 2 || stdout.length > 1024 * 1024) {
    throw new SecretsManagerBwsAdapterError('bws_output_invalid');
  }
  return stdout;
}
