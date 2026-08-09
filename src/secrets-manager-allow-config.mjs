import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { types as utilTypes } from 'node:util';

/**
 * Phase 14/15: load the local SM machine allowlist (no tokens, no secret values).
 *
 * Schema:
 *   {
 *     "schema_version": 1,
 *     "machine_id": "pc-name",
 *     "allowed_project_ids": ["uuid", "..."],
 *     "server_url"?: "https://...",          // optional self-host base → bws --server-url
 *     "api_url"?: "https://.../api",         // optional; requires identity_url
 *     "identity_url"?: "https://.../identity"
 *   }
 * Absent endpoint fields = Bitwarden cloud default.
 */

export class SecretsManagerAllowConfigError extends Error {
  constructor(code) {
    super(`Secrets Manager allow config rejected: ${code}`);
    this.name = 'SecretsManagerAllowConfigError';
    this.code = code;
  }
}

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MACHINE_ID = /^[a-z][a-z0-9_-]{0,63}$/;
const REQUIRED_FIELDS = new Set(['schema_version', 'machine_id', 'allowed_project_ids']);
const OPTIONAL_FIELDS = new Set(['server_url', 'api_url', 'identity_url']);
const ALL_FIELDS = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);

function assertHttpsUrl(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 256) {
    return false;
  }
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.hostname.length > 0;
  } catch {
    return false;
  }
}

export function defaultSecretsManagerAllowPath() {
  if (process.platform === 'darwin') {
    return path.join(
      os.homedir(),
      'Library',
      'Application Support',
      'BitwardenAgentCredentialBridge',
      'sm-machine.allow.json',
    );
  }
  const base = process.env.LOCALAPPDATA ||
    (process.env.USERPROFILE
      ? path.join(process.env.USERPROFILE, 'AppData', 'Local')
      : path.join(os.homedir(), 'AppData', 'Local'));
  return path.join(base, 'BitwardenAgentCredentialBridge', 'sm-machine.allow.json');
}

/**
 * @param {string} [filePath]
 */
export async function loadSecretsManagerAllowConfig(
  filePath = defaultSecretsManagerAllowPath(),
) {
  if (typeof filePath !== 'string' || filePath.length < 1) {
    throw new SecretsManagerAllowConfigError('invalid_path');
  }
  let raw;
  try {
    raw = await fs.readFile(filePath, { encoding: 'utf8' });
  } catch {
    throw new SecretsManagerAllowConfigError('allow_config_absent');
  }
  if (raw.length > 8192) {
    throw new SecretsManagerAllowConfigError('allow_config_too_large');
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  const config = exactObjectAllowingOptional(parsed);
  if (config.schema_version !== 1 ||
      typeof config.machine_id !== 'string' ||
      !MACHINE_ID.test(config.machine_id)) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  if (!Array.isArray(config.allowed_project_ids) ||
      config.allowed_project_ids.length < 1 ||
      config.allowed_project_ids.length > 16) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  /** @type {string[]} */
  const projectIds = [];
  const seen = new Set();
  for (const id of config.allowed_project_ids) {
    if (typeof id !== 'string' || !UUID.test(id)) {
      throw new SecretsManagerAllowConfigError('allow_config_invalid');
    }
    const normalized = id.toLowerCase();
    if (seen.has(normalized)) {
      throw new SecretsManagerAllowConfigError('allow_config_invalid');
    }
    seen.add(normalized);
    projectIds.push(normalized);
  }

  const endpoints = normalizeEndpoints(config);
  return Object.freeze({
    schema_version: 1,
    machine_id: config.machine_id,
    allowed_project_ids: Object.freeze(projectIds),
    ...endpoints,
    path: filePath,
  });
}

export function isProjectAllowed(allowConfig, projectId) {
  if (typeof projectId !== 'string' || !UUID.test(projectId)) {
    return false;
  }
  return allowConfig.allowed_project_ids.includes(projectId.toLowerCase());
}

/**
 * Build argv extras / child config for bws from allowlist endpoints.
 * @param {{ server_url?: string, api_url?: string, identity_url?: string }} allow
 * @returns {{ serverUrlArg: string | null, usesCloudDefault: boolean }}
 */
export function resolveBwsServerOptions(allow) {
  if (allow && typeof allow.server_url === 'string') {
    return { serverUrlArg: allow.server_url, usesCloudDefault: false };
  }
  // api+identity without server_url: derive base from api host (strip /api).
  if (allow && typeof allow.api_url === 'string' && typeof allow.identity_url === 'string') {
    try {
      const api = new URL(allow.api_url);
      const identity = new URL(allow.identity_url);
      if (api.protocol !== 'https:' || identity.protocol !== 'https:') {
        throw new Error('bad');
      }
      // Prefer explicit --server-url as vault/base host when paths are /api and /identity.
      const base = `${api.protocol}//${api.host}`;
      return { serverUrlArg: base, usesCloudDefault: false };
    } catch {
      throw new SecretsManagerAllowConfigError('allow_config_invalid');
    }
  }
  return { serverUrlArg: null, usesCloudDefault: true };
}

function normalizeEndpoints(config) {
  const hasServer = typeof config.server_url === 'string';
  const hasApi = typeof config.api_url === 'string';
  const hasIdentity = typeof config.identity_url === 'string';
  if (hasApi !== hasIdentity) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  if (hasServer && !assertHttpsUrl(config.server_url)) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  if (hasApi && (!assertHttpsUrl(config.api_url) || !assertHttpsUrl(config.identity_url))) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  /** @type {Record<string, string>} */
  const out = {};
  if (hasServer) out.server_url = config.server_url.replace(/\/$/, '');
  if (hasApi) {
    out.api_url = config.api_url.replace(/\/$/, '');
    out.identity_url = config.identity_url.replace(/\/$/, '');
  }
  return out;
}

function exactObjectAllowingOptional(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== 'string' || !ALL_FIELDS.has(key)) {
      throw new SecretsManagerAllowConfigError('allow_config_invalid');
    }
  }
  for (const required of REQUIRED_FIELDS) {
    if (!keys.includes(required)) {
      throw new SecretsManagerAllowConfigError('allow_config_invalid');
    }
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new SecretsManagerAllowConfigError('allow_config_invalid');
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
