import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { types as utilTypes } from 'node:util';

/**
 * Phase 14: load the local SM machine allowlist (no tokens, no secret values).
 *
 * Default path:
 *   %LOCALAPPDATA%\BitwardenAgentCredentialBridge\sm-machine.allow.json
 *   or macOS Application Support equivalent
 * Schema:
 *   {
 *     "schema_version": 1,
 *     "machine_id": "laptop-company",
 *     "allowed_project_ids": ["uuid", "uuid"]
 *   }
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
const ALLOW_FIELDS = new Set(['schema_version', 'machine_id', 'allowed_project_ids']);

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
 * @returns {Promise<{
 *   schema_version: 1,
 *   machine_id: string,
 *   allowed_project_ids: string[],
 *   path: string,
 * }>}
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
  const config = exactObject(parsed, ALLOW_FIELDS);
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
  return Object.freeze({
    schema_version: 1,
    machine_id: config.machine_id,
    allowed_project_ids: Object.freeze(projectIds),
    path: filePath,
  });
}

export function isProjectAllowed(allowConfig, projectId) {
  if (typeof projectId !== 'string' || !UUID.test(projectId)) {
    return false;
  }
  return allowConfig.allowed_project_ids.includes(projectId.toLowerCase());
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size ||
      keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new SecretsManagerAllowConfigError('allow_config_invalid');
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
