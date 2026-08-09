import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { types as utilTypes } from 'node:util';

/**
 * Phase 13: load the local personal-vault allowlist (digest only).
 *
 * Default path:
 *   %LOCALAPPDATA%\BitwardenAgentCredentialBridge\personal-vault.allow.json
 * Schema: { "schema_version": 1, "account_email_sha256": "<64 hex>" }
 * Never stores email plaintext. Not a git-tracked capability.
 */

export class PersonalBitwardenAllowConfigError extends Error {
  constructor(code) {
    super(`Personal Bitwarden allow config rejected: ${code}`);
    this.name = 'PersonalBitwardenAllowConfigError';
    this.code = code;
  }
}

const SHA256 = /^[0-9a-f]{64}$/;
const ALLOW_FIELDS = new Set(['schema_version', 'account_email_sha256']);

export function defaultPersonalVaultAllowPath() {
  const base = process.env.LOCALAPPDATA ||
    (process.env.USERPROFILE
      ? path.join(process.env.USERPROFILE, 'AppData', 'Local')
      : path.join(os.homedir(), 'AppData', 'Local'));
  return path.join(base, 'BitwardenAgentCredentialBridge', 'personal-vault.allow.json');
}

/**
 * @param {string} emailUtf8
 * @returns {string} lowercase hex digest
 */
export function digestPersonalAccountEmail(emailUtf8) {
  if (typeof emailUtf8 !== 'string' || emailUtf8.length < 3 || emailUtf8.length > 320) {
    throw new PersonalBitwardenAllowConfigError('invalid_email');
  }
  return createHash('sha256').update(emailUtf8, 'utf8').digest('hex');
}

/**
 * @param {string} [filePath]
 * @returns {Promise<{ schema_version: 1, account_email_sha256: string, path: string }>}
 */
export async function loadPersonalVaultAllowConfig(filePath = defaultPersonalVaultAllowPath()) {
  if (typeof filePath !== 'string' || filePath.length < 1) {
    throw new PersonalBitwardenAllowConfigError('invalid_path');
  }
  let raw;
  try {
    raw = await fs.readFile(filePath, { encoding: 'utf8' });
  } catch {
    throw new PersonalBitwardenAllowConfigError('allow_config_absent');
  }
  if (raw.length > 4096) {
    throw new PersonalBitwardenAllowConfigError('allow_config_too_large');
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new PersonalBitwardenAllowConfigError('allow_config_invalid');
  }
  const config = exactObject(parsed, ALLOW_FIELDS);
  if (config.schema_version !== 1 ||
      typeof config.account_email_sha256 !== 'string' ||
      !SHA256.test(config.account_email_sha256)) {
    throw new PersonalBitwardenAllowConfigError('allow_config_invalid');
  }
  return Object.freeze({
    schema_version: 1,
    account_email_sha256: config.account_email_sha256,
    path: filePath,
  });
}

export function safeEqualHexDigest(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' ||
      !SHA256.test(left) || !SHA256.test(right)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new PersonalBitwardenAllowConfigError('allow_config_invalid');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size ||
      keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new PersonalBitwardenAllowConfigError('allow_config_invalid');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new PersonalBitwardenAllowConfigError('allow_config_invalid');
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
