import { timingSafeEqual } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import {
  BASIC_SHAPED_CREDENTIAL_CLASSES,
  SENTINEL_CREDENTIAL_CLASSES,
  isRejectedCredentialClass,
  isSupportedCredentialClass,
} from './credential-classes.js';
import { isSecretsManagerLiveScope } from './secrets-manager-live-gate.mjs';
import { isProjectAllowed } from './secrets-manager-allow-config.mjs';

/**
 * Phase 14: resolve one SM secret under a branded live scope + machine allowlist.
 * Never logs secrets. Helper stays vault-free.
 */

export class SecretsManagerResolverError extends Error {
  constructor(code) {
    super(`Secrets Manager resolver rejected: ${code}`);
    this.name = 'SecretsManagerResolverError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SECRET_KEY = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;

/**
 * Brand an in-process resolver gate bound to an SM live scope and allow config.
 * Approval is out-of-band; this API accepts no approval secret.
 *
 * @param {unknown} liveScope
 * @param {{ allowed_project_ids: string[] }} allowConfig
 */
export function buildSecretsManagerResolverGate(liveScope, allowConfig) {
  if (!isSecretsManagerLiveScope(liveScope)) {
    throw new SecretsManagerResolverError('invalid_live_scope');
  }
  if (liveScope.secrets_manager_allowed !== true ||
      liveScope.helper_vault_free !== true ||
      liveScope.env_inject_forbidden !== true) {
    throw new SecretsManagerResolverError('invalid_live_scope');
  }
  if (
    allowConfig === null ||
    typeof allowConfig !== 'object' ||
    !Array.isArray(allowConfig.allowed_project_ids) ||
    allowConfig.allowed_project_ids.length < 1
  ) {
    throw new SecretsManagerResolverError('invalid_allow_config');
  }
  const gate = Object.freeze({
    schema_version: 1,
    mode: 'secrets_manager_resolve',
    secrets_manager_allowed: true,
    helper_vault_free: true,
    env_inject_forbidden: true,
    mutation_authorized: false,
    live_test_executed: false,
    authorization_ready: false,
    allowed_project_ids: Object.freeze([...allowConfig.allowed_project_ids]),
  });
  VALID_GATES.add(gate);
  return gate;
}

export function isSecretsManagerResolverGate(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

/**
 * Resolve through an injected adapter that returns `{ credential }` or
 * `{ username, password }`. Adapter must never be logged.
 *
 * @param {unknown} gate
 * @param {(request: {
 *   project_id: string,
 *   secret_key: string,
 *   credential_class: string,
 *   secret_key_password?: string,
 * }) => Promise<object> | object} adapter
 * @param {{
 *   project_id: string,
 *   secret_key: string,
 *   credential_class: string,
 *   secret_key_password?: string,
 * }} request
 */
export async function resolveSecretsManagerSecret(gate, adapter, request) {
  if (!isSecretsManagerResolverGate(gate)) {
    throw new SecretsManagerResolverError('invalid_gate');
  }
  if (typeof adapter !== 'function') {
    throw new SecretsManagerResolverError('invalid_adapter');
  }

  const allowedFields = new Set([
    'project_id',
    'secret_key',
    'credential_class',
    'secret_key_password',
  ]);
  const req = exactObject(request, allowedFields, true);
  if (typeof req.project_id !== 'string' || !UUID.test(req.project_id)) {
    throw new SecretsManagerResolverError('invalid_request');
  }
  if (typeof req.secret_key !== 'string' || !SECRET_KEY.test(req.secret_key)) {
    throw new SecretsManagerResolverError('invalid_request');
  }
  if (!isProjectAllowed(
    { allowed_project_ids: gate.allowed_project_ids },
    req.project_id,
  )) {
    throw new SecretsManagerResolverError('project_not_allowed');
  }
  if (isRejectedCredentialClass(req.credential_class)) {
    throw new SecretsManagerResolverError('rejected_credential_class');
  }
  if (!isSupportedCredentialClass(req.credential_class) ||
      req.credential_class === 'onecli_proxy') {
    throw new SecretsManagerResolverError('invalid_request');
  }
  if (![...SENTINEL_CREDENTIAL_CLASSES, ...BASIC_SHAPED_CREDENTIAL_CLASSES]
    .includes(req.credential_class)) {
    throw new SecretsManagerResolverError('invalid_request');
  }

  const needsPasswordKey = BASIC_SHAPED_CREDENTIAL_CLASSES.includes(req.credential_class);
  if (needsPasswordKey) {
    if (typeof req.secret_key_password !== 'string' ||
        !SECRET_KEY.test(req.secret_key_password)) {
      throw new SecretsManagerResolverError('invalid_request');
    }
  } else if (req.secret_key_password !== undefined) {
    throw new SecretsManagerResolverError('invalid_request');
  }

  const resolved = await adapter({
    project_id: req.project_id.toLowerCase(),
    secret_key: req.secret_key,
    credential_class: req.credential_class,
    ...(needsPasswordKey
      ? { secret_key_password: req.secret_key_password }
      : {}),
  });
  return sanitizeResolvedSecret(resolved, req.credential_class);
}

function sanitizeResolvedSecret(resolved, credentialClass) {
  if (resolved === null || typeof resolved !== 'object' || Array.isArray(resolved) ||
      utilTypes.isProxy(resolved) || Object.getPrototypeOf(resolved) !== Object.prototype) {
    throw new SecretsManagerResolverError('invalid_secret');
  }
  if (BASIC_SHAPED_CREDENTIAL_CLASSES.includes(credentialClass)) {
    const keys = Reflect.ownKeys(resolved);
    if (keys.length !== 2 || !keys.includes('username') || !keys.includes('password')) {
      throw new SecretsManagerResolverError('invalid_secret');
    }
    const username = resolved.username;
    const password = resolved.password;
    if (typeof username !== 'string' || typeof password !== 'string' ||
        username.length < 1 || password.length < 1 || username.includes(':')) {
      throw new SecretsManagerResolverError('invalid_secret');
    }
    return Object.freeze({ username, password });
  }
  const keys = Reflect.ownKeys(resolved);
  if (keys.length !== 1 || keys[0] !== 'credential') {
    throw new SecretsManagerResolverError('invalid_secret');
  }
  const credential = resolved.credential;
  if (typeof credential !== 'string' || credential.length < 8 || credential.length > 4096) {
    throw new SecretsManagerResolverError('invalid_secret');
  }
  timingSafeEqual(Buffer.from(credential.slice(0, 8)), Buffer.from(credential.slice(0, 8)));
  return Object.freeze({ credential });
}

function exactObject(value, fields, optionalPasswordKey = false) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new SecretsManagerResolverError('invalid_request');
  }
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== 'string' || !fields.has(key)) {
      throw new SecretsManagerResolverError('invalid_request');
    }
  }
  const required = optionalPasswordKey
    ? ['project_id', 'secret_key', 'credential_class']
    : [...fields];
  for (const key of required) {
    if (!keys.includes(key)) {
      throw new SecretsManagerResolverError('invalid_request');
    }
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new SecretsManagerResolverError('invalid_request');
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
