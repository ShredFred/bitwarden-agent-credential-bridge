import { timingSafeEqual } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import {
  BASIC_SHAPED_CREDENTIAL_CLASSES,
  SENTINEL_CREDENTIAL_CLASSES,
  isRejectedCredentialClass,
  isSupportedCredentialClass,
} from './credential-classes.js';
import { isPersonalBitwardenLiveScope } from './personal-bitwarden-live-gate.mjs';
import { PERSONAL_BITWARDEN_STORE_BASENAME } from './personal-bitwarden-dpapi-collector.mjs';

/**
 * Phase 13: resolve one field under a branded personal Bitwarden live scope.
 * Company/org remain forbidden. Helper stays vault-free. Never logs secrets.
 */

export class PersonalBitwardenResolverError extends Error {
  constructor(code) {
    super(`Personal Bitwarden resolver rejected: ${code}`);
    this.name = 'PersonalBitwardenResolverError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();

/**
 * Brand an in-process resolver gate bound to a personal live scope.
 * Approval is out-of-band; this API accepts no approval secret.
 */
export function buildPersonalBitwardenResolverGate(liveScope) {
  if (!isPersonalBitwardenLiveScope(liveScope)) {
    throw new PersonalBitwardenResolverError('invalid_live_scope');
  }
  if (liveScope.personal_vault_allowed !== true ||
      liveScope.company_vault_forbidden !== true ||
      liveScope.organization_vault_forbidden !== true ||
      liveScope.helper_vault_free !== true) {
    throw new PersonalBitwardenResolverError('invalid_live_scope');
  }
  const gate = Object.freeze({
    schema_version: 1,
    platform: 'win32',
    mode: 'personal_bitwarden_resolve',
    store_basename_fixed: true,
    personal_vault_allowed: true,
    company_vault_forbidden: true,
    organization_vault_forbidden: true,
    helper_vault_free: true,
    secret_logging_forbidden: true,
    mutation_authorized: false,
    live_test_executed: false,
    authorization_ready: false,
  });
  VALID_GATES.add(gate);
  return gate;
}

export function isPersonalBitwardenResolverGate(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

/**
 * Resolve one field through an injected adapter. Adapter return values must
 * never be logged by callers.
 */
export async function resolvePersonalBitwardenSecret(gate, adapter, request) {
  if (!isPersonalBitwardenResolverGate(gate)) {
    throw new PersonalBitwardenResolverError('invalid_gate');
  }
  if (typeof adapter !== 'function') {
    throw new PersonalBitwardenResolverError('invalid_adapter');
  }
  const req = exactObject(request, new Set(['item_ref', 'field', 'credential_class']));
  if (typeof req.item_ref !== 'string' || req.item_ref.length < 1 || req.item_ref.length > 128 ||
      typeof req.field !== 'string' || req.field.length < 1 || req.field.length > 64) {
    throw new PersonalBitwardenResolverError('invalid_request');
  }
  if (isRejectedCredentialClass(req.credential_class)) {
    throw new PersonalBitwardenResolverError('rejected_credential_class');
  }
  if (!isSupportedCredentialClass(req.credential_class) ||
      req.credential_class === 'onecli_proxy') {
    throw new PersonalBitwardenResolverError('invalid_request');
  }
  if (![...SENTINEL_CREDENTIAL_CLASSES, ...BASIC_SHAPED_CREDENTIAL_CLASSES]
    .includes(req.credential_class)) {
    throw new PersonalBitwardenResolverError('invalid_request');
  }

  const resolved = await adapter({
    store_basename: PERSONAL_BITWARDEN_STORE_BASENAME,
    item_ref: req.item_ref,
    field: req.field,
    credential_class: req.credential_class,
  });
  return sanitizeResolvedSecret(resolved, req.credential_class);
}

function sanitizeResolvedSecret(resolved, credentialClass) {
  if (resolved === null || typeof resolved !== 'object' || Array.isArray(resolved) ||
      utilTypes.isProxy(resolved) || Object.getPrototypeOf(resolved) !== Object.prototype) {
    throw new PersonalBitwardenResolverError('invalid_secret');
  }
  if (credentialClass === 'http_basic' || credentialClass === 'browser_form_login') {
    const keys = Reflect.ownKeys(resolved);
    if (keys.length !== 2 || !keys.includes('username') || !keys.includes('password')) {
      throw new PersonalBitwardenResolverError('invalid_secret');
    }
    const username = resolved.username;
    const password = resolved.password;
    if (typeof username !== 'string' || typeof password !== 'string' ||
        username.length < 1 || password.length < 1 || username.includes(':')) {
      throw new PersonalBitwardenResolverError('invalid_secret');
    }
    return Object.freeze({ username, password });
  }
  const keys = Reflect.ownKeys(resolved);
  if (keys.length !== 1 || keys[0] !== 'credential') {
    throw new PersonalBitwardenResolverError('invalid_secret');
  }
  const credential = resolved.credential;
  if (typeof credential !== 'string' || credential.length < 8 || credential.length > 4096) {
    throw new PersonalBitwardenResolverError('invalid_secret');
  }
  timingSafeEqual(Buffer.from(credential.slice(0, 8)), Buffer.from(credential.slice(0, 8)));
  return Object.freeze({ credential });
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new PersonalBitwardenResolverError('invalid_request');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new PersonalBitwardenResolverError('invalid_request');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new PersonalBitwardenResolverError('invalid_request');
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
