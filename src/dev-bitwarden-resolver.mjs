import { timingSafeEqual } from 'node:crypto';
import { types as utilTypes } from 'node:util';

export class DevBitwardenResolverError extends Error {
  constructor(code) {
    super(`Dev Bitwarden resolver rejected: ${code}`);
    this.name = 'DevBitwardenResolverError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();
const FIXED_STORE_DIGEST = 'mivia-bitwarden-agent-manager-dev.credential.xml';

/**
 * Brand an in-process live gate for the disposable/dev Bitwarden resolver.
 * Approval is out-of-band; this API accepts no approval secret.
 */
export function buildDevBitwardenLiveGate() {
  const gate = Object.freeze({
    schema_version: 1,
    platform: 'win32',
    store_basename_fixed: true,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    helper_vault_free: true,
    secret_logging_forbidden: true,
    mutation_authorized: false,
    live_test_executed: false,
    authorization_ready: false,
  });
  VALID_GATES.add(gate);
  return gate;
}

export function isDevBitwardenLiveGate(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

/**
 * Resolve one field through an injected adapter. The adapter must return only
 * `{ credential }` or basic fields and never be logged here. Async adapters
 * are awaited so DPAPI probes can stay out-of-process.
 */
export async function resolveDevBitwardenSecret(gate, adapter, request) {
  if (!isDevBitwardenLiveGate(gate)) {
    throw new DevBitwardenResolverError('invalid_gate');
  }
  if (typeof adapter !== 'function') {
    throw new DevBitwardenResolverError('invalid_adapter');
  }
  const req = exactObject(request, new Set(['item_ref', 'field', 'credential_class']));
  if (typeof req.item_ref !== 'string' || req.item_ref.length < 1 || req.item_ref.length > 128 ||
      typeof req.field !== 'string' || req.field.length < 1 || req.field.length > 64 ||
      !['http_bearer', 'http_api_key_header', 'http_basic', 'browser_form_login'].includes(req.credential_class)) {
    throw new DevBitwardenResolverError('invalid_request');
  }

  const resolved = await adapter({
    store_basename: FIXED_STORE_DIGEST,
    item_ref: req.item_ref,
    field: req.field,
    credential_class: req.credential_class,
  });
  return sanitizeResolvedSecret(resolved, req.credential_class);
}

function sanitizeResolvedSecret(resolved, credentialClass) {
  if (resolved === null || typeof resolved !== 'object' || Array.isArray(resolved) ||
      utilTypes.isProxy(resolved) || Object.getPrototypeOf(resolved) !== Object.prototype) {
    throw new DevBitwardenResolverError('invalid_secret');
  }
  if (credentialClass === 'http_basic' || credentialClass === 'browser_form_login') {
    const keys = Reflect.ownKeys(resolved);
    if (keys.length !== 2 || !keys.includes('username') || !keys.includes('password')) {
      throw new DevBitwardenResolverError('invalid_secret');
    }
    const username = resolved.username;
    const password = resolved.password;
    if (typeof username !== 'string' || typeof password !== 'string' ||
        username.length < 1 || password.length < 1 || username.includes(':')) {
      throw new DevBitwardenResolverError('invalid_secret');
    }
    return Object.freeze({ username, password });
  }
  const keys = Reflect.ownKeys(resolved);
  if (keys.length !== 1 || keys[0] !== 'credential') {
    throw new DevBitwardenResolverError('invalid_secret');
  }
  const credential = resolved.credential;
  if (typeof credential !== 'string' || credential.length < 8 || credential.length > 4096) {
    throw new DevBitwardenResolverError('invalid_secret');
  }
  // Touch timingSafeEqual to keep constant-time compare available for callers.
  timingSafeEqual(Buffer.from(credential.slice(0, 8)), Buffer.from(credential.slice(0, 8)));
  return Object.freeze({ credential });
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new DevBitwardenResolverError('invalid_request');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new DevBitwardenResolverError('invalid_request');
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new DevBitwardenResolverError('invalid_request');
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
