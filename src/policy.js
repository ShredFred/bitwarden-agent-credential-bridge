import { readFile } from 'node:fs/promises';
import {
  CREDENTIAL_PLACEHOLDER,
  SUPPORTED_CREDENTIAL_CLASSES,
} from './constants.js';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost']);
const HTTP_METHODS = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
]);

/**
 * @typedef {object} Policy
 * @property {number} version
 * @property {string} service
 * @property {string} credential_class
 * @property {string} bind
 * @property {string} upstream
 * @property {string} method
 * @property {string} path
 * @property {string} authorization
 */

/**
 * Validate a declarative policy object. Unsupported credential classes fail closed.
 * @param {unknown} raw
 * @returns {Policy}
 */
export function validatePolicy(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new PolicyValidationError('policy must be a JSON object');
  }

  /** @type {Record<string, unknown>} */
  const obj = /** @type {Record<string, unknown>} */ (raw);

  if (obj.version !== 1) {
    throw new PolicyValidationError('policy.version must be 1');
  }

  if (typeof obj.service !== 'string' || obj.service.trim() === '') {
    throw new PolicyValidationError('policy.service must be a non-empty string');
  }

  if (typeof obj.credential_class !== 'string' || obj.credential_class.trim() === '') {
    throw new PolicyValidationError(
      'policy.credential_class must be a non-empty string',
    );
  }

  if (!SUPPORTED_CREDENTIAL_CLASSES.includes(obj.credential_class)) {
    throw new PolicyValidationError(
      `unsupported credential_class "${obj.credential_class}"; Phase 1 supports only: ${SUPPORTED_CREDENTIAL_CLASSES.join(', ')}`,
    );
  }

  const bind = parseLoopbackHttpUrl(obj.bind, 'policy.bind');
  const upstream = parseLoopbackHttpUrl(obj.upstream, 'policy.upstream');

  if (typeof obj.method !== 'string' || !HTTP_METHODS.has(obj.method)) {
    throw new PolicyValidationError(
      'policy.method must be a standard HTTP method in uppercase',
    );
  }

  if (typeof obj.path !== 'string' || !obj.path.startsWith('/')) {
    throw new PolicyValidationError(
      'policy.path must be a string starting with "/"',
    );
  }

  if (typeof obj.authorization !== 'string') {
    throw new PolicyValidationError('policy.authorization must be a string');
  }

  validateAuthorizationPlaceholder(obj.authorization);

  return {
    version: 1,
    service: obj.service,
    credential_class: obj.credential_class,
    bind: bind.href.replace(/\/$/, ''),
    upstream: upstream.href.replace(/\/$/, ''),
    method: obj.method,
    path: obj.path,
    authorization: CREDENTIAL_PLACEHOLDER,
  };
}

/**
 * Load and validate a policy JSON file.
 * @param {string} filePath
 * @returns {Promise<Policy>}
 */
export async function loadPolicy(filePath) {
  let text;
  try {
    text = await readFile(filePath, 'utf8');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new PolicyValidationError(`failed to read policy file: ${message}`);
  }

  let raw;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new PolicyValidationError(`policy file is not valid JSON: ${message}`);
  }

  return validatePolicy(raw);
}

/**
 * Return a copy of policy with a concrete upstream origin (e.g. after binding the fake API).
 * @param {Policy} policy
 * @param {string} upstreamUrl
 * @returns {Policy}
 */
export function withUpstream(policy, upstreamUrl) {
  const upstream = parseLoopbackHttpUrl(upstreamUrl, 'upstream');
  return validatePolicy({
    ...policy,
    upstream: upstream.href.replace(/\/$/, ''),
  });
}

/**
 * Return a copy of policy with a concrete bind origin.
 * @param {Policy} policy
 * @param {string} bindUrl
 * @returns {Policy}
 */
export function withBind(policy, bindUrl) {
  const bind = parseLoopbackHttpUrl(bindUrl, 'bind');
  return validatePolicy({
    ...policy,
    bind: bind.href.replace(/\/$/, ''),
  });
}

/**
 * Parse and validate an http loopback URL with an explicit port (including 0).
 * @param {unknown} value
 * @param {string} fieldName
 * @returns {URL}
 */
export function parseLoopbackHttpUrl(value, fieldName) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new PolicyValidationError(`${fieldName} must be a non-empty string URL`);
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw new PolicyValidationError(`${fieldName} must be a valid URL`);
  }

  if (url.protocol !== 'http:') {
    throw new PolicyValidationError(
      `${fieldName} must use the http scheme (loopback only)`,
    );
  }

  if (!LOOPBACK_HOSTS.has(url.hostname)) {
    throw new PolicyValidationError(
      `${fieldName} must be loopback (127.0.0.1 or localhost); rejected non-loopback host`,
    );
  }

  // URL parser omits default ports; require an explicit port including :0.
  if (!/:(\d+)(?:\/|$)/.test(value) || url.port === '') {
    throw new PolicyValidationError(
      `${fieldName} must include an explicit port (use 0 for ephemeral bind)`,
    );
  }

  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new PolicyValidationError(
      `${fieldName} port must be an integer 0–65535`,
    );
  }

  if (url.username || url.password) {
    throw new PolicyValidationError(`${fieldName} must not include credentials`);
  }

  if (url.search || url.hash) {
    throw new PolicyValidationError(
      `${fieldName} must not include query or fragment`,
    );
  }

  if (url.pathname !== '/' && url.pathname !== '') {
    throw new PolicyValidationError(
      `${fieldName} must be an origin URL without a path (path is a separate policy field)`,
    );
  }

  return url;
}

/**
 * @param {string} value
 */
function validateAuthorizationPlaceholder(value) {
  if (value === CREDENTIAL_PLACEHOLDER) {
    return;
  }

  const placeholders = value.match(/\{\{[^}]*\}\}/g) ?? [];
  if (placeholders.length > 0) {
    throw new PolicyValidationError(
      `policy.authorization must be exactly ${CREDENTIAL_PLACEHOLDER}; unsupported placeholder rejected`,
    );
  }

  throw new PolicyValidationError(
    `policy.authorization must be exactly ${CREDENTIAL_PLACEHOLDER}; literal credential values are rejected`,
  );
}

export class PolicyValidationError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'PolicyValidationError';
  }
}
