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
const COMMON_POLICY_FIELDS = Object.freeze([
  'version',
  'service',
  'credential_class',
  'bind',
  'upstream',
  'method',
  'path',
]);
const VERSION_1_POLICY_FIELDS = new Set([
  ...COMMON_POLICY_FIELDS,
  'authorization',
]);
const VERSION_2_POLICY_FIELDS = new Set([
  ...COMMON_POLICY_FIELDS,
  'header_name',
  'header_value',
]);
const FORBIDDEN_API_KEY_HEADER_NAMES = new Set([
  'authorization',
  'connection',
  'cookie',
  'expect',
  'host',
  'http2-settings',
  'keep-alive',
  'max-forwards',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'set-cookie',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'via',
  'www-authenticate',
]);
const FORBIDDEN_API_KEY_HEADER_PREFIXES = Object.freeze([
  'access-control-',
  'content-',
  'forwarded',
  'proxy-',
  'sec-',
  'x-forwarded-',
]);
const LOWERCASE_ASCII_HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
/** Conservative protocol-name bound; ASCII characters are one byte each. */
const MAX_API_KEY_HEADER_NAME_LENGTH = 128;

/**
 * @typedef {object} PolicyBase
 * @property {number} version
 * @property {string} service
 * @property {string} credential_class
 * @property {string} bind
 * @property {string} upstream
 * @property {string} method
 * @property {string} path
 */

/** @typedef {PolicyBase & {version: 1, credential_class: 'http_bearer', authorization: string}} BearerPolicy */

/** @typedef {PolicyBase & {version: 2, credential_class: 'http_api_key_header', header_name: string, header_value: string}} ApiKeyHeaderPolicy */

/** @typedef {BearerPolicy | ApiKeyHeaderPolicy} Policy */

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

  if (obj.version !== 1 && obj.version !== 2) {
    throw new PolicyValidationError('policy.version must be 1 or 2');
  }

  validateExactFields(
    obj,
    obj.version === 1 ? VERSION_1_POLICY_FIELDS : VERSION_2_POLICY_FIELDS,
  );

  if (typeof obj.service !== 'string' || obj.service.trim() === '') {
    throw new PolicyValidationError('policy.service must be a non-empty string');
  }

  if (typeof obj.credential_class !== 'string' || obj.credential_class.trim() === '') {
    throw new PolicyValidationError(
      'policy.credential_class must be a non-empty string',
    );
  }

  if (
    !SUPPORTED_CREDENTIAL_CLASSES.includes(
      /** @type {string} */ (obj.credential_class),
    )
  ) {
    throw new PolicyValidationError(
      `unsupported credential_class; supported classes: ${SUPPORTED_CREDENTIAL_CLASSES.join(', ')}`,
    );
  }

  const expectedClass =
    obj.version === 1 ? 'http_bearer' : 'http_api_key_header';
  if (obj.credential_class !== expectedClass) {
    throw new PolicyValidationError(
      `policy.version ${obj.version} requires credential_class "${expectedClass}"`,
    );
  }

  const bind = parseLoopbackHttpUrl(obj.bind, 'policy.bind');
  const upstream = parseLoopbackHttpUrl(obj.upstream, 'policy.upstream');

  if (typeof obj.method !== 'string' || !HTTP_METHODS.has(obj.method)) {
    throw new PolicyValidationError(
      'policy.method must be a standard HTTP method in uppercase',
    );
  }

  if (
    typeof obj.path !== 'string' ||
    !obj.path.startsWith('/') ||
    obj.path.startsWith('//')
  ) {
    throw new PolicyValidationError(
      'policy.path must be an origin-relative string starting with one "/"',
    );
  }

  if (obj.path.includes('?') || obj.path.includes('#')) {
    throw new PolicyValidationError(
      'policy.path must not include query or fragment syntax',
    );
  }

  const common = {
    service: obj.service,
    bind: bind.href.replace(/\/$/, ''),
    upstream: upstream.href.replace(/\/$/, ''),
    method: obj.method,
    path: obj.path,
  };

  if (obj.version === 1) {
    if (typeof obj.authorization !== 'string') {
      throw new PolicyValidationError('policy.authorization must be a string');
    }
    validateCredentialPlaceholder(obj.authorization, 'policy.authorization');
    return {
      version: 1,
      ...common,
      credential_class: 'http_bearer',
      authorization: CREDENTIAL_PLACEHOLDER,
    };
  }

  validateApiKeyHeaderName(obj.header_name);
  if (typeof obj.header_value !== 'string') {
    throw new PolicyValidationError('policy.header_value must be a string');
  }
  validateCredentialPlaceholder(obj.header_value, 'policy.header_value');
  return {
    version: 2,
    ...common,
    credential_class: 'http_api_key_header',
    header_name: /** @type {string} */ (obj.header_name),
    header_value: CREDENTIAL_PLACEHOLDER,
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
 * @param {Record<string, unknown>} obj
 * @param {Set<string>} allowed
 */
function validateExactFields(obj, allowed) {
  const extras = Object.keys(obj).filter((key) => !allowed.has(key));
  if (extras.length > 0) {
    throw new PolicyValidationError(
      `policy contains unknown field(s): ${extras.sort().join(', ')}`,
    );
  }
}

/**
 * @param {unknown} value
 */
function validateApiKeyHeaderName(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    !LOWERCASE_ASCII_HEADER_NAME.test(value)
  ) {
    throw new PolicyValidationError(
      'policy.header_name must be a canonical lowercase ASCII HTTP header name',
    );
  }

  if (value.length > MAX_API_KEY_HEADER_NAME_LENGTH) {
    throw new PolicyValidationError(
      `policy.header_name must be at most ${MAX_API_KEY_HEADER_NAME_LENGTH} ASCII characters`,
    );
  }

  if (
    FORBIDDEN_API_KEY_HEADER_NAMES.has(value) ||
    FORBIDDEN_API_KEY_HEADER_PREFIXES.some(
      (prefix) => value === prefix || value.startsWith(prefix),
    )
  ) {
    throw new PolicyValidationError(
      'policy.header_name is forbidden for API-key injection',
    );
  }
}

/**
 * @param {string} value
 * @param {string} fieldName
 */
function validateCredentialPlaceholder(value, fieldName) {
  if (value === CREDENTIAL_PLACEHOLDER) {
    return;
  }

  const placeholders = value.match(/\{\{[^}]*\}\}/g) ?? [];
  if (placeholders.length > 0) {
    throw new PolicyValidationError(
      `${fieldName} must be exactly ${CREDENTIAL_PLACEHOLDER}; unsupported placeholder rejected`,
    );
  }

  throw new PolicyValidationError(
    `${fieldName} must be exactly ${CREDENTIAL_PLACEHOLDER}; literal credential values are rejected`,
  );
}

export class PolicyValidationError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'PolicyValidationError';
  }
}
