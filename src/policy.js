import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import {
  CREDENTIAL_CLASS_BY_VERSION,
  CREDENTIAL_PLACEHOLDER,
  PASSWORD_PLACEHOLDER,
  REJECTED_CREDENTIAL_CLASSES,
  SUPPORTED_CREDENTIAL_CLASSES,
  USERNAME_PLACEHOLDER,
  isRejectedCredentialClass,
} from './constants.js';
import { assertBrandedBrowserLiveGate } from './browser-form-login-live-gate.mjs';

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
const VERSION_6_POLICY_FIELDS = new Set([
  ...COMMON_POLICY_FIELDS,
  'query_name',
  'query_value',
]);
const VERSION_3_POLICY_FIELDS = new Set([
  ...COMMON_POLICY_FIELDS,
  'username_value',
  'password_value',
]);
const VERSION_4_POLICY_FIELDS = new Set([
  'version',
  'service',
  'credential_class',
  'bind',
  'gateway',
  'target_host',
  'target_port',
  'method',
  'path',
  'agent_token',
]);
const VERSION_5_POLICY_FIELDS = new Set([
  'version',
  'service',
  'credential_class',
  'bind',
  'login_origin',
  'login_path',
  'form_action',
  'username_field',
  'password_field',
  'hidden_fields',
  'success_path',
  'allowed_paths',
  'replay_method',
  'replay_path',
  'username_value',
  'password_value',
  'max_redirect_hops',
  'session_ttl_ms',
  'idle_ttl_ms',
]);
const VERSION_7_POLICY_FIELDS = new Set([
  'version',
  'service',
  'credential_class',
  'bind',
  'target_host',
  'target_port',
  'allowed_commands',
  'username_value',
  'password_value',
  'session_ttl_ms',
  'idle_ttl_ms',
]);
const VERSION_8_POLICY_FIELDS = new Set([
  'version',
  'service',
  'credential_class',
  'bind',
  'target_host',
  'target_port',
  'allowed_ops',
  'allowed_paths',
  'username_value',
  'password_value',
  'session_ttl_ms',
  'idle_ttl_ms',
]);
const SSH_COMMAND_NAME = /^[a-z][a-z0-9_-]{0,31}$/;
const MAX_SSH_COMMANDS = 8;
const MAX_FTP_PATHS = 16;
const FTP_OPS = new Set(['list', 'retr']);
const LOOPBACK_TARGET_HOSTS = new Set(['127.0.0.1', 'localhost']);
const FIELD_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const MAX_HIDDEN_FIELDS = 16;
const MAX_ALLOWED_PATHS = 32;
const DNS_HOSTNAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
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
const QUERY_PARAM_NAME = /^[a-z][a-z0-9_-]{0,63}$/;

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

/** @typedef {PolicyBase & {version: 6, credential_class: 'http_api_key_query', query_name: string, query_value: string}} ApiKeyQueryPolicy */

/** @typedef {PolicyBase & {version: 3, credential_class: 'http_basic', username_value: string, password_value: string}} BasicPolicy */

/** @typedef {{version: 4, service: string, credential_class: 'onecli_proxy', bind: string, gateway: string, target_host: string, target_port: 443, method: string, path: string, agent_token: string}} OneCliProxyPolicy */

/**
 * @typedef {{
 *   version: 5,
 *   service: string,
 *   credential_class: 'browser_form_login',
 *   bind: string,
 *   login_origin: string,
 *   login_path: string,
 *   form_action: string,
 *   username_field: string,
 *   password_field: string,
 *   hidden_fields: string[],
 *   success_path: string,
 *   allowed_paths: string[],
 *   replay_method: string,
 *   replay_path: string,
 *   username_value: string,
 *   password_value: string,
 *   max_redirect_hops: number,
 *   session_ttl_ms: number,
 *   idle_ttl_ms: number,
 * }} BrowserFormLoginPolicy
 */

/** @typedef {BearerPolicy | ApiKeyHeaderPolicy | ApiKeyQueryPolicy | BasicPolicy | OneCliProxyPolicy | BrowserFormLoginPolicy} Policy */

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

  if (obj.version !== 1 && obj.version !== 2 && obj.version !== 3 &&
      obj.version !== 4 && obj.version !== 5 && obj.version !== 6 &&
      obj.version !== 7 && obj.version !== 8) {
    throw new PolicyValidationError('policy.version must be 1, 2, 3, 4, 5, 6, 7, or 8');
  }

  const allowedFields =
    obj.version === 1
      ? VERSION_1_POLICY_FIELDS
      : obj.version === 2
        ? VERSION_2_POLICY_FIELDS
        : obj.version === 3
          ? VERSION_3_POLICY_FIELDS
          : obj.version === 4
            ? VERSION_4_POLICY_FIELDS
            : obj.version === 5
              ? VERSION_5_POLICY_FIELDS
              : obj.version === 6
                ? VERSION_6_POLICY_FIELDS
                : obj.version === 7
                  ? VERSION_7_POLICY_FIELDS
                  : VERSION_8_POLICY_FIELDS;
  validateExactFields(
    obj,
    allowedFields,
  );

  if (typeof obj.service !== 'string' || obj.service.trim() === '') {
    throw new PolicyValidationError('policy.service must be a non-empty string');
  }

  if (typeof obj.credential_class !== 'string' || obj.credential_class.trim() === '') {
    throw new PolicyValidationError(
      'policy.credential_class must be a non-empty string',
    );
  }

  if (isRejectedCredentialClass(obj.credential_class)) {
    throw new PolicyValidationError(
      `rejected credential_class; permanently unsupported: ${REJECTED_CREDENTIAL_CLASSES.join(', ')}`,
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
    CREDENTIAL_CLASS_BY_VERSION[
      /** @type {1|2|3|4|5|6|7|8} */ (obj.version)
    ];
  if (obj.credential_class !== expectedClass) {
    throw new PolicyValidationError(
      `policy.version ${obj.version} requires credential_class "${expectedClass}"`,
    );
  }

  const bind = parseLoopbackHttpUrl(obj.bind, 'policy.bind');
  const upstream = obj.version === 4 || obj.version === 5 ||
    obj.version === 7 || obj.version === 8
    ? null
    : parseLoopbackHttpUrl(obj.upstream, 'policy.upstream');

  if (obj.version === 5) {
    return validateBrowserFormLoginPolicy(obj, bind);
  }
  if (obj.version === 7) {
    return validateSshSessionPolicy(obj, bind);
  }
  if (obj.version === 8) {
    return validateFtpSessionPolicy(obj, bind);
  }

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
    method: obj.method,
    path: obj.path,
  };

  if (obj.version === 4) {
    const gateway = parseLoopbackHttpUrl(obj.gateway, 'policy.gateway');
    if (Number(gateway.port) === 0) {
      throw new PolicyValidationError('policy.gateway port must be non-zero');
    }
    if (typeof obj.target_host !== 'string' || !DNS_HOSTNAME.test(obj.target_host) ||
        isIP(obj.target_host) !== 0 ||
        obj.target_host.startsWith('xn--') || obj.target_host.includes('.xn--')) {
      throw new PolicyValidationError(
        'policy.target_host must be an exact lowercase ASCII DNS hostname without IP, IDNA, wildcard, or trailing dot syntax',
      );
    }
    if (obj.target_port !== 443) {
      throw new PolicyValidationError('policy.target_port must be exactly 443');
    }
    validateCredentialPlaceholder(obj.agent_token, 'policy.agent_token');
    return {
      version: 4,
      ...common,
      credential_class: 'onecli_proxy',
      gateway: gateway.href.replace(/\/$/, ''),
      target_host: obj.target_host,
      target_port: 443,
      agent_token: CREDENTIAL_PLACEHOLDER,
    };
  }

  const commonWithUpstream = {
    ...common,
    upstream: /** @type {URL} */ (upstream).href.replace(/\/$/, ''),
  };

  if (obj.version === 1) {
    if (typeof obj.authorization !== 'string') {
      throw new PolicyValidationError('policy.authorization must be a string');
    }
    validateCredentialPlaceholder(obj.authorization, 'policy.authorization');
    return {
      version: 1,
      ...commonWithUpstream,
      credential_class: 'http_bearer',
      authorization: CREDENTIAL_PLACEHOLDER,
    };
  }

  if (obj.version === 2) {
    validateApiKeyHeaderName(obj.header_name);
    if (typeof obj.header_value !== 'string') {
      throw new PolicyValidationError('policy.header_value must be a string');
    }
    validateCredentialPlaceholder(obj.header_value, 'policy.header_value');
    return {
      version: 2,
      ...commonWithUpstream,
      credential_class: 'http_api_key_header',
      header_name: /** @type {string} */ (obj.header_name),
      header_value: CREDENTIAL_PLACEHOLDER,
    };
  }

  if (obj.version === 6) {
    validateQueryParamName(obj.query_name);
    if (typeof obj.query_value !== 'string') {
      throw new PolicyValidationError('policy.query_value must be a string');
    }
    validateCredentialPlaceholder(obj.query_value, 'policy.query_value');
    return {
      version: 6,
      ...commonWithUpstream,
      credential_class: 'http_api_key_query',
      query_name: /** @type {string} */ (obj.query_name),
      query_value: CREDENTIAL_PLACEHOLDER,
    };
  }

  validateExactPlaceholder(
    obj.username_value,
    USERNAME_PLACEHOLDER,
    'policy.username_value',
  );
  validateExactPlaceholder(
    obj.password_value,
    PASSWORD_PLACEHOLDER,
    'policy.password_value',
  );
  return {
    version: 3,
    ...commonWithUpstream,
    credential_class: 'http_basic',
    username_value: USERNAME_PLACEHOLDER,
    password_value: PASSWORD_PLACEHOLDER,
  };
}

/**
 * @param {Record<string, unknown>} obj
 * @param {URL} bind
 * @param {URL} loginOrigin
 * @returns {BrowserFormLoginPolicy}
 */
function buildBrowserFormLoginPolicy(obj, bind, loginOrigin) {
  const loginPath = requireOriginPath(obj.login_path, 'policy.login_path');
  const formAction = requireOriginPath(obj.form_action, 'policy.form_action');
  const successPath = requireOriginPath(obj.success_path, 'policy.success_path');
  const replayPath = requireOriginPath(obj.replay_path, 'policy.replay_path');
  if (typeof obj.replay_method !== 'string' || !HTTP_METHODS.has(obj.replay_method)) {
    throw new PolicyValidationError(
      'policy.replay_method must be a standard HTTP method in uppercase',
    );
  }
  if (typeof obj.username_field !== 'string' || !FIELD_NAME.test(obj.username_field)) {
    throw new PolicyValidationError('policy.username_field must be an exact field name');
  }
  if (typeof obj.password_field !== 'string' || !FIELD_NAME.test(obj.password_field)) {
    throw new PolicyValidationError('policy.password_field must be an exact field name');
  }
  if (obj.username_field === obj.password_field) {
    throw new PolicyValidationError('policy username and password fields must differ');
  }
  if (!Array.isArray(obj.hidden_fields) || obj.hidden_fields.length > MAX_HIDDEN_FIELDS) {
    throw new PolicyValidationError('policy.hidden_fields must be a bounded exact name array');
  }
  const hiddenFields = [];
  for (const name of obj.hidden_fields) {
    if (typeof name !== 'string' || !FIELD_NAME.test(name)) {
      throw new PolicyValidationError('policy.hidden_fields entries must be exact field names');
    }
    if (name === obj.username_field || name === obj.password_field) {
      throw new PolicyValidationError('policy.hidden_fields must not repeat credential fields');
    }
    if (hiddenFields.includes(name)) {
      throw new PolicyValidationError('policy.hidden_fields must not contain duplicates');
    }
    hiddenFields.push(name);
  }
  if (!Array.isArray(obj.allowed_paths) || obj.allowed_paths.length < 1 ||
      obj.allowed_paths.length > MAX_ALLOWED_PATHS) {
    throw new PolicyValidationError('policy.allowed_paths must be a non-empty bounded path array');
  }
  const allowedPaths = [];
  for (const pathValue of obj.allowed_paths) {
    const path = requireOriginPath(pathValue, 'policy.allowed_paths');
    if (allowedPaths.includes(path)) {
      throw new PolicyValidationError('policy.allowed_paths must not contain duplicates');
    }
    allowedPaths.push(path);
  }
  if (!allowedPaths.includes(successPath)) {
    throw new PolicyValidationError('policy.success_path must be listed in allowed_paths');
  }
  if (!allowedPaths.includes(replayPath)) {
    throw new PolicyValidationError('policy.replay_path must be listed in allowed_paths');
  }
  if (obj.max_redirect_hops !== 1 && obj.max_redirect_hops !== 2 && obj.max_redirect_hops !== 3) {
    throw new PolicyValidationError('policy.max_redirect_hops must be 1, 2, or 3');
  }
  if (typeof obj.session_ttl_ms !== 'number' || !Number.isInteger(obj.session_ttl_ms) ||
      obj.session_ttl_ms < 1000 || obj.session_ttl_ms > 300000) {
    throw new PolicyValidationError('policy.session_ttl_ms must be an integer 1000–300000');
  }
  if (typeof obj.idle_ttl_ms !== 'number' || !Number.isInteger(obj.idle_ttl_ms) ||
      obj.idle_ttl_ms < 1000 || obj.idle_ttl_ms > obj.session_ttl_ms) {
    throw new PolicyValidationError('policy.idle_ttl_ms must be an integer 1000–session_ttl_ms');
  }
  validateExactPlaceholder(obj.username_value, USERNAME_PLACEHOLDER, 'policy.username_value');
  validateExactPlaceholder(obj.password_value, PASSWORD_PLACEHOLDER, 'policy.password_value');
  return {
    version: 5,
    service: /** @type {string} */ (obj.service),
    credential_class: 'browser_form_login',
    bind: bind.href.replace(/\/$/, ''),
    login_origin: loginOrigin.href.replace(/\/$/, ''),
    login_path: loginPath,
    form_action: formAction,
    username_field: /** @type {string} */ (obj.username_field),
    password_field: /** @type {string} */ (obj.password_field),
    hidden_fields: Object.freeze([...hiddenFields]),
    success_path: successPath,
    allowed_paths: Object.freeze([...allowedPaths]),
    replay_method: /** @type {string} */ (obj.replay_method),
    replay_path: replayPath,
    username_value: USERNAME_PLACEHOLDER,
    password_value: PASSWORD_PLACEHOLDER,
    max_redirect_hops: /** @type {number} */ (obj.max_redirect_hops),
    session_ttl_ms: /** @type {number} */ (obj.session_ttl_ms),
    idle_ttl_ms: /** @type {number} */ (obj.idle_ttl_ms),
  };
}

/**
 * @param {Record<string, unknown>} obj
 * @param {URL} bind
 * @returns {BrowserFormLoginPolicy}
 */
function validateBrowserFormLoginPolicy(obj, bind) {
  const loginOrigin = parseLoopbackHttpUrl(obj.login_origin, 'policy.login_origin');
  return buildBrowserFormLoginPolicy(obj, bind, loginOrigin);
}

/**
 * @param {Record<string, unknown>} obj
 * @param {URL} bind
 */
function validateSshSessionPolicy(obj, bind) {
  const target = parseLoopbackTarget(obj.target_host, obj.target_port);
  if (!Array.isArray(obj.allowed_commands) || obj.allowed_commands.length < 1 ||
      obj.allowed_commands.length > MAX_SSH_COMMANDS) {
    throw new PolicyValidationError('policy.allowed_commands must be a non-empty bounded array');
  }
  const allowedCommands = [];
  for (const command of obj.allowed_commands) {
    if (typeof command !== 'string' || !SSH_COMMAND_NAME.test(command)) {
      throw new PolicyValidationError('policy.allowed_commands entries must be exact lowercase command names');
    }
    if (allowedCommands.includes(command)) {
      throw new PolicyValidationError('policy.allowed_commands must not contain duplicates');
    }
    allowedCommands.push(command);
  }
  validateSessionTtls(obj);
  validateExactPlaceholder(obj.username_value, USERNAME_PLACEHOLDER, 'policy.username_value');
  validateExactPlaceholder(obj.password_value, PASSWORD_PLACEHOLDER, 'policy.password_value');
  return {
    version: 7,
    service: /** @type {string} */ (obj.service),
    credential_class: 'ssh',
    bind: bind.href.replace(/\/$/, ''),
    target_host: target.host,
    target_port: target.port,
    allowed_commands: Object.freeze([...allowedCommands]),
    username_value: USERNAME_PLACEHOLDER,
    password_value: PASSWORD_PLACEHOLDER,
    session_ttl_ms: /** @type {number} */ (obj.session_ttl_ms),
    idle_ttl_ms: /** @type {number} */ (obj.idle_ttl_ms),
  };
}

/**
 * @param {Record<string, unknown>} obj
 * @param {URL} bind
 */
function validateFtpSessionPolicy(obj, bind) {
  const target = parseLoopbackTarget(obj.target_host, obj.target_port);
  if (!Array.isArray(obj.allowed_ops) || obj.allowed_ops.length < 1 ||
      obj.allowed_ops.length > FTP_OPS.size) {
    throw new PolicyValidationError('policy.allowed_ops must be a non-empty subset of list,retr');
  }
  const allowedOps = [];
  for (const op of obj.allowed_ops) {
    if (typeof op !== 'string' || !FTP_OPS.has(op)) {
      throw new PolicyValidationError('policy.allowed_ops entries must be list or retr');
    }
    if (allowedOps.includes(op)) {
      throw new PolicyValidationError('policy.allowed_ops must not contain duplicates');
    }
    allowedOps.push(op);
  }
  if (!Array.isArray(obj.allowed_paths) || obj.allowed_paths.length < 1 ||
      obj.allowed_paths.length > MAX_FTP_PATHS) {
    throw new PolicyValidationError('policy.allowed_paths must be a non-empty bounded path array');
  }
  const allowedPaths = [];
  for (const pathValue of obj.allowed_paths) {
    const path = requireOriginPath(pathValue, 'policy.allowed_paths');
    if (allowedPaths.includes(path)) {
      throw new PolicyValidationError('policy.allowed_paths must not contain duplicates');
    }
    allowedPaths.push(path);
  }
  validateSessionTtls(obj);
  validateExactPlaceholder(obj.username_value, USERNAME_PLACEHOLDER, 'policy.username_value');
  validateExactPlaceholder(obj.password_value, PASSWORD_PLACEHOLDER, 'policy.password_value');
  return {
    version: 8,
    service: /** @type {string} */ (obj.service),
    credential_class: 'ftp',
    bind: bind.href.replace(/\/$/, ''),
    target_host: target.host,
    target_port: target.port,
    allowed_ops: Object.freeze([...allowedOps]),
    allowed_paths: Object.freeze([...allowedPaths]),
    username_value: USERNAME_PLACEHOLDER,
    password_value: PASSWORD_PLACEHOLDER,
    session_ttl_ms: /** @type {number} */ (obj.session_ttl_ms),
    idle_ttl_ms: /** @type {number} */ (obj.idle_ttl_ms),
  };
}

/**
 * @param {Record<string, unknown>} obj
 */
function validateSessionTtls(obj) {
  if (typeof obj.session_ttl_ms !== 'number' || !Number.isInteger(obj.session_ttl_ms) ||
      obj.session_ttl_ms < 1000 || obj.session_ttl_ms > 300000) {
    throw new PolicyValidationError('policy.session_ttl_ms must be an integer 1000–300000');
  }
  if (typeof obj.idle_ttl_ms !== 'number' || !Number.isInteger(obj.idle_ttl_ms) ||
      obj.idle_ttl_ms < 1000 || obj.idle_ttl_ms > obj.session_ttl_ms) {
    throw new PolicyValidationError('policy.idle_ttl_ms must be an integer 1000–session_ttl_ms');
  }
}

/**
 * @param {unknown} host
 * @param {unknown} port
 * @returns {{ host: string, port: number }}
 */
function parseLoopbackTarget(host, port) {
  if (typeof host !== 'string' || !LOOPBACK_TARGET_HOSTS.has(host)) {
    throw new PolicyValidationError('policy.target_host must be 127.0.0.1 or localhost');
  }
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 0 || port > 65535) {
    throw new PolicyValidationError('policy.target_port must be an integer 0–65535');
  }
  return { host, port };
}

function requireOriginPath(value, fieldName) {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('?') ||
    value.includes('#') ||
    value.includes('*')
  ) {
    throw new PolicyValidationError(
      `${fieldName} must be an exact origin-relative path without query, fragment, or wildcards`,
    );
  }
  return value;
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

/** Return a validated v4 policy with a concrete loopback gateway origin. */
export function withGateway(policy, gatewayUrl) {
  if (policy?.version !== 4) {
    throw new PolicyValidationError('withGateway requires a version-4 policy');
  }
  const gateway = parseLoopbackHttpUrl(gatewayUrl, 'gateway');
  return validatePolicy({ ...policy, gateway: gateway.href.replace(/\/$/, '') });
}

/** Return a validated v5 policy with a concrete loopback login origin. */
export function withLoginOrigin(policy, loginOriginUrl) {
  if (policy?.version !== 5) {
    throw new PolicyValidationError('withLoginOrigin requires a version-5 policy');
  }
  const loginOrigin = parseLoopbackHttpUrl(loginOriginUrl, 'login_origin');
  return validatePolicy({
    ...policy,
    login_origin: loginOrigin.href.replace(/\/$/, ''),
    hidden_fields: [...policy.hidden_fields],
    allowed_paths: [...policy.allowed_paths],
  });
}

/**
 * Bind a concrete loopback SSH/FTP target port after the fake server starts.
 * @param {object} policy
 * @param {{ host?: string, port: number }} target
 */
export function withSessionTarget(policy, target) {
  if (policy?.version !== 7 && policy?.version !== 8) {
    throw new PolicyValidationError('withSessionTarget requires a version-7 or version-8 policy');
  }
  const host = typeof target?.host === 'string' ? target.host : policy.target_host;
  const port = target?.port;
  const payload = {
    ...policy,
    target_host: host,
    target_port: port,
    username_value: USERNAME_PLACEHOLDER,
    password_value: PASSWORD_PLACEHOLDER,
  };
  if (policy.version === 7) {
    payload.allowed_commands = [...policy.allowed_commands];
  } else {
    payload.allowed_ops = [...policy.allowed_ops];
    payload.allowed_paths = [...policy.allowed_paths];
  }
  return validatePolicy(payload);
}

/**
 * Validate a version-5 browser policy against a branded live HTTPS gate.
 * Loopback-only validatePolicy remains unchanged for harness tests.
 * @param {unknown} raw
 * @param {object} gate
 * @returns {BrowserFormLoginPolicy}
 */
export function validateLiveBrowserFormLoginPolicy(raw, gate) {
  assertBrandedBrowserLiveGate(gate);
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new PolicyValidationError('policy must be a JSON object');
  }
  /** @type {Record<string, unknown>} */
  const obj = /** @type {Record<string, unknown>} */ (raw);
  if (obj.version !== 5 || obj.credential_class !== 'browser_form_login') {
    throw new PolicyValidationError('live browser policy must be version 5 browser_form_login');
  }
  validateExactFields(obj, VERSION_5_POLICY_FIELDS);
  if (typeof obj.service !== 'string' || obj.service.trim() === '') {
    throw new PolicyValidationError('policy.service must be a non-empty string');
  }
  const bind = parseLoopbackHttpUrl(obj.bind, 'policy.bind');
  let loginOrigin;
  try {
    loginOrigin = new URL(/** @type {string} */ (obj.login_origin));
  } catch {
    throw new PolicyValidationError('policy.login_origin must be a valid URL');
  }
  if (loginOrigin.protocol !== 'https:') {
    throw new PolicyValidationError('live policy.login_origin must use https');
  }
  if (loginOrigin.hostname !== gate.pinned_hostname) {
    throw new PolicyValidationError('live policy.login_origin hostname must match the branded gate');
  }
  if (loginOrigin.username || loginOrigin.password || loginOrigin.search || loginOrigin.hash) {
    throw new PolicyValidationError('live policy.login_origin must be a bare origin');
  }
  if (loginOrigin.pathname !== '/' && loginOrigin.pathname !== '') {
    throw new PolicyValidationError('live policy.login_origin must not include a path');
  }
  return buildBrowserFormLoginPolicy(obj, bind, loginOrigin);
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
function validateQueryParamName(value) {
  if (typeof value !== 'string' || !QUERY_PARAM_NAME.test(value)) {
    throw new PolicyValidationError(
      'policy.query_name must match ^[a-z][a-z0-9_-]{0,63}$',
    );
  }
}

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

/**
 * @param {unknown} value
 * @param {string} placeholder
 * @param {string} fieldName
 */
function validateExactPlaceholder(value, placeholder, fieldName) {
  if (value === placeholder) return;
  const kind =
    typeof value === 'string' && /\{\{[^}]*\}\}/.test(value)
      ? 'unsupported placeholder rejected'
      : 'literal credential values are rejected';
  throw new PolicyValidationError(
    `${fieldName} must be exactly ${placeholder}; ${kind}`,
  );
}

export class PolicyValidationError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'PolicyValidationError';
  }
}
