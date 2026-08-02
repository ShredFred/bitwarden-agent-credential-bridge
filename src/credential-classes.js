/**
 * Canonical credential-class registry for the fake/disposable harness.
 * Keep policy, broker, resolvers, and planners aligned on this module.
 */

/** Classes the harness can inject under their dedicated brokers. */
export const SUPPORTED_CREDENTIAL_CLASSES = Object.freeze([
  'http_bearer',
  'http_api_key_header',
  'http_basic',
  'onecli_proxy',
  'browser_form_login',
  'http_api_key_query',
]);

/**
 * Named HQ auth shapes that are permanently rejected (stable codes).
 * Unknown names remain default-denied via the supported allow-list.
 */
export const REJECTED_CREDENTIAL_CLASSES = Object.freeze([
  'oauth',
  'mfa_interactive',
  'sms',
  'email',
  'ssh',
  'ftp',
  'env_inject',
]);

/** Policy version → exact credential class. */
export const CREDENTIAL_CLASS_BY_VERSION = Object.freeze({
  1: 'http_bearer',
  2: 'http_api_key_header',
  3: 'http_basic',
  4: 'onecli_proxy',
  5: 'browser_form_login',
  6: 'http_api_key_query',
});

/** Classes accepted by startBroker (HTTP header/query/basic injection). */
export const HTTP_INJECTION_CREDENTIAL_CLASSES = Object.freeze([
  'http_bearer',
  'http_api_key_header',
  'http_basic',
  'http_api_key_query',
]);

/** Classes that resolve through sentinel-shaped vault adapters. */
export const SENTINEL_CREDENTIAL_CLASSES = Object.freeze([
  'http_bearer',
  'http_api_key_header',
  'http_api_key_query',
]);

/** Classes that resolve through username/password vault adapters. */
export const BASIC_SHAPED_CREDENTIAL_CLASSES = Object.freeze([
  'http_basic',
  'browser_form_login',
]);

/**
 * @param {unknown} name
 * @returns {name is string}
 */
export function isRejectedCredentialClass(name) {
  return typeof name === 'string' && REJECTED_CREDENTIAL_CLASSES.includes(name);
}

/**
 * @param {unknown} name
 * @returns {name is string}
 */
export function isSupportedCredentialClass(name) {
  return typeof name === 'string' && SUPPORTED_CREDENTIAL_CLASSES.includes(name);
}
