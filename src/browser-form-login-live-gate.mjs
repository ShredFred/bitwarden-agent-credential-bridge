import { types as utilTypes } from 'node:util';

export class BrowserFormLoginLiveGateError extends Error {
  constructor(code = 'invalid_live_gate') {
    super(`Browser form-login live gate rejected: ${code}`);
    this.name = 'BrowserFormLoginLiveGateError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();
const DNS_HOSTNAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * Brand an in-process operator gate for non-loopback disposable HTTPS login.
 * Approval is out-of-band; this API accepts no approval secret.
 */
export function buildBrowserFormLoginLiveGate(pinnedHostname) {
  if (typeof pinnedHostname !== 'string' || !DNS_HOSTNAME.test(pinnedHostname) ||
      pinnedHostname.includes('*') || pinnedHostname.startsWith('xn--')) {
    throw new BrowserFormLoginLiveGateError('invalid_hostname');
  }
  const gate = Object.freeze({
    schema_version: 1,
    mode: 'browser_form_login_live',
    pinned_hostname: pinnedHostname,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    helper_vault_free: true,
    playwright_default_absent: true,
    mutation_authorized: false,
    live_test_executed: false,
    authorization_ready: false,
  });
  VALID_GATES.add(gate);
  return gate;
}

export function isBrowserFormLoginLiveGate(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

/**
 * Validate an HTTPS login origin against a branded live gate.
 * @param {unknown} value
 * @param {object} gate
 * @returns {URL}
 */
export function parseLiveHttpsLoginOrigin(value, gate) {
  if (!isBrowserFormLoginLiveGate(gate)) {
    throw new BrowserFormLoginLiveGateError('unbranded_gate');
  }
  if (typeof value !== 'string' || value.trim() === '') {
    throw new BrowserFormLoginLiveGateError('invalid_origin');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new BrowserFormLoginLiveGateError('invalid_origin');
  }
  if (url.protocol !== 'https:') {
    throw new BrowserFormLoginLiveGateError('https_required');
  }
  if (url.hostname !== gate.pinned_hostname) {
    throw new BrowserFormLoginLiveGateError('hostname_mismatch');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new BrowserFormLoginLiveGateError('invalid_origin');
  }
  if (url.pathname !== '/' && url.pathname !== '') {
    throw new BrowserFormLoginLiveGateError('origin_path_forbidden');
  }
  return url;
}

/**
 * Reject forged/cloned gate objects that are not WeakSet-branded.
 */
export function assertBrandedBrowserLiveGate(value) {
  if (utilTypes.isProxy(value) || !isBrowserFormLoginLiveGate(value)) {
    throw new BrowserFormLoginLiveGateError('unbranded_gate');
  }
  return value;
}
