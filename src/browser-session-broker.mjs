import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { validateBasicCredentials } from './basic-credentials.js';
import { PASSWORD_PLACEHOLDER, USERNAME_PLACEHOLDER } from './constants.js';
import {
  assertBrandedBrowserLiveGate,
} from './browser-form-login-live-gate.mjs';
import { validateLiveBrowserFormLoginPolicy, validatePolicy } from './policy.js';

export class BrowserSessionBrokerError extends Error {
  /**
   * @param {string} code
   */
  constructor(code) {
    super(`Browser session broker rejected: ${code}`);
    this.name = 'BrowserSessionBrokerError';
    this.code = code;
  }
}

/** @type {boolean} */
let writerBusy = false;

const MFA_HINT = /\b(mfa|2fa|totp|otp|one[-\s]?time)|mfa_required|otp_required\b/i;
const CAPTCHA_HINT = /\b(captcha|recaptcha|hcaptcha|bot[-\s]?check)\b/i;
/** Maximum response body buffered by the browser session broker (1 MiB). */
export const MAX_BROWSER_RESPONSE_BODY_BYTES = 1 * 1024 * 1024;

/**
 * Start a disposable/dev browser form-login session broker.
 * Uses stdlib fetch + in-memory cookie jar. Never routes through startBroker.
 *
 * @param {{
 *   policy: unknown,
 *   credentials: import('./basic-credentials.js').BasicCredentials,
 *   fetchImpl?: typeof fetch,
 *   log?: (entry: {level:string,message:string,meta?:object}) => void,
 *   liveGate?: object | null,
 * }} options
 */
export async function startBrowserSessionBroker(options) {
  if (writerBusy) {
    throw new BrowserSessionBrokerError('concurrent_session_forbidden');
  }

  let policy;
  try {
    if (options.liveGate) {
      assertBrandedBrowserLiveGate(options.liveGate);
      policy = validateLiveBrowserFormLoginPolicy(options.policy, options.liveGate);
    } else {
      policy = validatePolicy(options.policy);
    }
  } catch (error) {
    if (error && typeof error === 'object' && error.name === 'BrowserFormLoginLiveGateError') {
      throw new BrowserSessionBrokerError('invalid_live_gate');
    }
    throw new BrowserSessionBrokerError('invalid_policy');
  }
  if (policy.credential_class !== 'browser_form_login' || policy.version !== 5) {
    throw new BrowserSessionBrokerError('wrong_broker');
  }
  if (policy.username_value !== USERNAME_PLACEHOLDER ||
      policy.password_value !== PASSWORD_PLACEHOLDER) {
    throw new BrowserSessionBrokerError('invalid_policy');
  }

  let credentials;
  try {
    credentials = validateBasicCredentials(options.credentials);
  } catch {
    throw new BrowserSessionBrokerError('invalid_credentials');
  }

  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const logs = [];
  const rawLog = options.log ?? ((entry) => { logs.push(entry); });
  /** @type {Set<string>} */
  const sensitive = buildCredentialSensitiveVariants(credentials);
  const log = (entry) => {
    rawLog({
      level: entry.level,
      message: redact(entry.message, sensitive),
      ...(entry.meta ? { meta: /** @type {object} */ (redact(entry.meta, sensitive)) } : {}),
    });
  };

  writerBusy = true;
  /** @type {Map<string, string>} */
  const jar = new Map();
  const createdAt = Date.now();
  let lastUsedAt = createdAt;
  let closed = false;

  try {
    await performLogin({
      policy,
      credentials,
      fetchImpl,
      jar,
      sensitive,
      log,
    });
  } catch (error) {
    writerBusy = false;
    jar.clear();
    throw error;
  }

  const sessionId = randomBytes(32).toString('hex');
  const bindUrl = new URL(policy.bind);
  const server = http.createServer((req, res) => {
    void handleReplay(req, res, {
      policy,
      fetchImpl,
      jar,
      sensitive,
      sessionId,
      createdAt,
      getLastUsed: () => lastUsedAt,
      touch: () => { lastUsedAt = Date.now(); },
      log,
      isClosed: () => closed,
    });
  });

  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(Number(bindUrl.port), bindUrl.hostname, () => {
        server.off('error', reject);
        resolve(undefined);
      });
    });
  } catch {
    closed = true;
    writerBusy = false;
    jar.clear();
    await closeServer(server).catch(() => {});
    throw new BrowserSessionBrokerError('bind_failed');
  }

  const address = server.address();
  if (address === null || typeof address === 'string') {
    closed = true;
    writerBusy = false;
    jar.clear();
    await closeServer(server);
    throw new BrowserSessionBrokerError('bind_failed');
  }

  const baseUrl = `http://${bindUrl.hostname}:${address.port}`;
  log({ level: 'info', message: 'browser session broker listening', meta: { bind: baseUrl } });

  return {
    session_id: sessionId,
    logged_in: true,
    origin_bound: true,
    baseUrl,
    replayUrl: `${baseUrl}${policy.replay_path}`,
    logs,
    async close() {
      if (closed) return;
      closed = true;
      jar.clear();
      sensitive.clear();
      writerBusy = false;
      await closeServer(server);
    },
  };
}

async function performLogin(ctx) {
  const { policy, credentials, fetchImpl, jar, sensitive, log } = ctx;
  const origin = policy.login_origin.replace(/\/$/, '');
  const loginUrl = `${origin}${policy.login_path}`;

  const formResponse = await fetchImpl(loginUrl, { method: 'GET', redirect: 'manual' });
  const formText = await readBoundedText(formResponse);
  assertNoChallenge(formText);
  const hiddenValues = extractPinnedHiddenFields(formText, policy.hidden_fields);

  const body = new URLSearchParams();
  body.set(policy.username_field, credentials.username);
  body.set(policy.password_field, credentials.password);
  for (const [name, value] of Object.entries(hiddenValues)) {
    body.set(name, value);
  }

  let url = `${origin}${policy.form_action}`;
  let hops = 0;
  let response = await fetchImpl(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: cookieHeader(jar),
    },
    body: body.toString(),
    redirect: 'manual',
  });
  ingestSetCookie(response, jar, sensitive, origin);

  while (isRedirect(response.status) && hops < policy.max_redirect_hops) {
    const location = response.headers.get('location');
    if (typeof location !== 'string' || location.length < 1) {
      throw new BrowserSessionBrokerError('login_failed');
    }
    const next = new URL(location, url);
    if (next.origin !== new URL(origin).origin) {
      throw new BrowserSessionBrokerError('cross_origin_redirect');
    }
    if (!policy.allowed_paths.includes(next.pathname) && next.pathname !== policy.login_path &&
        next.pathname !== policy.form_action && next.pathname !== policy.success_path) {
      // Allow hop only onto success or allowed paths after login.
      if (next.pathname !== policy.success_path && !policy.allowed_paths.includes(next.pathname)) {
        throw new BrowserSessionBrokerError('redirect_path_denied');
      }
    }
    hops += 1;
    url = next.href;
    response = await fetchImpl(url, {
      method: 'GET',
      headers: { cookie: cookieHeader(jar) },
      redirect: 'manual',
    });
    ingestSetCookie(response, jar, sensitive, origin);
  }

  if (isRedirect(response.status)) {
    throw new BrowserSessionBrokerError('redirect_hop_exhausted');
  }

  const finalText = await readBoundedText(response);
  assertNoChallenge(finalText);
  if (!response.ok) {
    throw new BrowserSessionBrokerError('login_failed');
  }

  const finalUrl = new URL(url);
  if (finalUrl.pathname !== policy.success_path && !policy.allowed_paths.includes(finalUrl.pathname)) {
    // Some sites land on success via 200 at success_path only.
    if (finalUrl.pathname !== policy.success_path) {
      throw new BrowserSessionBrokerError('success_path_mismatch');
    }
  }

  // Confirm success path with cookie.
  const verify = await fetchImpl(`${origin}${policy.success_path}`, {
    method: 'GET',
    headers: { cookie: cookieHeader(jar) },
    redirect: 'manual',
  });
  ingestSetCookie(verify, jar, sensitive, origin);
  const verifyText = await readBoundedText(verify);
  assertNoChallenge(verifyText);
  if (!verify.ok) {
    throw new BrowserSessionBrokerError('login_failed');
  }
  if (jar.size < 1) {
    throw new BrowserSessionBrokerError('session_cookie_absent');
  }
  log({ level: 'info', message: 'browser form login succeeded' });
}

async function handleReplay(req, res, ctx) {
  const {
    policy, fetchImpl, jar, sensitive, sessionId, createdAt, getLastUsed, touch, log, isClosed,
  } = ctx;
  if (isClosed()) {
    writeFixed(res, 503, 'session_closed');
    return;
  }
  const now = Date.now();
  if (now - createdAt > policy.session_ttl_ms || now - getLastUsed() > policy.idle_ttl_ms) {
    writeFixed(res, 401, 'session_expired');
    return;
  }

  const requestUrl = new URL(req.url ?? '/', 'http://127.0.0.1');
  if (req.method !== policy.replay_method ||
      !policy.allowed_paths.includes(requestUrl.pathname)) {
    writeFixed(res, 404, 'not_found');
    return;
  }
  if (requestUrl.search || requestUrl.hash) {
    writeFixed(res, 400, 'query_forbidden');
    return;
  }

  // Strip any caller cookies/authorization; broker injects jar only.
  touch();
  const origin = policy.login_origin.replace(/\/$/, '');
  const upstreamUrl = `${origin}${requestUrl.pathname}`;
  let upstream;
  try {
    upstream = await fetchImpl(upstreamUrl, {
      method: policy.replay_method,
      headers: { cookie: cookieHeader(jar), accept: 'application/json, text/plain, */*' },
      redirect: 'manual',
    });
  } catch {
    writeFixed(res, 502, 'upstream_failed');
    return;
  }
  if (isRedirect(upstream.status)) {
    writeFixed(res, 502, 'redirect_denied');
    return;
  }
  ingestSetCookie(upstream, jar, sensitive, origin);
  let text;
  try {
    text = await readBoundedText(upstream);
  } catch (error) {
    if (error instanceof BrowserSessionBrokerError && error.code === 'response_too_large') {
      writeFixed(res, 502, 'response_too_large');
      return;
    }
    writeFixed(res, 502, 'upstream_failed');
    return;
  }
  if (containsSensitive(text, sensitive) || containsSensitiveHeader(upstream.headers, sensitive)) {
    log({ level: 'error', message: 'blocked sensitive upstream payload' });
    writeFixed(res, 502, 'sensitive_response_blocked');
    return;
  }
  const contentType = upstream.headers.get('content-type') ?? 'application/octet-stream';
  res.writeHead(upstream.status, {
    'content-type': contentType,
    'x-bridge-session': 'bound',
    'x-bridge-session-id-present': sessionId.length === 64 ? 'true' : 'false',
  });
  res.end(text);
}

async function readBoundedText(response) {
  const lengthHeader = response.headers.get('content-length');
  if (lengthHeader !== null) {
    const declared = Number(lengthHeader);
    if (Number.isFinite(declared) && declared > MAX_BROWSER_RESPONSE_BODY_BYTES) {
      if (typeof response.body?.cancel === 'function') {
        await response.body.cancel().catch(() => {});
      }
      throw new BrowserSessionBrokerError('response_too_large');
    }
  }
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > MAX_BROWSER_RESPONSE_BODY_BYTES) {
    throw new BrowserSessionBrokerError('response_too_large');
  }
  return buffer.toString('utf8');
}

function assertNoChallenge(text) {
  if (MFA_HINT.test(text)) {
    throw new BrowserSessionBrokerError('mfa_required');
  }
  if (CAPTCHA_HINT.test(text)) {
    throw new BrowserSessionBrokerError('captcha_required');
  }
}

function extractPinnedHiddenFields(html, names) {
  /** @type {Record<string, string>} */
  const out = Object.create(null);
  for (const name of names) {
    const pattern = new RegExp(
      `<input[^>]*type=["']hidden["'][^>]*name=["']${escapeRegExp(name)}["'][^>]*value=["']([^"']*)["'][^>]*>` +
      `|<input[^>]*name=["']${escapeRegExp(name)}["'][^>]*type=["']hidden["'][^>]*value=["']([^"']*)["'][^>]*>`,
      'i',
    );
    const match = html.match(pattern);
    if (!match) {
      throw new BrowserSessionBrokerError('hidden_field_missing');
    }
    out[name] = match[1] ?? match[2] ?? '';
  }
  return out;
}

function ingestSetCookie(response, jar, sensitive, origin) {
  const headers = typeof response.headers.getSetCookie === 'function'
    ? response.headers.getSetCookie()
    : rawSetCookie(response.headers);
  for (const line of headers) {
    const pair = String(line).split(';', 1)[0];
    const eq = pair.indexOf('=');
    if (eq < 1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!name || !value) continue;
    jar.set(name, value);
    if (jar.size > 32) {
      throw new BrowserSessionBrokerError('cookie_jar_overflow');
    }
    for (const variant of sensitiveVariantsFor(value)) sensitive.add(variant);
    for (const variant of sensitiveVariantsFor(`${name}=${value}`)) sensitive.add(variant);
  }
  void origin;
}

function rawSetCookie(headers) {
  const any = headers;
  if (typeof any.raw === 'function') {
    const raw = any.raw();
    if (raw && Array.isArray(raw['set-cookie'])) return raw['set-cookie'];
  }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

function cookieHeader(jar) {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

function isRedirect(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function buildCredentialSensitiveVariants(credentials) {
  const set = new Set();
  for (const value of [
    credentials.username,
    credentials.password,
    `${credentials.username}:${credentials.password}`,
    `${credentials.username}=${credentials.password}`,
  ]) {
    for (const variant of sensitiveVariantsFor(value)) set.add(variant);
    // application/x-www-form-urlencoded uses + for spaces.
    set.add(encodeURIComponent(value).replace(/%20/g, '+'));
  }
  return set;
}

function sensitiveVariantsFor(value) {
  const upperPercent = encodeURIComponent(value);
  const lowerPercent = upperPercent.replace(/%[0-9A-F]{2}/g, (t) => t.toLowerCase());
  return [
    value,
    upperPercent,
    lowerPercent,
    upperPercent.replace(/%20/g, '+'),
    Buffer.from(value, 'utf8').toString('base64'),
    Buffer.from(value, 'utf8').toString('base64url'),
    JSON.stringify(value).slice(1, -1),
  ].filter((v) => v.length > 0);
}

function containsSensitive(text, sensitive) {
  for (const variant of sensitive) {
    if (variant.length >= 8 && text.includes(variant)) return true;
  }
  return false;
}

function containsSensitiveHeader(headers, sensitive) {
  for (const [name, value] of headers.entries()) {
    if (name === 'set-cookie' || containsSensitive(String(value), sensitive)) return true;
  }
  return false;
}

function redact(value, sensitive) {
  if (typeof value === 'string') {
    let out = value;
    for (const variant of sensitive) {
      if (variant.length >= 8) out = out.split(variant).join('[REDACTED]');
    }
    return out;
  }
  if (Array.isArray(value)) return value.map((item) => redact(item, sensitive));
  if (value !== null && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redact(v, sensitive);
    return out;
  }
  return value;
}

function writeFixed(res, status, code) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: code }));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    server.close(() => resolve());
  });
}
