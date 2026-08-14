import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { validateBasicCredentials } from './basic-credentials.js';
import { PASSWORD_PLACEHOLDER, USERNAME_PLACEHOLDER } from './constants.js';
import { createFetchPageAdapter } from './bridge-browser-fake-adapter.mjs';
import {
  ALLOWED_AGENT_OPS,
  AGENT_ERROR_CODES,
  BridgeBrowserTargetingError,
  authorizeTargetSelection,
  assertInjectSafe,
  denyAgentOp,
  enumerateAgentCandidates,
  FORBIDDEN_AGENT_OPS,
  parseTargetSelection,
} from './bridge-browser-targeting.mjs';
import { validatePolicy } from './policy.js';

export class BridgeOwnedBrowserError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(`Bridge-owned browser rejected: ${code}`);
    this.name = 'BridgeOwnedBrowserError';
    this.code = code;
  }
}

export const MAX_BRIDGE_OWNED_BROWSERS = 1;

/** @type {number} */
let activeSessions = 0;

/**
 * Start a Bridge-owned browser session for v5 browser_form_login.
 * The agent can snapshot candidates and select indices. Only this process
 * injects credentials. Cookies never leave the adapter jar.
 *
 * @param {{
 *   policy: unknown,
 *   credentials: import('./basic-credentials.js').BasicCredentials,
 *   adapter?: ReturnType<typeof createFetchPageAdapter>,
 *   driver?: 'fetch' | 'playwright',
 *   playwright?: object,
 *   browser?: 'chromium' | 'firefox' | 'webkit',
 *   headless?: boolean,
 *   log?: (entry: {level:string,message:string,meta?:object}) => void,
 * }} options
 */
export async function startBridgeOwnedBrowser(options) {
  if (activeSessions >= MAX_BRIDGE_OWNED_BROWSERS) {
    throw new BridgeOwnedBrowserError('concurrent_session_forbidden');
  }

  let policy;
  try {
    policy = validatePolicy(options.policy);
  } catch {
    throw new BridgeOwnedBrowserError('invalid_policy');
  }
  if (policy.credential_class !== 'browser_form_login' || policy.version !== 5) {
    throw new BridgeOwnedBrowserError('wrong_broker');
  }
  if (policy.username_value !== USERNAME_PLACEHOLDER ||
      policy.password_value !== PASSWORD_PLACEHOLDER) {
    throw new BridgeOwnedBrowserError('invalid_policy');
  }

  let credentials;
  try {
    credentials = validateBasicCredentials(options.credentials);
  } catch {
    throw new BridgeOwnedBrowserError('invalid_credentials');
  }

  let adapter = options.adapter;
  if (!adapter) {
    if (options.driver === 'playwright') {
      try {
        const { createPlaywrightPageAdapter } = await import('./bridge-browser-playwright-adapter.mjs');
        adapter = await createPlaywrightPageAdapter({
          origin: policy.login_origin,
          loginPath: policy.login_path,
          playwright: options.playwright,
          headless: options.headless,
          browser: options.browser,
        });
      } catch (error) {
        if (error instanceof BridgeBrowserTargetingError) {
          throw new BridgeOwnedBrowserError(error.code);
        }
        throw new BridgeOwnedBrowserError('playwright_launch_failed');
      }
    } else if (options.driver === undefined || options.driver === 'fetch') {
      adapter = createFetchPageAdapter({
        origin: policy.login_origin,
        loginPath: policy.login_path,
      });
    } else {
      throw new BridgeOwnedBrowserError('invalid_request');
    }
  }

  /** @type {Set<string>} */
  const sensitive = buildCredentialSensitiveVariants(credentials);
  const logs = [];
  const rawLog = options.log ?? ((entry) => { logs.push(entry); });
  const log = (entry) => {
    rawLog({
      level: entry.level,
      message: redact(entry.message, sensitive),
      ...(entry.meta ? { meta: redact(entry.meta, sensitive) } : {}),
    });
  };

  activeSessions += 1;
  const sessionId = randomBytes(32).toString('hex');
  const createdAt = Date.now();
  let lastUsedAt = createdAt;
  let closed = false;
  let loggedIn = false;
  let generation = 0;
  /** @type {null | { generation: number, origin: string, candidates: readonly object[], form_action: string }} */
  let lastSnapshot = null;
  /** @type {null | ReturnType<typeof authorizeTargetSelection>} */
  let authorized = null;

  const bindUrl = new URL(policy.bind);
  const server = http.createServer((req, res) => {
    void handleAgentRequest(req, res, {
      policy,
      credentials,
      adapter,
      sensitive,
      sessionId,
      createdAt,
      getLastUsed: () => lastUsedAt,
      touch: () => { lastUsedAt = Date.now(); },
      log,
      isClosed: () => closed,
      getLoggedIn: () => loggedIn,
      setLoggedIn: (value) => { loggedIn = value; },
      getGeneration: () => generation,
      bumpGeneration: () => {
        generation += 1;
        lastSnapshot = null;
        authorized = null;
        return generation;
      },
      getLastSnapshot: () => lastSnapshot,
      setLastSnapshot: (snap) => { lastSnapshot = snap; },
      getAuthorized: () => authorized,
      setAuthorized: (value) => { authorized = value; },
    });
  });

  try {
    await listenHttp(server, bindUrl);
  } catch {
    closed = true;
    activeSessions = Math.max(0, activeSessions - 1);
    await adapter.close();
    throw new BridgeOwnedBrowserError('bind_failed');
  }

  const address = server.address();
  if (address === null || typeof address === 'string') {
    closed = true;
    activeSessions = Math.max(0, activeSessions - 1);
    await adapter.close();
    await closeHttp(server);
    throw new BridgeOwnedBrowserError('bind_failed');
  }

  const baseUrl = `http://${bindUrl.hostname}:${address.port}`;
  log({ level: 'info', message: 'bridge-owned browser listening', meta: { bind: baseUrl } });

  return {
    session_id: sessionId,
    get logged_in() {
      return loggedIn;
    },
    origin_bound: true,
    agent_cdp_absent: true,
    cookie_export_forbidden: true,
    authorization_ready: false,
    helper_vault_free: true,
    agent_secret_visible: false,
    baseUrl,
    logs,
    async close() {
      if (closed) return;
      closed = true;
      await adapter.close();
      sensitive.clear();
      activeSessions = Math.max(0, activeSessions - 1);
      await closeHttp(server);
    },
  };
}

async function handleAgentRequest(req, res, ctx) {
  const { policy, sensitive, sessionId, createdAt, getLastUsed, touch, log, isClosed } = ctx;
  if (isClosed()) {
    writeFixed(res, 503, 'session_closed');
    return;
  }
  const now = Date.now();
  if (now - createdAt > policy.session_ttl_ms || now - getLastUsed() > policy.idle_ttl_ms) {
    writeFixed(res, 401, 'session_expired');
    return;
  }
  touch();

  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  const op = opFromPath(req.method ?? '', url.pathname);
  const deny = denyAgentOp(op);
  if (deny) {
    writeFixed(res, 403, deny);
    return;
  }

  try {
    if (op === 'status' && req.method === 'GET') {
      writeJson(res, sensitive, {
        ok: true,
        logged_in: ctx.getLoggedIn(),
        origin_bound: true,
        agent_cdp_absent: true,
        cookie_export_forbidden: true,
        authorization_ready: false,
        helper_vault_free: true,
        agent_secret_visible: false,
        session_id: sessionId,
        allowed_ops: ALLOWED_AGENT_OPS,
      });
      return;
    }

    if (op === 'contract' && req.method === 'GET') {
      writeJson(res, sensitive, {
        ok: true,
        allowed_ops: ALLOWED_AGENT_OPS,
        forbidden_ops: FORBIDDEN_AGENT_OPS,
        allowed_paths: ctx.policy.allowed_paths,
        login_path: ctx.policy.login_path,
        success_path: ctx.policy.success_path,
        error_codes: AGENT_ERROR_CODES,
        inject_login_body: Object.freeze(['empty', 'generation']),
        cookie_export_forbidden: true,
        agent_cdp_absent: true,
        authorization_ready: false,
        helper_vault_free: true,
      });
      return;
    }

    if (op === 'snapshot' && req.method === 'GET') {
      await handleSnapshot(res, ctx);
      return;
    }

    if (op === 'select_targets' && req.method === 'POST') {
      await handleSelect(req, res, ctx);
      return;
    }

    if (op === 'inject_login' && req.method === 'POST') {
      await handleInject(req, res, ctx);
      return;
    }

    if (op === 'goto' && req.method === 'POST') {
      await handleGoto(req, res, ctx);
      return;
    }

    writeFixed(res, 404, 'not_found');
  } catch (error) {
    const code = error instanceof BridgeBrowserTargetingError ||
      error instanceof BridgeOwnedBrowserError
      ? error.code
      : 'adapter_failed';
    log({ level: 'error', message: 'bridge-owned browser op failed' });
    writeFixed(res, statusFor(code), code);
  }
}

async function handleSnapshot(res, ctx) {
  const { adapter, sensitive, bumpGeneration, setLastSnapshot, getLoggedIn, policy } = ctx;
  const page = await adapter.snapshotPage();
  await adapter.absorbCookiesInto(sensitive);
  const generation = bumpGeneration();
  if (page.facts.challenge !== 'none') {
    const code = page.facts.challenge === 'mfa' ? 'mfa_required' : 'captcha_required';
    throw new BridgeOwnedBrowserError(code);
  }
  const candidates = enumerateAgentCandidates(page.facts);
  setLastSnapshot({
    generation,
    origin: page.facts.origin,
    candidates,
    form_action: page.facts.form_action,
  });
  const payload = {
    ok: true,
    logged_in: getLoggedIn(),
    generation,
    origin: page.facts.origin,
    path: page.facts.path,
    challenge: page.facts.challenge,
    candidates,
    title: titleOf(page.html),
  };
  if (getLoggedIn() && page.facts.path !== policy.success_path &&
      !policy.allowed_paths.includes(page.facts.path)) {
    throw new BridgeOwnedBrowserError('path_denied');
  }
  writeJson(res, sensitive, payload);
}

async function handleSelect(req, res, ctx) {
  const raw = await readJsonObject(req);
  const selection = parseTargetSelection(raw);
  const snapshot = ctx.getLastSnapshot();
  if (snapshot === null) {
    throw new BridgeOwnedBrowserError('stale_generation');
  }
  const authorized = authorizeTargetSelection(snapshot, selection, ctx.policy);
  ctx.setAuthorized(authorized);
  writeJson(res, ctx.sensitive, {
    ok: true,
    selected: true,
    generation: selection.generation,
    username_kind: authorized.username.kind,
    password_kind: authorized.password.kind,
    submit_kind: authorized.submit.kind,
  });
}

async function handleInject(req, res, ctx) {
  const raw = await readJsonObject(req);
  const keys = Object.keys(raw);
  if (keys.length > 1 || (keys.length === 1 && keys[0] !== 'generation')) {
    throw new BridgeOwnedBrowserError('extra_field_forbidden');
  }
  if (ctx.getLoggedIn()) {
    throw new BridgeOwnedBrowserError('already_logged_in');
  }
  const authorized = ctx.getAuthorized();
  const snapshot = ctx.getLastSnapshot();
  if (authorized === null || snapshot === null) {
    throw new BridgeOwnedBrowserError('inject_before_select');
  }
  if (keys.length === 1 && raw.generation !== snapshot.generation) {
    throw new BridgeOwnedBrowserError('stale_generation');
  }

  const live = await ctx.adapter.snapshotPage();
  assertInjectSafe(live.facts, authorized, ctx.policy);
  if (live.facts.challenge !== 'none') {
    const code = live.facts.challenge === 'mfa' ? 'mfa_required' : 'captcha_required';
    throw new BridgeOwnedBrowserError(code);
  }

  const submitted = await ctx.adapter.submitLogin({
    formAction: live.facts.form_action,
    usernameField: authorized.username.name,
    passwordField: authorized.password.name,
    username: ctx.credentials.username,
    password: ctx.credentials.password,
    hiddenNames: [...ctx.policy.hidden_fields],
    maxRedirectHops: ctx.policy.max_redirect_hops,
    submitLabel: authorized.submit.name,
  });
  await ctx.adapter.absorbCookiesInto(ctx.sensitive);
  const landed = new URL(submitted.url);
  if (landed.origin !== new URL(ctx.policy.login_origin).origin) {
    throw new BridgeOwnedBrowserError('origin_mismatch');
  }
  if (landed.pathname !== ctx.policy.success_path) {
    throw new BridgeOwnedBrowserError('success_path_mismatch');
  }
  ctx.setLoggedIn(true);
  ctx.bumpGeneration();
  writeJson(res, ctx.sensitive, {
    ok: true,
    logged_in: true,
    origin_bound: true,
    cookie_export_forbidden: true,
    agent_secret_visible: false,
  });
}

async function handleGoto(req, res, ctx) {
  const raw = await readJsonObject(req);
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== 'path' || typeof raw.path !== 'string') {
    throw new BridgeOwnedBrowserError('invalid_request');
  }
  if (!ctx.getLoggedIn()) {
    throw new BridgeOwnedBrowserError('not_logged_in');
  }
  if (!ctx.policy.allowed_paths.includes(raw.path)) {
    throw new BridgeOwnedBrowserError('path_denied');
  }
  const target = new URL(raw.path, `${ctx.policy.login_origin}/`).href;
  const page = await ctx.adapter.goto(target);
  await ctx.adapter.absorbCookiesInto(ctx.sensitive);
  ctx.bumpGeneration();
  writeJson(res, ctx.sensitive, {
    ok: true,
    logged_in: true,
    path: page.facts.path,
    title: titleOf(page.html),
  });
}

function opFromPath(method, pathname) {
  if (method === 'GET' && pathname === '/status') return 'status';
  if (method === 'GET' && pathname === '/contract') return 'contract';
  if (method === 'GET' && pathname === '/snapshot') return 'snapshot';
  if (method === 'POST' && pathname === '/select_targets') return 'select_targets';
  if (method === 'POST' && pathname === '/inject_login') return 'inject_login';
  if (method === 'POST' && pathname === '/goto') return 'goto';
  if (pathname.length > 1) return pathname.slice(1);
  return 'unknown';
}

function titleOf(html) {
  const match = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i) ||
    html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/<[^>]+>/g, '').trim().slice(0, 64) : '';
}

function statusFor(code) {
  if (code === 'session_expired' || code === 'not_logged_in') return 401;
  if (
    code === 'command_forbidden' ||
    code === 'session_material_forbidden' ||
    code === 'path_denied' ||
    code === 'already_logged_in'
  ) {
    return 403;
  }
  if (code === 'mfa_required' || code === 'captcha_required' || code === 'challenge_blocked') {
    return 403;
  }
  if (code === 'success_path_mismatch' || code === 'login_failed') return 401;
  return 400;
}

async function readJsonObject(req) {
  const raw = await readBody(req, 4096);
  if (raw === '') return {};
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new BridgeOwnedBrowserError('invalid_request');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new BridgeOwnedBrowserError('invalid_request');
  }
  return parsed;
}

function writeJson(res, sensitive, payload) {
  const body = JSON.stringify(payload);
  if (containsSensitive(body, sensitive)) {
    writeFixed(res, 502, 'sensitive_response_blocked');
    return;
  }
  if (/"set-cookie"/i.test(body) || /cookie=/i.test(body)) {
    writeFixed(res, 502, 'sensitive_response_blocked');
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

function writeFixed(res, status, code) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: code }));
}

function buildCredentialSensitiveVariants(credentials) {
  const set = new Set();
  for (const value of [
    credentials.username,
    credentials.password,
    `${credentials.username}:${credentials.password}`,
  ]) {
    for (const variant of [
      value,
      encodeURIComponent(value),
      encodeURIComponent(value).replace(/%20/g, '+'),
      Buffer.from(value, 'utf8').toString('base64'),
      Buffer.from(value, 'utf8').toString('base64url'),
    ]) {
      if (variant.length >= 8) set.add(variant);
    }
  }
  return set;
}

function containsSensitive(text, sensitive) {
  for (const variant of sensitive) {
    if (variant.length >= 8 && text.includes(variant)) return true;
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
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redact(v, sensitive);
    return out;
  }
  return value;
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new BridgeOwnedBrowserError('invalid_request'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function listenHttp(server, bindUrl) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number(bindUrl.port), bindUrl.hostname, () => {
      server.off('error', reject);
      resolve(undefined);
    });
  });
}

function closeHttp(server) {
  return new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}
