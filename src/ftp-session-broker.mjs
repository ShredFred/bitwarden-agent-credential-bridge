import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { validateBasicCredentials } from './basic-credentials.js';
import { PASSWORD_PLACEHOLDER, USERNAME_PLACEHOLDER } from './constants.js';
import { exchangeJsonLines } from './fake-session-protocol.mjs';
import { validatePolicy } from './policy.js';

export class FtpSessionBrokerError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(`FTP session broker rejected: ${code}`);
    this.name = 'FtpSessionBrokerError';
    this.code = code;
  }
}

export const MAX_FTP_SESSION_BROKERS = 8;

/** @type {number} */
let activeSessions = 0;
const MAX_ACTIVE_SESSIONS = MAX_FTP_SESSION_BROKERS;

/**
 * Dedicated FTP session broker over a fake loopback target.
 *
 * @param {{
 *   policy: unknown,
 *   credentials: import('./basic-credentials.js').BasicCredentials,
 *   log?: (entry: {level:string,message:string,meta?:object}) => void,
 * }} options
 */
export async function startFtpSessionBroker(options) {
  if (activeSessions >= MAX_ACTIVE_SESSIONS) {
    throw new FtpSessionBrokerError('concurrent_session_forbidden');
  }

  let policy;
  try {
    policy = validatePolicy(options.policy);
  } catch {
    throw new FtpSessionBrokerError('invalid_policy');
  }
  if (policy.credential_class !== 'ftp' || policy.version !== 8) {
    throw new FtpSessionBrokerError('wrong_broker');
  }
  if (policy.username_value !== USERNAME_PLACEHOLDER ||
      policy.password_value !== PASSWORD_PLACEHOLDER) {
    throw new FtpSessionBrokerError('invalid_policy');
  }
  if (typeof policy.target_port !== 'number' || policy.target_port < 1) {
    throw new FtpSessionBrokerError('target_unbound');
  }

  let credentials;
  try {
    credentials = validateBasicCredentials(options.credentials);
  } catch {
    throw new FtpSessionBrokerError('invalid_credentials');
  }

  activeSessions += 1;
  const sensitive = buildSensitive(credentials);
  const logs = [];
  const rawLog = options.log ?? ((entry) => { logs.push(entry); });
  const log = (entry) => {
    rawLog({
      level: entry.level,
      message: redact(entry.message, sensitive),
      ...(entry.meta ? { meta: redact(entry.meta, sensitive) } : {}),
    });
  };

  let closed = false;
  const createdAt = Date.now();
  let lastUsedAt = createdAt;
  const sessionId = randomBytes(32).toString('hex');

  try {
    const replies = await exchangeJsonLines({
      host: policy.target_host,
      port: policy.target_port,
      messages: [
        { op: 'auth', username: credentials.username, password: credentials.password },
      ],
    });
    const auth = replies[1];
    if (!auth || auth.ok !== true || auth.code !== 'authenticated') {
      throw new FtpSessionBrokerError('auth_failed');
    }
  } catch (error) {
    activeSessions = Math.max(0, activeSessions - 1);
    sensitive.clear();
    if (error instanceof FtpSessionBrokerError) throw error;
    throw new FtpSessionBrokerError('auth_failed');
  }

  const bindUrl = new URL(policy.bind);
  const server = http.createServer((req, res) => {
    void handleRequest(req, res, {
      policy,
      credentials,
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
    await listenHttp(server, bindUrl);
  } catch {
    closed = true;
    activeSessions = Math.max(0, activeSessions - 1);
    sensitive.clear();
    throw new FtpSessionBrokerError('bind_failed');
  }

  const address = server.address();
  if (address === null || typeof address === 'string') {
    closed = true;
    activeSessions = Math.max(0, activeSessions - 1);
    sensitive.clear();
    await closeHttp(server);
    throw new FtpSessionBrokerError('bind_failed');
  }

  const baseUrl = `http://${bindUrl.hostname}:${address.port}`;
  log({ level: 'info', message: 'ftp session broker listening', meta: { bind: baseUrl } });

  return {
    session_id: sessionId,
    logged_in: true,
    baseUrl,
    replayUrl: `${baseUrl}/status`,
    logs,
    async close() {
      if (closed) return;
      closed = true;
      sensitive.clear();
      activeSessions = Math.max(0, activeSessions - 1);
      await closeHttp(server);
    },
  };
}

async function handleRequest(req, res, ctx) {
  const {
    policy, credentials, sensitive, sessionId, createdAt, getLastUsed, touch, log, isClosed,
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
  touch();

  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  if (req.method === 'GET' && url.pathname === '/status') {
    const body = JSON.stringify({
      ok: true,
      logged_in: true,
      session_id: sessionId,
      credential_class: 'ftp',
    });
    if (containsSensitive(body, sensitive)) {
      writeFixed(res, 502, 'sensitive_response_blocked');
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    res.end(body);
    return;
  }

  if (req.method === 'POST' && url.pathname === '/list') {
    if (!policy.allowed_ops.includes('list')) {
      writeFixed(res, 403, 'op_denied');
      return;
    }
    try {
      const replies = await exchangeJsonLines({
        host: policy.target_host,
        port: policy.target_port,
        messages: [
          { op: 'auth', username: credentials.username, password: credentials.password },
          { op: 'list' },
          { op: 'quit' },
        ],
      });
      const listReply = replies[2];
      if (!listReply || listReply.ok !== true || !Array.isArray(listReply.entries)) {
        writeFixed(res, 502, 'list_failed');
        return;
      }
      const entries = listReply.entries.filter((p) => policy.allowed_paths.includes(p));
      const body = JSON.stringify({ ok: true, entries });
      if (containsSensitive(body, sensitive)) {
        writeFixed(res, 502, 'sensitive_response_blocked');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(body);
    } catch {
      log({ level: 'error', message: 'ftp list failed' });
      writeFixed(res, 502, 'list_failed');
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/retr') {
    if (!policy.allowed_ops.includes('retr')) {
      writeFixed(res, 403, 'op_denied');
      return;
    }
    let raw;
    try {
      raw = await readBody(req, 4096);
    } catch {
      writeFixed(res, 400, 'invalid_request');
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      writeFixed(res, 400, 'invalid_request');
      return;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) ||
        typeof parsed.path !== 'string' || !policy.allowed_paths.includes(parsed.path)) {
      writeFixed(res, 403, 'path_denied');
      return;
    }
    try {
      const replies = await exchangeJsonLines({
        host: policy.target_host,
        port: policy.target_port,
        messages: [
          { op: 'auth', username: credentials.username, password: credentials.password },
          { op: 'retr', path: parsed.path },
          { op: 'quit' },
        ],
      });
      const retr = replies[2];
      if (!retr || retr.ok !== true || typeof retr.body !== 'string') {
        writeFixed(res, 502, 'retr_failed');
        return;
      }
      const body = JSON.stringify({
        ok: true,
        path: parsed.path,
        size: retr.body.length,
        body: retr.body,
      });
      if (containsSensitive(body, sensitive)) {
        writeFixed(res, 502, 'sensitive_response_blocked');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(body);
    } catch {
      log({ level: 'error', message: 'ftp retr failed' });
      writeFixed(res, 502, 'retr_failed');
    }
    return;
  }

  writeFixed(res, 404, 'not_found');
}

function buildSensitive(credentials) {
  const set = new Set();
  for (const value of [credentials.username, credentials.password]) {
    set.add(value);
    set.add(encodeURIComponent(value));
    set.add(Buffer.from(value, 'utf8').toString('base64'));
  }
  return set;
}

function containsSensitive(text, sensitive) {
  for (const variant of sensitive) {
    if (variant.length >= 4 && text.includes(variant)) return true;
  }
  return false;
}

function redact(value, sensitive) {
  if (typeof value === 'string') {
    let out = value;
    for (const variant of sensitive) {
      if (variant.length >= 4) out = out.split(variant).join('[redacted]');
    }
    return out;
  }
  if (Array.isArray(value)) return value.map((item) => redact(item, sensitive));
  if (value && typeof value === 'object') {
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

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('too_large'));
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
