import http from 'node:http';
import { Transform } from 'node:stream';
import {
  oneCliProxyAuthorizationValue,
  validateAgentToken,
} from './agent-token.js';
import { parseLoopbackHttpUrl, validatePolicy } from './policy.js';

export const MAX_PROXY_REQUEST_BODY_BYTES = 1 * 1024 * 1024;
export const MAX_PROXY_RESPONSE_BODY_BYTES = 1 * 1024 * 1024;
export const MAX_TUNNEL_BYTES_PER_DIRECTION = 8 * 1024 * 1024;
export const MAX_CONCURRENT_PROXY_CLIENTS = 16;
export const PROXY_HANDSHAKE_TIMEOUT_MS = 10_000;
export const PROXY_IDLE_TIMEOUT_MS = 120_000;

const BLOCKED_REQUEST_HEADERS = new Set([
  'connection', 'cookie', 'expect', 'host', 'http2-settings', 'keep-alive',
  'max-forwards', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection',
  'set-cookie', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'via',
  'www-authenticate', 'x-api-key', 'authorization', 'content-length',
]);
const BLOCKED_PREFIXES = ['forwarded', 'proxy-', 'sec-', 'x-forwarded-'];
const BLOCKED_RESPONSE_HEADERS = new Set([
  'authorization', 'connection', 'content-length', 'cookie', 'keep-alive',
  'content-encoding',
  'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'set-cookie',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'via', 'www-authenticate',
]);

export class OneCliProxyBrokerError extends Error {
  constructor(code) {
    super(`OneCLI proxy broker failed: ${code}`);
    this.name = 'OneCliProxyBrokerError';
    this.code = code;
  }
}

export async function startOneCliProxyBroker(options) {
  let policy;
  try { policy = validatePolicy(options?.policy); } catch {
    throw new OneCliProxyBrokerError('invalid_policy');
  }
  if (policy.version !== 4 || policy.credential_class !== 'onecli_proxy') {
    throw new OneCliProxyBrokerError('invalid_policy');
  }
  let token;
  try { token = validateAgentToken(options?.agentToken); } catch {
    throw new OneCliProxyBrokerError('invalid_agent_token');
  }
  const proxyAuthorization = oneCliProxyAuthorizationValue(token);
  const sensitive = sensitiveVariants(token, proxyAuthorization);
  const logs = [];
  const rawLog = options.log ?? ((entry) => logs.push(entry));
  const log = (entry) => rawLog(redact(entry, sensitive));
  const bind = parseLoopbackHttpUrl(policy.bind, 'policy.bind');
  const gateway = parseLoopbackHttpUrl(policy.gateway, 'policy.gateway');
  const clients = new Set();

  const server = http.createServer((req, res) => {
    if (!admitClient(req.socket, clients, res)) return;
    void handleAbsoluteRequest(req, res, {
      policy, gateway, proxyAuthorization, sensitive, log,
    }).finally(() => clients.delete(req.socket));
  });
  server.on('connect', (req, client, head) => {
    if (!admitClient(client, clients)) {
      writeSocketError(client, 503, 'proxy_busy');
      return;
    }
    void handleConnect(req, client, head, {
      policy, gateway, proxyAuthorization, log,
    }).finally(() => clients.delete(client));
  });
  server.on('clientError', (_error, socket) => writeSocketError(socket, 400, 'bad_request'));
  server.requestTimeout = PROXY_HANDSHAKE_TIMEOUT_MS;
  server.headersTimeout = PROXY_HANDSHAKE_TIMEOUT_MS;
  server.maxHeadersCount = 64;

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number(bind.port), bind.hostname, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    await closeProxyServer(server, clients);
    throw new OneCliProxyBrokerError('bind_failed');
  }
  const proxyUrl = `http://${bind.hostname}:${address.port}`;
  log({ level: 'info', message: 'OneCLI proxy broker listening', meta: { bind: proxyUrl } });
  return Object.freeze({
    server,
    host: bind.hostname,
    port: address.port,
    proxyUrl,
    logs,
    close: () => closeProxyServer(server, clients),
  });
}

async function handleConnect(req, client, clientHead, ctx) {
  client.setTimeout(PROXY_IDLE_TIMEOUT_MS, () => client.destroy());
  if (clientHead.length > MAX_TUNNEL_BYTES_PER_DIRECTION) {
    client.destroy();
    return;
  }
  if (req.method !== 'CONNECT' || req.url !== `${ctx.policy.target_host}:443` ||
      hasForbiddenRawHeader(req.rawHeaders)) {
    writeSocketError(client, 403, 'target_denied');
    return;
  }
  const upstreamRequest = http.request({
    host: ctx.gateway.hostname,
    port: Number(ctx.gateway.port),
    method: 'CONNECT',
    path: `${ctx.policy.target_host}:443`,
    agent: false,
    headers: {
      host: `${ctx.policy.target_host}:443`,
      'proxy-authorization': ctx.proxyAuthorization,
      connection: 'close',
    },
  });
  const abortUpstream = () => upstreamRequest.destroy();
  client.once('close', abortUpstream);
  client.once('error', abortUpstream);
  if (client.destroyed) upstreamRequest.destroy();
  const outcome = await new Promise((resolve) => {
    let settled = false;
    const done = (value) => { if (!settled) { settled = true; resolve(value); } };
    upstreamRequest.setTimeout(PROXY_HANDSHAKE_TIMEOUT_MS, () => {
      upstreamRequest.destroy();
      done({ ok: false });
    });
    upstreamRequest.once('connect', (response, upstream, upstreamHead) =>
      done({ ok: response.statusCode === 200, response, upstream, upstreamHead }));
    upstreamRequest.once('response', (response) => {
      response.resume();
      upstreamRequest.destroy();
      done({ ok: false });
    });
    upstreamRequest.once('error', () => {
      upstreamRequest.destroy();
      done({ ok: false });
    });
    upstreamRequest.end();
  });
  if (!outcome.ok || outcome.upstream === undefined) {
    outcome.upstream?.destroy();
    upstreamRequest.destroy();
    writeSocketError(client, 502, 'gateway_failed');
    return;
  }
  const upstream = outcome.upstream;
  if ((outcome.upstreamHead?.length ?? 0) > MAX_TUNNEL_BYTES_PER_DIRECTION ||
      clientHead.length > MAX_TUNNEL_BYTES_PER_DIRECTION) {
    client.destroy();
    upstream.destroy();
    return;
  }
  if (client.destroyed || client.writableEnded) {
    upstream.destroy();
    return;
  }
  const destroyTunnel = () => { client.destroy(); upstream.destroy(); };
  client.once('error', destroyTunnel);
  upstream.once('error', destroyTunnel);
  upstream.setTimeout(PROXY_IDLE_TIMEOUT_MS, () => upstream.destroy());
  client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  if (outcome.upstreamHead?.length > 0) client.write(outcome.upstreamHead);
  if (clientHead.length > 0) upstream.write(clientHead);
  const clientLimit = byteLimit(MAX_TUNNEL_BYTES_PER_DIRECTION, () => {
    client.destroy(); upstream.destroy();
  }, clientHead.length);
  const upstreamLimit = byteLimit(MAX_TUNNEL_BYTES_PER_DIRECTION, () => {
    client.destroy(); upstream.destroy();
  }, outcome.upstreamHead?.length ?? 0);
  clientLimit.once('error', () => { client.destroy(); upstream.destroy(); });
  upstreamLimit.once('error', () => { client.destroy(); upstream.destroy(); });
  client.pipe(clientLimit).pipe(upstream);
  upstream.pipe(upstreamLimit).pipe(client);
  await Promise.race([closed(client), closed(upstream)]);
  client.destroy();
  upstream.destroy();
}

async function handleAbsoluteRequest(req, res, ctx) {
  let target;
  try { target = new URL(req.url ?? ''); } catch {
    writeJson(res, 400, 'bad_request');
    return;
  }
  if (target.protocol !== 'http:' || target.username || target.password ||
      target.hostname !== ctx.policy.target_host || Number(target.port) !== 443 ||
      target.pathname !== ctx.policy.path || target.search || target.hash ||
      req.method !== ctx.policy.method || hasForbiddenRawHeader(req.rawHeaders)) {
    denyRequest(req, res, 403, 'target_denied');
    return;
  }
  let body;
  try { body = await readBody(req, MAX_PROXY_REQUEST_BODY_BYTES); } catch {
    writeJson(res, 413, 'payload_too_large');
    return;
  }
  const headers = sanitizeRequestHeaders(req.headers);
  headers.host = `${ctx.policy.target_host}:443`;
  headers['proxy-authorization'] = ctx.proxyAuthorization;
  headers.connection = 'close';
  if (body.length > 0) headers['content-length'] = String(body.length);
  const result = await requestGateway(ctx.gateway, {
    method: ctx.policy.method,
    path: `http://${ctx.policy.target_host}:443${ctx.policy.path}`,
    headers,
    body,
  }, req.socket);
  if (req.socket.destroyed || res.destroyed) return;
  if (!result.ok || result.status < 200 || result.status >= 300 ||
      result.headers['content-encoding'] !== undefined ||
      looksCompressed(result.body) ||
      containsSensitive(result.body, ctx.sensitive) ||
      headersContainSensitive(result.headers, ctx.sensitive)) {
    writeJson(res, 502, 'gateway_failed');
    return;
  }
  const responseHeaders = sanitizeResponseHeaders(result.headers, result.body.length);
  res.writeHead(result.status, responseHeaders);
  res.end(result.body);
}

function requestGateway(gateway, request, clientSocket) {
  return new Promise((resolve) => {
    const upstream = http.request({
      host: gateway.hostname,
      port: Number(gateway.port),
      method: request.method,
      path: request.path,
      agent: false,
      headers: request.headers,
    });
    let settled = false;
    const abort = () => upstream.destroy();
    clientSocket.once('close', abort);
    clientSocket.once('error', abort);
    const done = (value) => {
      if (!settled) {
        settled = true;
        clientSocket.off('close', abort);
        clientSocket.off('error', abort);
        resolve(value);
      }
    };
    if (clientSocket.destroyed) upstream.destroy();
    upstream.setTimeout(PROXY_HANDSHAKE_TIMEOUT_MS, () => {
      upstream.destroy(); done({ ok: false });
    });
    upstream.once('error', () => done({ ok: false }));
    upstream.once('response', (response) => {
      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_PROXY_RESPONSE_BODY_BYTES) {
          chunks.length = 0;
          response.destroy();
          done({ ok: false });
        } else chunks.push(Buffer.from(chunk));
      });
      response.once('end', () => done({
        ok: true,
        status: response.statusCode ?? 502,
        headers: response.headers,
        body: Buffer.concat(chunks, total),
      }));
      response.once('error', () => done({ ok: false }));
    });
    if (request.body.length > 0) upstream.write(request.body);
    upstream.end();
  });
}

function sanitizeRequestHeaders(headers) {
  const out = {};
  const connectionTokens = new Set(String(headers.connection ?? '').split(',')
    .map((value) => value.trim().toLowerCase()).filter(Boolean));
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (value === undefined || BLOCKED_REQUEST_HEADERS.has(lower) ||
        connectionTokens.has(lower) || BLOCKED_PREFIXES.some((prefix) =>
          lower === prefix || lower.startsWith(prefix))) continue;
    out[lower] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

function sanitizeResponseHeaders(headers, bodyLength) {
  const out = {};
  const connectionTokens = new Set(String(headers.connection ?? '').split(',')
    .map((value) => value.trim().toLowerCase()).filter(Boolean));
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (value === undefined || BLOCKED_RESPONSE_HEADERS.has(lower) ||
        connectionTokens.has(lower)) continue;
    out[lower] = Array.isArray(value) ? value.join(', ') : value;
  }
  out['content-length'] = String(bodyLength);
  out.connection = 'close';
  return out;
}

function hasForbiddenRawHeader(rawHeaders) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) return true;
  const seen = new Set();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase();
    if (seen.has(name) || name === 'proxy-authorization' || name === 'proxy-connection' ||
        name === 'authorization' || name === 'cookie' || name === 'upgrade') return true;
    seen.add(name);
  }
  return false;
}

function readBody(req, maximum) {
  const declared = req.headers['content-length'];
  if (declared !== undefined && (!/^\d+$/.test(String(declared)) || Number(declared) > maximum)) {
    req.resume();
    return Promise.reject(new Error('too_large'));
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maximum) {
        chunks.length = 0;
        req.destroy();
        reject(new Error('too_large'));
      } else chunks.push(Buffer.from(chunk));
    });
    req.once('end', () => resolve(Buffer.concat(chunks, total)));
    req.once('error', reject);
  });
}

function denyRequest(req, res, status, code) {
  req.pause();
  res.once('finish', () => req.socket.destroy());
  writeJson(res, status, code);
}

function looksCompressed(body) {
  if (body.length < 2) return false;
  if (body[0] === 0x1f && body[1] === 0x8b) return true;
  return body[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(body[1]);
}

function admitClient(socket, clients, res) {
  if (clients.has(socket)) return true;
  if (clients.size >= MAX_CONCURRENT_PROXY_CLIENTS) {
    if (res !== undefined) writeJson(res, 503, 'proxy_busy');
    return false;
  }
  clients.add(socket);
  socket.once('close', () => clients.delete(socket));
  return true;
}

function byteLimit(maximum, onLimit, initialTotal = 0) {
  let total = initialTotal;
  return new Transform({
    transform(chunk, _encoding, callback) {
      total += chunk.length;
      if (total > maximum) {
        onLimit(); callback(new Error('tunnel_limit'));
      } else callback(null, chunk);
    },
  });
}

function sensitiveVariants(token, authorization) {
  const payload = authorization.slice('Basic '.length);
  const encoded = encodeURIComponent(token);
  const encodedPayload = encodeURIComponent(payload);
  const tokenBase64 = Buffer.from(token, 'ascii').toString('base64');
  return new Set([token, `${token}:`, payload, authorization,
    payload.toLowerCase(), payload.toUpperCase(), authorization.toLowerCase(),
    authorization.toUpperCase(), tokenBase64, encoded,
    encoded.replace(/%[0-9A-F]{2}/g, (value) => value.toLowerCase()), encodedPayload,
    encodedPayload.replace(/%[0-9A-F]{2}/g, (value) => value.toLowerCase()),
    Buffer.from(token).toString('base64url')]);
}
function redact(value, variants) {
  if (typeof value === 'string') {
    let result = value;
    for (const item of [...variants].sort((a, b) => b.length - a.length)) {
      result = result.split(item).join('[REDACTED]');
    }
    return result;
  }
  if (Array.isArray(value)) return value.map((item) => redact(item, variants));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) =>
      [redact(key, variants), redact(item, variants)]));
  }
  return value;
}
function containsSensitive(body, variants) {
  return [...variants].some((value) => body.includes(value));
}
function headersContainSensitive(headers, variants) {
  return Object.entries(headers).some(([name, value]) =>
    [...variants].some((secret) => name.includes(secret) || String(value).includes(secret)));
}
function writeJson(res, status, code) {
  if (res.headersSent || res.destroyed) return;
  const body = Buffer.from(JSON.stringify({ error: code }));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length,
    connection: 'close' });
  res.end(body);
}
function writeSocketError(socket, status, code) {
  if (socket.destroyed) return;
  const reason = status === 400 ? 'Bad Request' : status === 403 ? 'Forbidden' :
    status === 503 ? 'Service Unavailable' : 'Bad Gateway';
  const body = JSON.stringify({ error: code });
  socket.end(`HTTP/1.1 ${status} ${reason}\r\nContent-Type: application/json\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
}
function closed(socket) {
  return new Promise((resolve) => {
    if (socket.destroyed) resolve();
    else socket.once('close', resolve);
  });
}
async function closeProxyServer(server, clients) {
  for (const socket of clients) socket.destroy();
  if (!server.listening) return;
  await new Promise((resolve, reject) => server.close((error) =>
    error ? reject(error) : resolve()));
}
