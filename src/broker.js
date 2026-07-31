import http from 'node:http';
import {
  CREDENTIAL_PLACEHOLDER,
  SUPPORTED_CREDENTIAL_CLASSES,
} from './constants.js';
import { parseLoopbackHttpUrl } from './policy.js';

/** Maximum inbound request body accepted by the broker (1 MiB). */
export const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024;

const REDACTED = '[REDACTED]';

/**
 * Foreground-only HTTP credential broker.
 * Binds to a loopback URL from policy, accepts only the allowed method/path,
 * strips caller Authorization, injects the runtime sentinel on the outbound
 * request only, and returns a sanitized response to the caller.
 */

export class BrokerError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string }} [opts]
   */
  constructor(message, opts = {}) {
    super(message);
    this.name = 'BrokerError';
    this.code = opts.code ?? 'broker_error';
  }
}

/**
 * @typedef {object} BrokerLogEntry
 * @property {string} level
 * @property {string} message
 * @property {Record<string, unknown>} [meta]
 */

/**
 * Redact every exact occurrence of the runtime sentinel from strings and
 * nested log metadata before anything is logged or surfaced.
 * @param {unknown} value
 * @param {string} sentinel
 * @returns {unknown}
 */
export function redactSentinel(value, sentinel) {
  if (typeof value === 'string') {
    return sentinel.length === 0
      ? value
      : value.split(sentinel).join(REDACTED);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSentinel(item, sentinel));
  }
  if (value !== null && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      out[key] = redactSentinel(nested, sentinel);
    }
    return out;
  }
  return value;
}

/**
 * Start a foreground HTTP broker bound to policy.bind (port 0 = ephemeral).
 *
 * @param {{
 *   policy: import('./policy.js').Policy,
 *   sentinel: string,
 *   log?: (entry: BrokerLogEntry) => void,
 *   fetchImpl?: typeof fetch,
 * }} options
 * @returns {Promise<{
 *   server: http.Server,
 *   host: string,
 *   port: number,
 *   baseUrl: string,
 *   url: string,
 *   logs: BrokerLogEntry[],
 *   close: () => Promise<void>,
 * }>}
 */
export async function startBroker(options) {
  const { policy, sentinel, fetchImpl = globalThis.fetch } = options;
  /** @type {BrokerLogEntry[]} */
  const logs = [];

  const rawLog =
    options.log ??
    ((entry) => {
      logs.push(entry);
    });

  if (typeof sentinel !== 'string' || sentinel.length === 0) {
    throw new BrokerError('broker requires an explicit runtime sentinel', {
      code: 'missing_sentinel',
    });
  }

  /**
   * @param {BrokerLogEntry} entry
   */
  const log = (entry) => {
    /** @type {BrokerLogEntry} */
    const safe = {
      level: entry.level,
      message: /** @type {string} */ (redactSentinel(entry.message, sentinel)),
    };
    if (entry.meta !== undefined) {
      safe.meta = /** @type {Record<string, unknown>} */ (
        redactSentinel(entry.meta, sentinel)
      );
    }
    rawLog(safe);
  };

  if (
    !SUPPORTED_CREDENTIAL_CLASSES.includes(policy.credential_class) ||
    policy.credential_class !== 'http_bearer'
  ) {
    throw new BrokerError(
      `unsupported credential_class "${policy.credential_class}"; refusing to inject`,
      { code: 'unsupported_credential_class' },
    );
  }

  if (policy.authorization !== CREDENTIAL_PLACEHOLDER) {
    throw new BrokerError(
      'policy.authorization must be the credential placeholder; refusing to inject',
      { code: 'invalid_authorization_placeholder' },
    );
  }

  const bindUrl = parseLoopbackHttpUrl(policy.bind, 'policy.bind');
  const upstreamUrl = parseLoopbackHttpUrl(policy.upstream, 'policy.upstream');
  const bindHost = bindUrl.hostname;
  const bindPort = Number(bindUrl.port);

  const server = http.createServer((req, res) => {
    void handleBrokerRequest(req, res, {
      policy,
      sentinel,
      upstreamOrigin: upstreamUrl.href.replace(/\/$/, ''),
      fetchImpl,
      log,
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(bindPort, bindHost, () => {
      server.off('error', reject);
      resolve(undefined);
    });
  });

  const address = server.address();
  if (address === null || typeof address === 'string') {
    await closeServer(server);
    throw new BrokerError('broker failed to bind a TCP port', {
      code: 'bind_failed',
    });
  }

  const port = address.port;
  const baseUrl = `http://${bindHost}:${port}`;
  const url = `${baseUrl}${policy.path}`;

  log({
    level: 'info',
    message: 'broker listening',
    meta: { bind: baseUrl, method: policy.method, path: policy.path },
  });

  return {
    server,
    host: bindHost,
    port,
    baseUrl,
    url,
    logs,
    close: () => closeServer(server),
  };
}

/**
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {{
 *   policy: import('./policy.js').Policy,
 *   sentinel: string,
 *   upstreamOrigin: string,
 *   fetchImpl: typeof fetch,
 *   log: (entry: BrokerLogEntry) => void,
 * }} ctx
 */
async function handleBrokerRequest(req, res, ctx) {
  const { policy, sentinel, upstreamOrigin, fetchImpl, log } = ctx;
  const requestUrl = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);

  if (req.method !== policy.method || requestUrl.pathname !== policy.path) {
    log({
      level: 'warn',
      message: 'request denied: method or path not allowed',
      meta: { method: req.method ?? null, path: requestUrl.pathname },
    });
    writeJson(res, 404, { error: 'not_found' });
    return;
  }

  // Strip any caller-supplied Authorization; sentinel is injected outbound only.
  /** @type {Record<string, string>} */
  const outboundHeaders = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    const lower = key.toLowerCase();
    if (lower === 'authorization' || lower === 'host' || lower === 'connection') {
      continue;
    }
    outboundHeaders[key] = Array.isArray(value) ? value.join(', ') : value;
  }
  outboundHeaders.Authorization = `Bearer ${sentinel}`;

  const outboundUrl = `${upstreamOrigin}${policy.path}${requestUrl.search}`;

  log({
    level: 'info',
    message: 'forwarding allowed request',
    meta: {
      method: policy.method,
      path: policy.path,
      upstream: `${upstreamOrigin}${policy.path}`,
    },
  });

  let body;
  try {
    body = await readRequestBody(req, MAX_REQUEST_BODY_BYTES);
  } catch (err) {
    if (isRequestBodyTooLarge(err)) {
      log({
        level: 'warn',
        message: 'request body exceeds size limit',
        meta: { limit: MAX_REQUEST_BODY_BYTES },
      });
      writeJson(res, 413, { error: 'payload_too_large' });
      return;
    }
    const message = err instanceof Error ? err.message : String(err);
    log({
      level: 'error',
      message: 'failed to read request body',
      meta: { error: message },
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  let upstreamResponse;
  try {
    upstreamResponse = await fetchImpl(outboundUrl, {
      method: policy.method,
      headers: outboundHeaders,
      redirect: 'manual',
      body:
        body === null || policy.method === 'GET' || policy.method === 'HEAD'
          ? undefined
          : body,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log({
      level: 'error',
      message: 'upstream request failed',
      meta: { error: message },
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  if (isRedirectResponse(upstreamResponse)) {
    log({
      level: 'warn',
      message: 'upstream redirect rejected',
      meta: { status: upstreamResponse.status },
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  const responseBody = Buffer.from(await upstreamResponse.arrayBuffer());

  if (
    bufferContainsExactSentinel(responseBody, sentinel) ||
    headersContainExactSentinel(upstreamResponse.headers, sentinel)
  ) {
    log({
      level: 'error',
      message: 'upstream response contained credential material; refusing to forward',
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  const sanitizedHeaders = sanitizeResponseHeaders(upstreamResponse.headers);

  res.writeHead(upstreamResponse.status, sanitizedHeaders);
  res.end(responseBody);
}

/**
 * @param {Response} response
 * @returns {boolean}
 */
function isRedirectResponse(response) {
  if (response.type === 'opaqueredirect') {
    return true;
  }
  return response.status >= 300 && response.status < 400;
}

/**
 * @param {Buffer} body
 * @param {string} sentinel
 * @returns {boolean}
 */
function bufferContainsExactSentinel(body, sentinel) {
  if (sentinel.length === 0) return false;
  return body.includes(sentinel);
}

/**
 * @param {Headers} headers
 * @param {string} sentinel
 * @returns {boolean}
 */
function headersContainExactSentinel(headers, sentinel) {
  if (sentinel.length === 0) return false;
  for (const value of headers.values()) {
    if (value.includes(sentinel)) {
      return true;
    }
  }
  return false;
}

/**
 * Drop hop-by-hop and credential-bearing headers from the upstream response.
 * @param {Headers} headers
 * @returns {Record<string, string>}
 */
function sanitizeResponseHeaders(headers) {
  /** @type {Record<string, string>} */
  const out = {};
  const blocked = new Set([
    'authorization',
    'proxy-authorization',
    'www-authenticate',
    'set-cookie',
    'cookie',
    'connection',
    'transfer-encoding',
    'keep-alive',
  ]);

  for (const [key, value] of headers.entries()) {
    if (blocked.has(key.toLowerCase())) continue;
    out[key] = value;
  }

  if (!out['content-type']) {
    out['content-type'] = 'application/octet-stream';
  }

  return out;
}

/**
 * Read the inbound body up to maxBytes. Rejects without retaining excess bytes
 * once the limit is exceeded (Content-Length checked early when present).
 * @param {http.IncomingMessage} req
 * @param {number} maxBytes
 * @returns {Promise<Buffer | null>}
 */
function readRequestBody(req, maxBytes) {
  const method = req.method ?? 'GET';
  if (method === 'GET' || method === 'HEAD') {
    return Promise.resolve(null);
  }

  const contentLengthHeader = req.headers['content-length'];
  if (contentLengthHeader !== undefined) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      req.resume();
      return Promise.reject(Object.assign(new Error('request body too large'), {
        code: 'request_body_too_large',
      }));
    }
  }

  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let total = 0;
    let settled = false;

    const failTooLarge = () => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.resume();
      req.destroy();
      reject(
        Object.assign(new Error('request body too large'), {
          code: 'request_body_too_large',
        }),
      );
    };

    /** @param {Buffer | string} chunk */
    const onData = (chunk) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > maxBytes) {
        failTooLarge();
        return;
      }
      chunks.push(buf);
    };

    const onEnd = () => {
      if (settled) return;
      settled = true;
      resolve(chunks.length === 0 ? null : Buffer.concat(chunks));
    };

    /** @param {Error} err */
    const onError = (err) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      reject(err);
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
  });
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isRequestBodyTooLarge(err) {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    /** @type {{ code?: string }} */ (err).code === 'request_body_too_large'
  );
}

/**
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function writeJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

/** @param {http.Server} server */
function closeServer(server) {
  return new Promise((resolve, reject) => {
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    server.close((err) => (err ? reject(err) : resolve()));
  });
}
