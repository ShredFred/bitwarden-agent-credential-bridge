import http from 'node:http';
import {
  basicAuthorizationValue,
  validateBasicCredentials,
} from './basic-credentials.js';
import {
  CREDENTIAL_PLACEHOLDER,
  SUPPORTED_CREDENTIAL_CLASSES,
} from './constants.js';
import { parseLoopbackHttpUrl, validatePolicy } from './policy.js';

/** Maximum inbound request body accepted by the broker (1 MiB). */
export const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024;
/** Maximum upstream response body buffered by the broker (1 MiB). */
export const MAX_UPSTREAM_RESPONSE_BODY_BYTES = 1 * 1024 * 1024;

const REDACTED = '[REDACTED]';
const UNSAFE_CALLER_HEADER_NAMES = new Set([
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
const UNSAFE_CALLER_HEADER_PREFIXES = Object.freeze([
  'access-control-',
  'content-',
  'forwarded',
  'proxy-',
  'sec-',
  'x-forwarded-',
]);

/**
 * Foreground-only HTTP credential broker.
 * Binds to a loopback URL from policy, accepts only the allowed method/path,
 * strips caller credential/protocol headers, injects the runtime sentinel at
 * the outbound boundary, and returns a bounded sanitized response.
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
 * Redact the runtime sentinel and its deterministic encoded forms from strings
 * and nested log metadata before anything is logged or surfaced.
 * @param {unknown} value
 * @param {string} sentinel
 * @returns {unknown}
 */
export function redactSentinel(value, sentinel) {
  return redactSensitiveVariants(value, buildSentinelSensitiveVariants(sentinel));
}

/**
 * @param {string} sentinel
 * @returns {Set<string>}
 */
function buildSentinelSensitiveVariants(sentinel) {
  return new Set(
    [
      sentinel,
      encodeURIComponent(sentinel),
      Buffer.from(sentinel, 'utf8').toString('base64'),
      Buffer.from(sentinel, 'utf8').toString('base64url'),
    ].filter((variant) => variant.length > 0),
  );
}

/**
 * Build all deterministic sensitive forms required for an HTTP Basic bundle.
 * Values remain in memory and are never persisted.
 * @param {import('./basic-credentials.js').BasicCredentials} credentials
 * @returns {Set<string>}
 */
function buildBasicSensitiveVariants(credentials) {
  const joined = `${credentials.username}:${credentials.password}`;
  const payload = Buffer.from(joined, 'ascii').toString('base64');
  const fullAuthorization = `Basic ${payload}`;
  const variants = new Set();

  for (const value of [
    credentials.username,
    credentials.password,
    joined,
    payload,
    fullAuthorization,
  ]) {
    const upperPercent = encodeURIComponent(value);
    const lowerPercentDigits = upperPercent.replace(
      /%[0-9A-F]{2}/g,
      (triplet) => triplet.toLowerCase(),
    );
    for (const variant of [
      value,
      upperPercent,
      lowerPercentDigits,
      Buffer.from(value, 'utf8').toString('base64'),
      Buffer.from(value, 'utf8').toString('base64url'),
    ]) {
      if (variant.length > 0) variants.add(variant);
    }
  }

  return variants;
}

/**
 * @param {unknown} value
 * @param {Set<string>} sensitiveVariants
 * @returns {unknown}
 */
function redactSensitiveVariants(value, sensitiveVariants) {
  if (typeof value === 'string') {
    let safe = value;
    for (const variant of [...sensitiveVariants].sort(
      (left, right) => right.length - left.length,
    )) {
      safe = safe.split(variant).join(REDACTED);
    }
    return safe;
  }
  if (Array.isArray(value)) {
    return value.map((item) =>
      redactSensitiveVariants(item, sensitiveVariants),
    );
  }
  if (value !== null && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      const safeKey = /** @type {string} */ (
        redactSensitiveVariants(key, sensitiveVariants)
      );
      out[safeKey] = redactSensitiveVariants(nested, sensitiveVariants);
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
 *   sentinel?: string,
 *   credentials?: import('./basic-credentials.js').BasicCredentials,
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
  const {
    policy: suppliedPolicy,
    sentinel,
    credentials: suppliedCredentials,
    fetchImpl = globalThis.fetch,
  } = options;
  /** @type {BrokerLogEntry[]} */
  const logs = [];

  const rawLog =
    options.log ??
    ((entry) => {
      logs.push(entry);
    });

  const suppliedClass =
    suppliedPolicy !== null &&
    typeof suppliedPolicy === 'object' &&
    'credential_class' in suppliedPolicy
      ? suppliedPolicy.credential_class
      : undefined;
  if (
    typeof suppliedClass !== 'string' ||
    !SUPPORTED_CREDENTIAL_CLASSES.includes(suppliedClass)
  ) {
    throw new BrokerError(
      'unsupported credential_class; refusing to inject',
      { code: 'unsupported_credential_class' },
    );
  }
  if (suppliedClass === 'onecli_proxy') {
    throw new BrokerError(
      'onecli_proxy requires the dedicated chained proxy broker',
      { code: 'wrong_broker' },
    );
  }

  let policy;
  try {
    policy = validatePolicy(suppliedPolicy);
  } catch {
    const code =
      suppliedClass === 'http_bearer' &&
      'authorization' in
        /** @type {Record<string, unknown>} */ (suppliedPolicy) &&
      /** @type {{ authorization?: unknown }} */ (suppliedPolicy)
        .authorization !== CREDENTIAL_PLACEHOLDER
        ? 'invalid_authorization_placeholder'
        : 'invalid_policy';
    throw new BrokerError(
      'policy failed broker-start validation; refusing to inject',
      { code },
    );
  }

  /** @type {Set<string>} */
  let sensitiveVariants;
  let outboundCredentialValue;
  if (policy.credential_class === 'http_basic') {
    if (sentinel !== undefined) {
      throw new BrokerError(
        'version 3 requires credentials only; sentinel material is rejected',
        { code: 'ambiguous_runtime_material' },
      );
    }
    let credentials;
    try {
      credentials = validateBasicCredentials(suppliedCredentials);
    } catch {
      throw new BrokerError(
        'version 3 requires an exact valid username/password credentials object',
        { code: 'invalid_credentials' },
      );
    }
    sensitiveVariants = buildBasicSensitiveVariants(credentials);
    outboundCredentialValue = basicAuthorizationValue(credentials);
  } else {
    if (suppliedCredentials !== undefined) {
      throw new BrokerError(
        'version 1 and 2 accept sentinel material only; credentials are rejected',
        { code: 'ambiguous_runtime_material' },
      );
    }
    if (typeof sentinel !== 'string' || sentinel.length === 0) {
      throw new BrokerError('broker requires an explicit runtime sentinel', {
        code: 'missing_sentinel',
      });
    }
    sensitiveVariants = buildSentinelSensitiveVariants(sentinel);
    outboundCredentialValue =
      policy.credential_class === 'http_bearer'
        ? `Bearer ${sentinel}`
        : sentinel;
  }

  /**
   * @param {BrokerLogEntry} entry
   */
  const log = (entry) => {
    /** @type {BrokerLogEntry} */
    const safe = {
      level: entry.level,
      message: /** @type {string} */ (
        redactSensitiveVariants(entry.message, sensitiveVariants)
      ),
    };
    if (entry.meta !== undefined) {
      safe.meta = /** @type {Record<string, unknown>} */ (
        redactSensitiveVariants(entry.meta, sensitiveVariants)
      );
    }
    rawLog(safe);
  };

  const bindUrl = parseLoopbackHttpUrl(policy.bind, 'policy.bind');
  const upstreamUrl = parseLoopbackHttpUrl(policy.upstream, 'policy.upstream');
  const bindHost = bindUrl.hostname;
  const bindPort = Number(bindUrl.port);

  const server = http.createServer((req, res) => {
    void handleBrokerRequest(req, res, {
      policy,
      outboundCredentialValue,
      sensitiveVariants,
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
 *   outboundCredentialValue: string,
 *   sensitiveVariants: Set<string>,
 *   upstreamOrigin: string,
 *   fetchImpl: typeof fetch,
 *   log: (entry: BrokerLogEntry) => void,
 * }} ctx
 */
async function handleBrokerRequest(req, res, ctx) {
  const {
    policy,
    outboundCredentialValue,
    sensitiveVariants,
    upstreamOrigin,
    fetchImpl,
    log,
  } = ctx;
  const requestTarget = req.url ?? '/';

  if (
    !requestTarget.startsWith('/') ||
    requestTarget.startsWith('//') ||
    requestTarget.includes('?') ||
    requestTarget.includes('#')
  ) {
    log({
      level: 'warn',
      message: 'request denied: query or ambiguous request target',
    });
    writeJson(res, 400, { error: 'invalid_request_target' });
    return;
  }

  const requestUrl = new URL(requestTarget, 'http://127.0.0.1');

  if (req.method !== policy.method || requestUrl.pathname !== policy.path) {
    log({
      level: 'warn',
      message: 'request denied: method or path not allowed',
      meta: { method: req.method ?? null, path: requestUrl.pathname },
    });
    writeJson(res, 404, { error: 'not_found' });
    return;
  }

  // Strip caller credential/protocol headers before the single policy-pinned injection.
  /** @type {Record<string, string>} */
  const outboundHeaders = {};
  const connectionHeader = req.headers.connection;
  const connectionTokens = new Set(
    (Array.isArray(connectionHeader)
      ? connectionHeader.join(',')
      : (connectionHeader ?? '')
    )
      .split(',')
      .map((name) => name.trim().toLowerCase())
      .filter(Boolean),
  );
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    const lower = key.toLowerCase();
    const pinnedHeader =
      policy.credential_class === 'http_api_key_header'
        ? policy.header_name
        : null;
    if (isUnsafeCallerHeader(lower, pinnedHeader, connectionTokens)) {
      continue;
    }
    outboundHeaders[lower] = Array.isArray(value) ? value.join(', ') : value;
  }
  if (policy.credential_class === 'http_bearer') {
    outboundHeaders.authorization = outboundCredentialValue;
  } else if (policy.credential_class === 'http_api_key_header') {
    outboundHeaders[policy.header_name] = outboundCredentialValue;
  } else {
    outboundHeaders.authorization = outboundCredentialValue;
  }

  const outboundUrl = `${upstreamOrigin}${policy.path}`;

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
    await cancelResponseBody(upstreamResponse);
    log({
      level: 'warn',
      message: 'upstream redirect rejected',
      meta: { status: upstreamResponse.status },
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  if (
    headersContainSensitiveVariant(upstreamResponse.headers, sensitiveVariants)
  ) {
    await cancelResponseBody(upstreamResponse);
    log({
      level: 'error',
      message: 'upstream response contained credential material; refusing to forward',
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  let responseBody;
  try {
    responseBody = await readBoundedResponseBody(
      upstreamResponse,
      MAX_UPSTREAM_RESPONSE_BODY_BYTES,
    );
  } catch (err) {
    const tooLarge = isResponseBodyTooLarge(err);
    log({
      level: tooLarge ? 'warn' : 'error',
      message: tooLarge
        ? 'upstream response exceeds size limit'
        : 'failed to read upstream response',
      meta: tooLarge
        ? { limit: MAX_UPSTREAM_RESPONSE_BODY_BYTES }
        : {
            error: err instanceof Error ? err.message : String(err),
          },
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  if (bufferContainsSensitiveVariant(responseBody, sensitiveVariants)) {
    log({
      level: 'error',
      message: 'upstream response contained credential material; refusing to forward',
    });
    writeJson(res, 502, { error: 'upstream_failed' });
    return;
  }

  const pinnedHeader =
    policy.credential_class === 'http_api_key_header'
      ? policy.header_name
      : null;
  const sanitizedHeaders = sanitizeResponseHeaders(
    upstreamResponse.headers,
    pinnedHeader,
    responseBody.length,
  );

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
 * @param {Set<string>} sensitiveVariants
 * @returns {boolean}
 */
function bufferContainsSensitiveVariant(body, sensitiveVariants) {
  for (const variant of sensitiveVariants) {
    if (body.includes(variant)) return true;
  }
  return false;
}

/**
 * @param {Headers} headers
 * @param {Set<string>} sensitiveVariants
 * @returns {boolean}
 */
function headersContainSensitiveVariant(headers, sensitiveVariants) {
  for (const [name, value] of headers.entries()) {
    for (const variant of sensitiveVariants) {
      if (name.includes(variant) || value.includes(variant)) return true;
    }
  }
  return false;
}

/**
 * @param {string} name
 * @param {string | null} pinnedHeader
 * @param {Set<string>} connectionTokens
 * @returns {boolean}
 */
function isUnsafeCallerHeader(name, pinnedHeader, connectionTokens) {
  return (
    name === pinnedHeader ||
    connectionTokens.has(name) ||
    UNSAFE_CALLER_HEADER_NAMES.has(name) ||
    UNSAFE_CALLER_HEADER_PREFIXES.some(
      (prefix) => name === prefix || name.startsWith(prefix),
    )
  );
}

/**
 * Drop hop-by-hop and credential-bearing headers from the upstream response.
 * @param {Headers} headers
 * @param {string | null} pinnedHeader
 * @param {number} bodyLength
 * @returns {Record<string, string>}
 */
function sanitizeResponseHeaders(headers, pinnedHeader, bodyLength) {
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
    'proxy-authenticate',
    'proxy-connection',
    'te',
    'trailer',
    'upgrade',
    'content-encoding',
    'content-length',
  ]);
  for (const name of (headers.get('connection') ?? '').split(',')) {
    const normalized = name.trim().toLowerCase();
    if (normalized) blocked.add(normalized);
  }
  if (pinnedHeader !== null) blocked.add(pinnedHeader);

  for (const [key, value] of headers.entries()) {
    if (blocked.has(key.toLowerCase())) continue;
    out[key] = value;
  }

  if (!out['content-type']) {
    out['content-type'] = 'application/octet-stream';
  }
  out['content-length'] = String(bodyLength);

  return out;
}

/**
 * Read an upstream body into one complete bounded buffer. A valid declared
 * Content-Length is checked before reading; streaming bytes are counted again
 * so missing, invalid, or inaccurate declarations cannot bypass the limit.
 *
 * @param {Response} response
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 */
async function readBoundedResponseBody(response, maxBytes) {
  const declaredHeader = response.headers.get('content-length');
  if (declaredHeader !== null && /^\d+$/.test(declaredHeader)) {
    if (BigInt(declaredHeader) > BigInt(maxBytes)) {
      await cancelResponseBody(response);
      throw responseBodyTooLargeError();
    }
  }

  if (response.body === null) {
    return Buffer.alloc(0);
  }

  const reader = response.body.getReader();
  /** @type {Buffer[]} */
  const chunks = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > maxBytes) {
        chunks.length = 0;
        throw responseBodyTooLargeError();
      }
      chunks.push(chunk);
    }
  } catch (err) {
    chunks.length = 0;
    try {
      await reader.cancel();
    } catch {
      // The original read or size failure remains authoritative.
    }
    try {
      reader.releaseLock();
    } catch {
      // The original read or size failure remains authoritative.
    }
    throw err;
  }

  reader.releaseLock();
  return Buffer.concat(chunks, total);
}

/** @param {Response} response */
async function cancelResponseBody(response) {
  if (response.body === null) return;
  try {
    await response.body.cancel();
  } catch {
    // A generic broker failure is returned; cancellation details stay internal.
  }
}

function responseBodyTooLargeError() {
  return Object.assign(new Error('upstream response body too large'), {
    code: 'response_body_too_large',
  });
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isResponseBodyTooLarge(err) {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    /** @type {{ code?: string }} */ (err).code === 'response_body_too_large'
  );
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
