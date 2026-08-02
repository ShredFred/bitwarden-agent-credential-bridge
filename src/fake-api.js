import http from 'node:http';
import {
  basicAuthorizationValue,
  validateBasicCredentials,
} from './basic-credentials.js';
import { FAKE_API_CONSTANT_BODY } from './constants.js';

/**
 * Local fake HTTP API used only by this fake-only harness.
 * Accepts exactly one configured bearer, API-key header, Basic, or query key
 * without returning or logging its value, then returns a constant JSON body.
 *
 * @param {{
 *   sentinel?: string,
 *   credentials?: import('./basic-credentials.js').BasicCredentials,
 *   host?: string,
 *   path?: string,
 *   method?: string,
 *   credentialClass?: 'http_bearer' | 'http_api_key_header' | 'http_basic' | 'http_api_key_query',
 *   headerName?: string,
 *   queryName?: string,
 * }} options
 * @returns {Promise<{
 *   server: http.Server,
 *   host: string,
 *   port: number,
 *   baseUrl: string,
 *   close: () => Promise<void>,
 * }>}
 */
export async function startFakeApi(options) {
  const host = options.host ?? '127.0.0.1';
  const allowedPath = options.path ?? '/v1/resource';
  const allowedMethod = options.method ?? 'GET';
  const credentialClass = options.credentialClass ?? 'http_bearer';
  if (
    credentialClass !== 'http_bearer' &&
    credentialClass !== 'http_api_key_header' &&
    credentialClass !== 'http_basic' &&
    credentialClass !== 'http_api_key_query'
  ) {
    throw new Error('startFakeApi received an unsupported credential class');
  }

  let expectedValue;
  /** @type {string | null} */
  let headerName = null;
  /** @type {string | null} */
  let queryName = null;

  if (credentialClass === 'http_api_key_query') {
    queryName = options.queryName ?? null;
    if (typeof queryName !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/.test(queryName)) {
      throw new Error('startFakeApi requires an exact lowercase query_name');
    }
    if (options.credentials !== undefined) {
      throw new Error('startFakeApi rejects credentials material for query mode');
    }
    const sentinel = options.sentinel;
    if (typeof sentinel !== 'string' || sentinel.length === 0) {
      throw new Error('startFakeApi requires an explicit runtime sentinel');
    }
    expectedValue = sentinel;
  } else {
    headerName =
      credentialClass === 'http_api_key_header'
        ? options.headerName ?? null
        : 'authorization';
    if (
      typeof headerName !== 'string' ||
      headerName.length === 0 ||
      !/^[!#$%&'*+\-.^_`|~0-9a-z]+$/.test(headerName)
    ) {
      throw new Error(
        'startFakeApi requires a canonical lowercase API-key header name',
      );
    }
    if (credentialClass === 'http_basic') {
      if (options.sentinel !== undefined) {
        throw new Error('startFakeApi rejects sentinel material for HTTP Basic');
      }
      let credentials;
      try {
        credentials = validateBasicCredentials(options.credentials);
      } catch {
        throw new Error(
          'startFakeApi requires an exact valid HTTP Basic credentials object',
        );
      }
      expectedValue = basicAuthorizationValue(credentials);
    } else {
      if (options.credentials !== undefined) {
        throw new Error(
          'startFakeApi rejects credentials material for bearer and API-key modes',
        );
      }
      const sentinel = options.sentinel;
      if (typeof sentinel !== 'string' || sentinel.length === 0) {
        throw new Error('startFakeApi requires an explicit runtime sentinel');
      }
      expectedValue =
        credentialClass === 'http_bearer' ? `Bearer ${sentinel}` : sentinel;
    }
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://${host}`);

    if (req.method !== allowedMethod || url.pathname !== allowedPath) {
      res.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }

    if (credentialClass === 'http_api_key_query') {
      const keys = [...url.searchParams.keys()];
      if (
        keys.length !== 1 ||
        keys[0] !== queryName ||
        url.searchParams.get(/** @type {string} */ (queryName)) !== expectedValue
      ) {
        res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      // Header credentials must not satisfy a query-only policy.
      if (req.headers.authorization !== undefined) {
        res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
    } else {
      if (url.search !== '' && url.search !== '?') {
        res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'query_forbidden' }));
        return;
      }
      const credentialValues = rawHeaderValues(
        req.rawHeaders,
        /** @type {string} */ (headerName),
      );
      if (
        credentialValues.length !== 1 ||
        credentialValues[0] !== expectedValue
      ) {
        res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
    }

    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(FAKE_API_CONSTANT_BODY));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, () => {
      server.off('error', reject);
      resolve(undefined);
    });
  });

  const address = server.address();
  if (address === null || typeof address === 'string') {
    await closeServer(server);
    throw new Error('fake API failed to bind a TCP port');
  }

  const port = address.port;
  const baseUrl = `http://${host}:${port}`;

  return {
    server,
    host,
    port,
    baseUrl,
    close: () => closeServer(server),
  };
}

/**
 * @param {string[]} rawHeaders
 * @param {string} headerName
 * @returns {string[]}
 */
function rawHeaderValues(rawHeaders, headerName) {
  const needle = headerName.toLowerCase();
  /** @type {string[]} */
  const values = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (rawHeaders[i].toLowerCase() === needle) {
      values.push(rawHeaders[i + 1]);
    }
  }
  return values;
}

/**
 * @param {http.Server} server
 * @returns {Promise<void>}
 */
function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
