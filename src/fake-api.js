import http from 'node:http';
import { FAKE_API_CONSTANT_BODY } from './constants.js';

/**
 * Local fake HTTP API used only by this Phase 1 harness.
 * Accepts a single caller-supplied bearer-token sentinel and returns a constant JSON body.
 *
 * @param {{
 *   sentinel: string,
 *   host?: string,
 *   path?: string,
 *   method?: string,
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
  const sentinel = options?.sentinel;
  if (typeof sentinel !== 'string' || sentinel.length === 0) {
    throw new Error('startFakeApi requires an explicit runtime sentinel');
  }

  const host = options.host ?? '127.0.0.1';
  const allowedPath = options.path ?? '/v1/resource';
  const allowedMethod = options.method ?? 'GET';

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://${host}`);

    if (req.method !== allowedMethod || url.pathname !== allowedPath) {
      res.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }

    const auth = req.headers.authorization;
    const expected = `Bearer ${sentinel}`;
    if (auth !== expected) {
      res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
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

/** @param {http.Server} server */
function closeServer(server) {
  return new Promise((resolve, reject) => {
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    server.close((err) => (err ? reject(err) : resolve()));
  });
}
