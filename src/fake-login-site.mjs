import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { validateBasicCredentials } from './basic-credentials.js';

const SESSION_COOKIE = 'fake_session';

/**
 * Loopback fake website login surface for Phase 6 browser_form_login tests.
 * Accepts one runtime username/password pair; issues an opaque session cookie.
 *
 * @param {{
 *   credentials: import('./basic-credentials.js').BasicCredentials,
 *   host?: string,
 *   loginPath?: string,
 *   formAction?: string,
 *   successPath?: string,
 *   usernameField?: string,
 *   passwordField?: string,
 *   hiddenFields?: Record<string, string>,
 *   challengeMode?: 'none' | 'mfa' | 'captcha',
 * }} options
 */
export async function startFakeLoginSite(options) {
  const credentials = validateBasicCredentials(options.credentials);
  const host = options.host ?? '127.0.0.1';
  const loginPath = options.loginPath ?? '/login';
  const formAction = options.formAction ?? '/login';
  const successPath = options.successPath ?? '/home';
  const mePath = '/api/me';
  const usernameField = options.usernameField ?? 'username';
  const passwordField = options.passwordField ?? 'password';
  const hiddenFields = options.hiddenFields ?? Object.create(null);
  const challengeMode = options.challengeMode ?? 'none';
  /** @type {Set<string>} */
  const sessions = new Set();

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://${host}`);
    if (req.method === 'GET' && url.pathname === loginPath) {
      if (challengeMode === 'mfa') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><html><body><p>Enter MFA code</p></body></html>');
        return;
      }
      if (challengeMode === 'captcha') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><html><body><div class="recaptcha">bot-check</div></body></html>');
        return;
      }
      const hiddenHtml = Object.entries(hiddenFields)
        .map(([name, value]) =>
          `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />`)
        .join('');
      const body =
        `<!doctype html><html><body><form method="POST" action="${escapeHtml(formAction)}">` +
        `<input name="${escapeHtml(usernameField)}" />` +
        `<input name="${escapeHtml(passwordField)}" type="password" />` +
        `${hiddenHtml}<button type="submit">login</button></form></body></html>`;
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(body);
      return;
    }

    if (req.method === 'POST' && url.pathname === formAction) {
      void readBody(req).then((raw) => {
        const params = new URLSearchParams(raw);
        for (const [name, expected] of Object.entries(hiddenFields)) {
          if (params.get(name) !== expected) {
            writeFixed(res, 400, 'login_failed');
            return;
          }
        }
        if (params.get(usernameField) !== credentials.username ||
            params.get(passwordField) !== credentials.password) {
          // Deliberately do not echo submitted password values.
          writeFixed(res, 401, 'login_failed');
          return;
        }
        if (params.has('otp') || params.has('totp') || params.has('mfa')) {
          writeFixed(res, 403, 'mfa_required');
          return;
        }
        const token = randomBytes(32).toString('base64url');
        sessions.add(token);
        res.writeHead(302, {
          location: successPath,
          'set-cookie': `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict`,
        });
        res.end();
      }).catch(() => writeFixed(res, 400, 'login_failed'));
      return;
    }

    if (req.method === 'GET' && (url.pathname === successPath || url.pathname === mePath)) {
      const cookieHeader = req.headers.cookie ?? '';
      const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
      const token = match?.[1];
      if (typeof token !== 'string' || !sessions.has(token)) {
        writeFixed(res, 401, 'unauthorized');
        return;
      }
      if (url.pathname === mePath) {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: true, role: 'member' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><html><body><h1>home</h1></body></html>');
      return;
    }

    writeFixed(res, 404, 'not_found');
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
    throw new Error('fake login site failed to bind');
  }

  return {
    server,
    host,
    port: address.port,
    baseUrl: `http://${host}:${address.port}`,
    sessionCookieName: SESSION_COOKIE,
    close: () => closeServer(server),
  };
}

function writeFixed(res, status, code) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: code }));
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 16 * 1024) {
        reject(new Error('body_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    server.close(() => resolve());
  });
}
