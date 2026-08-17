import {
  BridgeBrowserTargetingError,
  parseLoginPageFacts,
} from './bridge-browser-targeting.mjs';

const MAX_BODY_BYTES = 256 * 1024;

/**
 * Fetch-backed page adapter for loopback fake login sites.
 * Cookies stay in a private jar and are never returned to callers.
 *
 * @param {{ origin: string, loginPath: string, fetchImpl?: typeof fetch }} options
 */
export function createFetchPageAdapter(options) {
  if (typeof options.origin !== 'string' || typeof options.loginPath !== 'string') {
    throw new BridgeBrowserTargetingError('invalid_request');
  }
  const origin = new URL(options.origin).origin;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  /** @type {Map<string, string>} */
  const jar = new Map();
  let currentUrl = new URL(options.loginPath, `${origin}/`).href;

  return {
    origin,
    /**
     * @returns {Promise<{ html: string, url: string, facts: ReturnType<typeof parseLoginPageFacts> }>}
     */
    async snapshotPage() {
      const { html, url } = await request(fetchImpl, jar, currentUrl, { method: 'GET' });
      currentUrl = url;
      const facts = parseLoginPageFacts(html, url);
      return { html, url, facts };
    },

    /**
     * @param {{
     *   formAction: string,
     *   usernameField: string,
     *   passwordField: string,
     *   username: string,
     *   password: string,
     *   hiddenNames: string[],
     *   maxRedirectHops: number,
     *   submitLabel?: string,
     * }} submit
     */
    async submitLogin(submit) {
      void submit.submitLabel;
      const { html: loginHtml, url: loginUrl } = await request(fetchImpl, jar, currentUrl, {
        method: 'GET',
      });
      const facts = parseLoginPageFacts(loginHtml, loginUrl);
      const hidden = {};
      for (const name of submit.hiddenNames) {
        const match = loginHtml.match(
          new RegExp(`<input\\b[^>]*name=["']${escapeRegExp(name)}["'][^>]*>`, 'i'),
        );
        if (!match) {
          throw new BridgeBrowserTargetingError('target_kind_mismatch');
        }
        const attrs = parseAttrs(match[0].replace(/^<input\b/i, '').replace(/>$/, ''));
        hidden[name] = attrs.value ?? '';
      }
      const body = new URLSearchParams();
      body.set(submit.usernameField, submit.username);
      body.set(submit.passwordField, submit.password);
      for (const [name, value] of Object.entries(hidden)) body.set(name, value);

      const posted = await request(fetchImpl, jar, submit.formAction, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        maxRedirectHops: submit.maxRedirectHops,
      });
      currentUrl = posted.url;
      return {
        url: posted.url,
        html: posted.html,
        facts: parseLoginPageFacts(posted.html, posted.url),
      };
    },

    /**
     * @param {string} absoluteUrl
     */
    async goto(absoluteUrl) {
      const target = new URL(absoluteUrl);
      if (target.origin !== origin) {
        throw new BridgeBrowserTargetingError('origin_mismatch');
      }
      const { html, url } = await request(fetchImpl, jar, target.href, { method: 'GET' });
      currentUrl = url;
      return { html, url, facts: parseLoginPageFacts(html, url) };
    },

    currentUrl() {
      return currentUrl;
    },

    /**
     * Cookie *names* only, for internal sensitive-set updates. Values stay private.
     * @returns {string[]}
     */
    cookieNames() {
      return [...jar.keys()];
    },

    /**
     * Add issued cookie values into a sensitive set without exposing them to the agent.
     * @param {Set<string>} sensitive
     */
    async absorbCookiesInto(sensitive) {
      for (const value of jar.values()) {
        if (value.length >= 8) sensitive.add(value);
      }
    },

    async passwordFieldsOccupied() {
      return false;
    },

    async screenshotPage() {
      throw new BridgeBrowserTargetingError('screenshot_unsupported');
    },

    async resetLoginPage() {
      const target = new URL(options.loginPath, `${origin}/`).href;
      const { html, url } = await request(fetchImpl, jar, target, { method: 'GET' });
      currentUrl = url;
      return { html, url, facts: parseLoginPageFacts(html, url) };
    },

    async close() {
      jar.clear();
    },
  };
}

/**
 * @param {typeof fetch} fetchImpl
 * @param {Map<string, string>} jar
 * @param {string} url
 * @param {{ method: string, headers?: Record<string, string>, body?: string, maxRedirectHops?: number }} init
 */
async function request(fetchImpl, jar, url, init) {
  let current = url;
  let hops = 0;
  const maxHops = init.maxRedirectHops ?? 3;
  let method = init.method;
  let body = init.body;
  let headers = { ...(init.headers ?? {}) };

  while (true) {
    headers = {
      ...headers,
      cookie: cookieHeader(jar),
    };
    const response = await fetchImpl(current, {
      method,
      headers,
      body: method === 'GET' ? undefined : body,
      redirect: 'manual',
    });
    absorbSetCookie(jar, response.headers);
    if (isRedirect(response.status)) {
      const location = response.headers.get('location');
      if (!location) {
        throw new BridgeBrowserTargetingError('adapter_failed');
      }
      hops += 1;
      if (hops > maxHops) {
        throw new BridgeBrowserTargetingError('adapter_failed');
      }
      current = new URL(location, current).href;
      method = 'GET';
      body = undefined;
      headers = {};
      await response.arrayBuffer();
      continue;
    }
    const html = await readBoundedText(response);
    return { html, url: current, status: response.status };
  }
}

function absorbSetCookie(jar, headers) {
  const lines = typeof headers.getSetCookie === 'function'
    ? headers.getSetCookie()
    : rawSetCookie(headers);
  for (const line of lines) {
    const pair = String(line).split(';', 1)[0];
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
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

async function readBoundedText(response) {
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength > MAX_BODY_BYTES) {
    throw new BridgeBrowserTargetingError('page_unreadable');
  }
  return Buffer.from(buffer).toString('utf8');
}

function parseAttrs(raw) {
  /** @type {Record<string, string>} */
  const attrs = {};
  const re = /([a-zA-Z_:][\w:.-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let match;
  while ((match = re.exec(raw)) !== null) {
    attrs[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
  }
  return attrs;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
