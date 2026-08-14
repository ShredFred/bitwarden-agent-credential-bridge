import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateFakeSentinel } from '../src/constants.js';
import { startBridgeOwnedBrowser, BridgeOwnedBrowserError } from '../src/bridge-owned-browser.mjs';
import { createPlaywrightPageAdapter } from '../src/bridge-browser-playwright-adapter.mjs';
import { BridgeBrowserTargetingError } from '../src/bridge-browser-targeting.mjs';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import { loadPolicy, withBind, withLoginOrigin } from '../src/policy.js';

const samplePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-browser-login.json',
);

const LOGIN_HTML =
  '<form method="POST" action="/login">' +
  '<input name="username" />' +
  '<input name="password" type="password" />' +
  '<input type="hidden" name="csrf" value="csrf_token_aa" />' +
  '<button type="submit">login</button></form>';

const HOME_HTML = '<html><body><h1>home</h1></body></html>';
const ME_JSON = '{"ok":true,"role":"member"}';

function makeStubPlaywright(origin) {
  let url = `${origin}/login`;
  let html = LOGIN_HTML;
  const cookieStore = [];
  const fills = [];

  function locator(selector) {
    const loc = {
      fill: async (value) => {
        fills.push({ selector, value });
      },
      click: async () => {
        url = `${origin}/home`;
        html = HOME_HTML;
        cookieStore.splice(0, cookieStore.length, {
          name: 'fake_session',
          value: 'sessiontoken_abcdefghijk',
        });
      },
      first: () => loc,
      getByRole: () => loc,
      locator: () => loc,
    };
    return loc;
  }

  const page = {
    url: () => url,
    content: async () => html,
    goto: async (next) => {
      url = next;
      if (String(next).endsWith('/api/me')) html = ME_JSON;
      else if (String(next).endsWith('/home')) html = HOME_HTML;
      else html = LOGIN_HTML;
    },
    locator,
    waitForLoadState: async () => {},
  };

  const stub = {
    fills,
    cookieStore,
    launchOptions: null,
    chromium: {
      launch: async (opts) => {
        stub.launchOptions = opts;
        return {
          newContext: async () => ({
            newPage: async () => page,
            cookies: async () => cookieStore.map((cookie) => ({ ...cookie })),
            close: async () => {},
          }),
          close: async () => {},
        };
      },
    },
  };
  return stub;
}

async function policyFor(origin) {
  return withBind(
    withLoginOrigin(await loadPolicy(samplePath), origin),
    'http://127.0.0.1:0',
  );
}

describe('bridge-owned playwright driver', () => {
  it('injects through a Bridge-owned stub browser without exposing cookies or the page', async () => {
    const origin = 'http://127.0.0.1:9';
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const stub = makeStubPlaywright(origin);
    const session = await startBridgeOwnedBrowser({
      policy: await policyFor(origin),
      credentials,
      driver: 'playwright',
      playwright: stub,
    });
    try {
      assert.equal(session.agent_cdp_absent, true);
      assert.equal(session.screenshot_forbidden, true);
      assert.equal(session.headless, true);
      assert.equal(stub.launchOptions.headless, true);
      assert.equal(stub.launchOptions.devtools, false);
      assert.equal(stub.launchOptions.handleSIGINT, false);
      assert.equal(JSON.stringify(session).includes('newPage'), false);
      const snap = await (await fetch(`${session.baseUrl}/snapshot`)).json();
      await fetch(`${session.baseUrl}/select_targets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          generation: snap.generation,
          username_index: 0,
          password_index: 1,
          submit_index: 2,
        }),
      });
      const injected = await (await fetch(`${session.baseUrl}/inject_login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      })).json();
      assert.equal(injected.logged_in, true);
      assert.equal(JSON.stringify(injected).includes(credentials.password), false);
      assert.equal(JSON.stringify(injected).includes('sessiontoken_abcdefghijk'), false);
      assert.ok(stub.fills.some((f) => f.selector.includes('password') && f.value === credentials.password));
      const cookies = await (await fetch(`${session.baseUrl}/cookie_list`)).json();
      assert.equal(cookies.error, 'session_material_forbidden');
    } finally {
      await session.close();
    }
  });

  it('launches headed Playwright when requested and still forbids screenshots', async () => {
    const origin = 'http://127.0.0.1:9';
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const stub = makeStubPlaywright(origin);
    const session = await startBridgeOwnedBrowser({
      policy: await policyFor(origin),
      credentials,
      driver: 'playwright',
      playwright: stub,
      headless: false,
    });
    try {
      assert.equal(session.headless, false);
      assert.equal(stub.launchOptions.headless, false);
      assert.equal(stub.launchOptions.devtools, false);
      assert.equal(session.screenshot_forbidden, true);
      const screenshot = await (await fetch(`${session.baseUrl}/screenshot`)).json();
      assert.equal(screenshot.error, 'command_forbidden');
    } finally {
      await session.close();
    }
  });

  it('fails closed when Playwright is not installed', async () => {
    await assert.rejects(
      () => createPlaywrightPageAdapter({
        origin: 'http://127.0.0.1:9',
        loginPath: '/login',
        playwright: {},
      }),
      (error) => error instanceof BridgeBrowserTargetingError &&
        error.code === 'playwright_absent',
    );
    await assert.rejects(
      async () => startBridgeOwnedBrowser({
        policy: await policyFor('http://127.0.0.1:9'),
        credentials: { username: 'user_abcdefgh', password: generateFakeSentinel() },
        driver: 'playwright',
        playwright: {},
      }),
      (error) => error instanceof BridgeOwnedBrowserError &&
        error.code === 'playwright_absent',
    );
  });

  it('drives the fake login site with real Playwright when present', async (t) => {
    let playwright;
    try {
      playwright = await import('playwright');
    } catch {
      t.skip('playwright package is not installed');
      return;
    }
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const site = await startFakeLoginSite({
      credentials,
      hiddenFields: { csrf: 'csrf_token_aa' },
    });
    let session;
    try {
      session = await startBridgeOwnedBrowser({
        policy: await policyFor(site.baseUrl),
        credentials,
        driver: 'playwright',
        playwright,
        browser: playwright.firefox ? 'firefox' : 'chromium',
        headless: true,
      });
      const snap = await (await fetch(`${session.baseUrl}/snapshot`)).json();
      assert.equal(snap.candidates[1].kind, 'password');
      await fetch(`${session.baseUrl}/select_targets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          generation: snap.generation,
          username_index: 0,
          password_index: 1,
          submit_index: 2,
        }),
      });
      const injected = await (await fetch(`${session.baseUrl}/inject_login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      })).json();
      assert.equal(injected.logged_in, true);
      assert.equal(JSON.stringify(injected).includes(credentials.password), false);
    } catch (error) {
      if (error && error.code === 'playwright_launch_failed') {
        t.skip('playwright browsers are not installed');
        return;
      }
      throw error;
    } finally {
      if (session) await session.close();
      await site.close();
    }
  });
});
