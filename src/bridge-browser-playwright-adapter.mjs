import {
  BridgeBrowserTargetingError,
  parseLoginPageFacts,
} from './bridge-browser-targeting.mjs';

/**
 * In-process Playwright driver owned by the Bridge.
 * The page, context, CDP, and cookie values never appear on the returned adapter.
 *
 * @param {{
 *   origin: string,
 *   loginPath: string,
 *   playwright?: object,
 *   browser?: 'chromium' | 'firefox' | 'webkit',
 *   headless?: boolean,
 * }} options
 */
export async function createPlaywrightPageAdapter(options) {
  if (typeof options.origin !== 'string' || typeof options.loginPath !== 'string') {
    throw new BridgeBrowserTargetingError('invalid_request');
  }
  const origin = new URL(options.origin).origin;
  const playwright = options.playwright ?? await importPlaywright();
  const requested = options.browser ?? 'chromium';
  const browserType = pickBrowser(playwright, requested);
  const launchOptions = {
    headless: options.headless !== false,
    devtools: false,
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  };
  if (requested === 'chromium') launchOptions.chromiumSandbox = false;

  let browser;
  try {
    browser = await browserType.launch(launchOptions);
  } catch {
    throw new BridgeBrowserTargetingError('playwright_launch_failed');
  }

  let context;
  let page;
  try {
    context = await browser.newContext({
      acceptDownloads: false,
      javaScriptEnabled: true,
      bypassCSP: false,
      ignoreHTTPSErrors: false,
    });
    page = await context.newPage();
    const loginUrl = new URL(options.loginPath, `${origin}/`).href;
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded' });
  } catch (error) {
    if (context) await context.close().catch(() => {});
    await browser.close().catch(() => {});
    if (error instanceof BridgeBrowserTargetingError) throw error;
    throw new BridgeBrowserTargetingError('playwright_launch_failed');
  }

  return {
    origin,
    async snapshotPage() {
      try {
        const url = page.url();
        assertSameOrigin(url, origin);
        const html = await page.content();
        return { html, url, facts: parseLoginPageFacts(html, url) };
      } catch (error) {
        if (error instanceof BridgeBrowserTargetingError) throw error;
        throw new BridgeBrowserTargetingError('adapter_failed');
      }
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
      try {
        void submit.hiddenNames;
        void submit.maxRedirectHops;
        assertSameOrigin(submit.formAction, origin);
        const usernameSel = nameSelector(submit.usernameField, false);
        const passwordSel = nameSelector(submit.passwordField, true);
        await page.locator(usernameSel).fill(submit.username);
        await page.locator(passwordSel).fill(submit.password);
        await clickAuthorizedSubmit(page, submit.submitLabel);
        await page.waitForLoadState('domcontentloaded');
        const url = page.url();
        assertSameOrigin(url, origin);
        const html = await page.content();
        return { html, url, facts: parseLoginPageFacts(html, url) };
      } catch (error) {
        if (error instanceof BridgeBrowserTargetingError) throw error;
        throw new BridgeBrowserTargetingError('adapter_failed');
      }
    },

    /**
     * @param {string} absoluteUrl
     */
    async goto(absoluteUrl) {
      try {
        const target = new URL(absoluteUrl);
        if (target.origin !== origin) {
          throw new BridgeBrowserTargetingError('origin_mismatch');
        }
        await page.goto(target.href, { waitUntil: 'domcontentloaded' });
        const url = page.url();
        assertSameOrigin(url, origin);
        const html = await page.content();
        return { html, url, facts: parseLoginPageFacts(html, url) };
      } catch (error) {
        if (error instanceof BridgeBrowserTargetingError) throw error;
        throw new BridgeBrowserTargetingError('adapter_failed');
      }
    },

    currentUrl() {
      return page.url();
    },

    async cookieNames() {
      const cookies = await context.cookies();
      return cookies.map((cookie) => cookie.name);
    },

    /**
     * @param {Set<string>} sensitive
     */
    async absorbCookiesInto(sensitive) {
      const cookies = await context.cookies();
      for (const cookie of cookies) {
        if (cookie.value.length >= 8) sensitive.add(cookie.value);
      }
    },

    async close() {
      await context.close().catch(() => {});
      await browser.close().catch(() => {});
    },
  };
}

async function importPlaywright() {
  try {
    return await import('playwright');
  } catch {
    throw new BridgeBrowserTargetingError('playwright_absent');
  }
}

function pickBrowser(playwright, name) {
  const requested = name ?? 'chromium';
  const type = playwright[requested];
  if (!type || typeof type.launch !== 'function') {
    throw new BridgeBrowserTargetingError('playwright_absent');
  }
  return type;
}

function assertSameOrigin(url, origin) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
  if (parsed.origin !== origin) {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
}

function nameSelector(field, password) {
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(field)) {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
  if (password) return `input[name="${field}"][type="password"]`;
  return `input[name="${field}"]`;
}

/**
 * @param {{ locator: Function }} page
 * @param {string | undefined} label
 */
async function clickAuthorizedSubmit(page, label) {
  if (typeof label !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,63}$/.test(label)) {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
  const form = page.locator('form');
  if (typeof form.getByRole === 'function') {
    await form.getByRole('button', { name: label, exact: true }).click();
    return;
  }
  await form.locator('button[type="submit"], button:not([type]), input[type="submit"]').first().click();
}
