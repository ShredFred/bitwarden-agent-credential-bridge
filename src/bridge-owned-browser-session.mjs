import path from 'node:path';
import { startFakeLoginSite } from './fake-login-site.mjs';
import {
  BridgeOwnedBrowserError,
  startBridgeOwnedBrowser,
} from './bridge-owned-browser.mjs';
import { loadPolicy, validatePolicy, withBind, withLoginOrigin } from './policy.js';

/**
 * Start a Bridge-owned browser for one already-validated operational binding.
 * Resolves credentials through the injected callback (fake or SM). Never
 * accepts approval flags. Cookies stay in the adapter.
 *
 * @param {{
 *   repoRoot: string,
 *   bindings: { bindings: Array<{
 *     alias: string,
 *     policy: string,
 *     credential_class: string,
 *   }> },
 *   alias: string,
 *   resolveSecret: (binding: object) => Promise<{
 *     credential_class: string,
 *     username?: string,
 *     password?: string,
 *   }>,
 *   driver?: 'fetch' | 'playwright',
 *   playwright?: object,
 *   bind?: string,
 *   headless?: boolean,
 *   browser?: 'chromium' | 'firefox' | 'webkit',
 * }} options
 */
export async function startBridgeOwnedBrowserForBinding(options) {
  if (typeof options.repoRoot !== 'string' || options.repoRoot.length < 1) {
    throw new BridgeOwnedBrowserError('invalid_request');
  }
  const alias = options.alias;
  if (typeof alias !== 'string') {
    throw new BridgeOwnedBrowserError('invalid_alias');
  }
  const binding = options.bindings.bindings.find((entry) => entry.alias === alias);
  if (!binding) {
    throw new BridgeOwnedBrowserError('unknown_alias');
  }
  if (binding.credential_class !== 'browser_form_login') {
    throw new BridgeOwnedBrowserError('wrong_broker');
  }

  let policy;
  try {
    policy = validatePolicy(await loadPolicy(path.join(options.repoRoot, binding.policy)));
  } catch {
    throw new BridgeOwnedBrowserError('invalid_policy');
  }
  if (policy.credential_class !== 'browser_form_login') {
    throw new BridgeOwnedBrowserError('wrong_broker');
  }

  const selected = await options.resolveSecret(binding);
  if (
    selected.credential_class !== 'browser_form_login' ||
    typeof selected.username !== 'string' ||
    typeof selected.password !== 'string'
  ) {
    throw new BridgeOwnedBrowserError('invalid_credentials');
  }
  const credentials = {
    username: selected.username,
    password: selected.password,
  };
  const hiddenFields = Object.fromEntries(
    policy.hidden_fields.map((name) => [name, `token-${binding.alias}`]),
  );
  const site = await startFakeLoginSite({ credentials, hiddenFields });
  const bind = options.bind ?? 'http://127.0.0.1:0';
  const driver = options.driver ?? 'fetch';
  try {
    const session = await startBridgeOwnedBrowser({
      policy: withBind(withLoginOrigin(policy, site.baseUrl), bind),
      credentials,
      driver,
      playwright: options.playwright,
      headless: options.headless,
      browser: options.browser,
    });
    return {
      alias,
      driver,
      runtime: 'bridge_owned_browser',
      session,
      async close() {
        await session.close();
        await site.close();
      },
    };
  } catch (error) {
    await site.close().catch(() => {});
    throw error;
  }
}
