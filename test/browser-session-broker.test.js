import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateFakeSentinel } from '../src/constants.js';
import {
  BrowserSessionBrokerError,
  startBrowserSessionBroker,
} from '../src/browser-session-broker.mjs';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import { loadPolicy, withBind, withLoginOrigin } from '../src/policy.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const samplePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-browser-login.json',
);

describe('browser session broker', () => {
  it('logs in opaquely and replays only allowed paths without leaking secrets', async () => {
    const username = 'user_abcdefgh';
    const password = generateFakeSentinel();
    const site = await startFakeLoginSite({
      credentials: { username, password },
      hiddenFields: { csrf: 'token-1' },
    });
    const basePolicy = await loadPolicy(samplePath);
    const policy = withBind(
      withLoginOrigin(basePolicy, site.baseUrl),
      'http://127.0.0.1:0',
    );
    const logs = [];
    const broker = await startBrowserSessionBroker({
      policy,
      credentials: { username, password },
      log: (entry) => logs.push(entry),
    });
    try {
      assert.equal(broker.logged_in, true);
      assert.equal(broker.origin_bound, true);
      assert.equal(typeof broker.session_id, 'string');
      assert.equal(broker.session_id.length, 64);

      const denied = await fetch(`${broker.baseUrl}/login`);
      assert.equal(denied.status, 404);

      const replay = await fetch(broker.replayUrl);
      assert.equal(replay.status, 200);
      const text = await replay.json();
      assert.equal(text.ok, true);
      assert.equal(JSON.stringify(text).includes(password), false);
      assert.equal(JSON.stringify(logs).includes(password), false);
      assert.equal(JSON.stringify(broker).includes(password), false);
    } finally {
      await broker.close();
      await site.close();
    }
  });

  it('fails closed on bad credentials without returning HTML', async () => {
    const username = 'user_abcdefgh';
    const password = generateFakeSentinel();
    const site = await startFakeLoginSite({
      credentials: { username, password },
      hiddenFields: { csrf: 'token-1' },
    });
    const policy = withBind(
      withLoginOrigin(await loadPolicy(samplePath), site.baseUrl),
      'http://127.0.0.1:0',
    );
    await assert.rejects(
      () => startBrowserSessionBroker({
        policy,
        credentials: { username, password: `${password}x` },
      }),
      (error) => error instanceof BrowserSessionBrokerError &&
        (error.code === 'login_failed' || error.code === 'success_path_mismatch' ||
          error.code === 'session_cookie_absent'),
    );
    await site.close();
  });
});
