import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateFakeSentinel } from '../src/constants.js';
import { startBrowserSessionBroker } from '../src/browser-session-broker.mjs';
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

function assertNoSecret(label, value, secrets) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of secrets) {
    if (!secret || secret.length < 8) continue;
    assert.ok(!text.includes(secret), `${label} must not contain secret material`);
  }
}

describe('browser form-login exposure', () => {
  it('keeps username, password, and issued session cookie off agent-readable surfaces', async () => {
    const username = 'user_abcdefgh';
    const password = generateFakeSentinel();
    const site = await startFakeLoginSite({
      credentials: { username, password },
      hiddenFields: { csrf: 'token-1' },
    });
    const logs = [];
    /** @type {string[]} */
    const capturedCookies = [];
    const realFetch = globalThis.fetch;
    const fetchImpl = async (input, init) => {
      const response = await realFetch(input, init);
      const lines = typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : [];
      for (const line of lines) {
        const pair = String(line).split(';', 1)[0];
        const eq = pair.indexOf('=');
        if (eq > 0) capturedCookies.push(pair.slice(eq + 1).trim());
      }
      return response;
    };

    const broker = await startBrowserSessionBroker({
      policy: withBind(withLoginOrigin(await loadPolicy(samplePath), site.baseUrl), 'http://127.0.0.1:0'),
      credentials: { username, password },
      fetchImpl,
      log: (entry) => logs.push(entry),
    });
    try {
      assert.ok(capturedCookies.length >= 1, 'login must issue a session cookie');
      const secrets = [username, password, ...capturedCookies];
      const replay = await fetch(broker.replayUrl);
      const body = await replay.text();
      const headerBlob = [...replay.headers.entries()];
      assertNoSecret('body', body, secrets);
      assertNoSecret('headers', headerBlob, secrets);
      assertNoSecret('logs', logs, secrets);
      assertNoSecret('broker handle', {
        session_id: broker.session_id,
        baseUrl: broker.baseUrl,
        replayUrl: broker.replayUrl,
      }, secrets);
      assert.equal(replay.headers.get('set-cookie'), null);
    } finally {
      await broker.close();
      await site.close();
    }
  });
});
