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
    assert.ok(!text.includes(secret), `${label} must not contain secret`);
  }
}

describe('browser form-login exposure', () => {
  it('keeps username, password, and session cookie off agent-readable surfaces', async () => {
    const username = 'user_abcdefgh';
    const password = generateFakeSentinel();
    const site = await startFakeLoginSite({
      credentials: { username, password },
      hiddenFields: { csrf: 'token-1' },
    });
    const logs = [];
    const broker = await startBrowserSessionBroker({
      policy: withBind(withLoginOrigin(await loadPolicy(samplePath), site.baseUrl), 'http://127.0.0.1:0'),
      credentials: { username, password },
      log: (entry) => logs.push(entry),
    });
    try {
      const replay = await fetch(broker.replayUrl);
      const body = await replay.text();
      const headerBlob = [...replay.headers.entries()];
      assertNoSecret('body', body, [username, password]);
      assertNoSecret('headers', headerBlob, [username, password]);
      assertNoSecret('logs', logs, [username, password]);
      assertNoSecret('broker handle', {
        session_id: broker.session_id,
        baseUrl: broker.baseUrl,
        replayUrl: broker.replayUrl,
      }, [username, password]);
      assert.equal(replay.headers.get('set-cookie'), null);
    } finally {
      await broker.close();
      await site.close();
    }
  });
});
