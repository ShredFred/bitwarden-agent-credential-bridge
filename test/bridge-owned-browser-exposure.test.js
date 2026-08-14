import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateFakeSentinel } from '../src/constants.js';
import { startBridgeOwnedBrowser } from '../src/bridge-owned-browser.mjs';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import { loadPolicy, withBind, withLoginOrigin } from '../src/policy.js';

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

describe('bridge-owned browser exposure', () => {
  it('keeps username, password, csrf value, and session cookie off agent surfaces', async () => {
    const username = 'user_abcdefgh';
    const password = generateFakeSentinel();
    const site = await startFakeLoginSite({
      credentials: { username, password },
      hiddenFields: { csrf: 'csrf_token_aa' },
    });
    const logs = [];
    const session = await startBridgeOwnedBrowser({
      policy: withBind(
        withLoginOrigin(await loadPolicy(samplePath), site.baseUrl),
        'http://127.0.0.1:0',
      ),
      credentials: { username, password },
      log: (entry) => logs.push(entry),
    });
    try {
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
      const status = await (await fetch(`${session.baseUrl}/status`)).json();
      const home = await (await fetch(`${session.baseUrl}/snapshot`)).json();
      const me = await (await fetch(`${session.baseUrl}/goto`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: '/api/me' }),
      })).json();
      const cookies = await (await fetch(`${session.baseUrl}/cookie_list`)).json();
      const shot = await (await fetch(`${session.baseUrl}/screenshot`)).json();

      const secrets = [username, password, 'csrf_token_aa'];
      assertNoSecret('snapshot', snap, secrets);
      assertNoSecret('inject', injected, secrets);
      assertNoSecret('status', status, secrets);
      assertNoSecret('home', home, secrets);
      assertNoSecret('goto', me, secrets);
      assertNoSecret('screenshot', shot, secrets);
      assertNoSecret('logs', logs, secrets);
      assertNoSecret('handle', {
        session_id: session.session_id,
        baseUrl: session.baseUrl,
      }, secrets);
      assert.equal(cookies.error, 'session_material_forbidden');
      assert.equal(shot.error, 'screenshot_unsupported');
      assert.equal(status.cookie_export_forbidden, true);
      assert.equal(status.agent_secret_visible, false);
    } finally {
      await session.close();
      await site.close();
    }
  });
});
