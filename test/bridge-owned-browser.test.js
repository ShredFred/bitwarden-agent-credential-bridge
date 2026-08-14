import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateFakeSentinel } from '../src/constants.js';
import {
  BridgeOwnedBrowserError,
  MAX_BRIDGE_OWNED_BROWSERS,
  startBridgeOwnedBrowser,
} from '../src/bridge-owned-browser.mjs';
import { FORBIDDEN_AGENT_OPS } from '../src/bridge-browser-targeting.mjs';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import { loadPolicy, withBind, withLoginOrigin } from '../src/policy.js';

const samplePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-browser-login.json',
);

async function policyFor(origin) {
  return withBind(
    withLoginOrigin(await loadPolicy(samplePath), origin),
    'http://127.0.0.1:0',
  );
}

async function readJson(response) {
  return JSON.parse(await response.text());
}

describe('bridge-owned browser', () => {
  it('lets the agent pick indices then injects login without a password in the command', async () => {
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const site = await startFakeLoginSite({
      credentials,
      hiddenFields: { csrf: 'token-1' },
    });
    const session = await startBridgeOwnedBrowser({
      policy: await policyFor(site.baseUrl),
      credentials,
    });
    try {
      assert.equal(session.origin_bound, true);
      assert.equal(session.agent_cdp_absent, true);
      assert.equal(session.cookie_export_forbidden, true);
      assert.equal(session.screenshot_password_entry_forbidden, true);
      assert.equal(session.headless, true);
      assert.equal(session.driver, 'fetch');
      assert.equal(session.authorization_ready, false);

      const contract = await readJson(await fetch(`${session.baseUrl}/contract`));
      assert.equal(contract.ok, true);
      assert.ok(contract.allowed_ops.includes('snapshot'));
      assert.ok(contract.forbidden_ops.includes('cookie_list'));
      assert.equal(contract.screenshot_password_entry_forbidden, true);
      assert.equal(contract.screenshot_unsupported, true);
      assert.ok(contract.allowed_ops.includes('screenshot'));
      assert.equal(contract.headless, true);
      assert.ok(contract.allowed_paths.includes('/home'));
      assert.ok(contract.error_codes.includes('session_material_forbidden'));
      assert.deepEqual(contract.inject_login_body, ['empty', 'generation']);
      assert.equal(JSON.stringify(contract).includes(credentials.password), false);

      const snapRes = await fetch(`${session.baseUrl}/snapshot`);
      const snap = await readJson(snapRes);
      assert.equal(snapRes.status, 200);
      assert.equal(snap.logged_in, false);
      assert.equal(snap.candidates[0].kind, 'username');
      assert.equal(snap.candidates[1].kind, 'password');
      assert.equal(snap.candidates[2].kind, 'submit');
      assert.equal(JSON.stringify(snap).includes(credentials.password), false);
      assert.equal(JSON.stringify(snap).includes('token-1'), false);

      const selectRes = await fetch(`${session.baseUrl}/select_targets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          generation: snap.generation,
          username_index: 0,
          password_index: 1,
          submit_index: 2,
        }),
      });
      assert.equal(selectRes.status, 200);

      const injectRes = await fetch(`${session.baseUrl}/inject_login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      const injected = await readJson(injectRes);
      assert.equal(injectRes.status, 200);
      assert.equal(injected.logged_in, true);
      assert.equal(session.logged_in, true);
      assert.equal(JSON.stringify(injected).includes(credentials.password), false);

      const home = await readJson(await fetch(`${session.baseUrl}/snapshot`));
      assert.equal(home.logged_in, true);
      assert.equal(home.path, '/home');
      assert.equal(home.title, 'home');

      const me = await readJson(await fetch(`${session.baseUrl}/goto`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: '/api/me' }),
      }));
      assert.equal(me.ok, true);
      assert.equal(me.path, '/api/me');
    } finally {
      await session.close();
      await site.close();
    }
  });

  it('rejects headed fetch because there is no window to show', async () => {
    await assert.rejects(
      async () => startBridgeOwnedBrowser({
        policy: await policyFor('http://127.0.0.1:9'),
        credentials: { username: 'user_abcdefgh', password: generateFakeSentinel() },
        headless: false,
      }),
      (error) => error instanceof BridgeOwnedBrowserError && error.code === 'invalid_request',
    );
  });

  it('rejects cookie/eval/selector smuggling with stable codes', async () => {
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const site = await startFakeLoginSite({
      credentials,
      hiddenFields: { csrf: 'token-1' },
    });
    const session = await startBridgeOwnedBrowser({
      policy: await policyFor(site.baseUrl),
      credentials,
    });
    try {
      for (const op of ['cookie_list', 'eval', 'state_save', 'fill_password', 'cdp']) {
        const response = await fetch(`${session.baseUrl}/${op}`);
        const body = await readJson(response);
        assert.equal(response.status, 403, op);
        assert.equal(body.error, 'session_material_forbidden', op);
      }
      const screenshot = await readJson(await fetch(`${session.baseUrl}/screenshot`));
      assert.equal(screenshot.error, 'screenshot_unsupported');

      const snap = await readJson(await fetch(`${session.baseUrl}/snapshot`));
      const smuggled = await fetch(`${session.baseUrl}/select_targets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          generation: snap.generation,
          username_index: 0,
          password_index: 1,
          submit_index: 2,
          selector: 'input[name=password]',
        }),
      });
      assert.equal(smuggled.status, 400);
      assert.equal((await readJson(smuggled)).error, 'extra_field_forbidden');

      const swapped = await fetch(`${session.baseUrl}/select_targets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          generation: snap.generation,
          username_index: 1,
          password_index: 0,
          submit_index: 2,
        }),
      });
      assert.equal((await readJson(swapped)).error, 'target_kind_mismatch');

      const deniedPath = await fetch(`${session.baseUrl}/goto`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: '/login' }),
      });
      assert.equal((await readJson(deniedPath)).error, 'not_logged_in');
      assert.ok(FORBIDDEN_AGENT_OPS.length > 5);
    } finally {
      await session.close();
      await site.close();
    }
  });

  it('fails closed on MFA pages and concurrent sessions', async () => {
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const site = await startFakeLoginSite({
      credentials,
      hiddenFields: { csrf: 'token-1' },
      challengeMode: 'mfa',
    });
    const session = await startBridgeOwnedBrowser({
      policy: await policyFor(site.baseUrl),
      credentials,
    });
    try {
      const snap = await readJson(await fetch(`${session.baseUrl}/snapshot`));
      assert.equal(snap.error, 'mfa_required');
      const policy = await policyFor(site.baseUrl);
      await assert.rejects(
        () => startBridgeOwnedBrowser({
          policy,
          credentials,
        }),
        (error) => error instanceof BridgeOwnedBrowserError &&
          error.code === 'concurrent_session_forbidden',
      );
      assert.equal(MAX_BRIDGE_OWNED_BROWSERS, 1);
    } finally {
      await session.close();
      await site.close();
    }
  });
});
