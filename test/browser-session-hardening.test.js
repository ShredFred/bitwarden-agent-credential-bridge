import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateFakeSentinel } from '../src/constants.js';
import {
  BrowserSessionBrokerError,
  startBrowserSessionBroker,
} from '../src/browser-session-broker.mjs';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import { loadPolicy, validatePolicy, withBind, withLoginOrigin } from '../src/policy.js';

const samplePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-browser-login.json',
);

async function basePolicy(origin, overrides = {}) {
  const loaded = await loadPolicy(samplePath);
  return withBind(withLoginOrigin({
    ...loaded,
    hidden_fields: [...loaded.hidden_fields],
    allowed_paths: [...loaded.allowed_paths],
    ...overrides,
  }, origin), 'http://127.0.0.1:0');
}

describe('browser session broker hardening', () => {
  it('fails closed on MFA and CAPTCHA challenge pages', async () => {
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    for (const [mode, code] of [['mfa', 'mfa_required'], ['captcha', 'captcha_required']]) {
      const site = await startFakeLoginSite({
        credentials,
        hiddenFields: { csrf: 'token-1' },
        challengeMode: mode,
      });
      try {
        const policy = await basePolicy(site.baseUrl);
        await assert.rejects(
          () => startBrowserSessionBroker({ policy, credentials }),
          (error) => error instanceof BrowserSessionBrokerError && error.code === code,
        );
      } finally {
        await site.close();
      }
    }
  });

  it('rejects a second concurrent session writer', async () => {
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const site = await startFakeLoginSite({
      credentials,
      hiddenFields: { csrf: 'token-1' },
    });
    const first = await startBrowserSessionBroker({
      policy: await basePolicy(site.baseUrl),
      credentials,
    });
    try {
      const policy = await basePolicy(site.baseUrl);
      await assert.rejects(
        () => startBrowserSessionBroker({ policy, credentials }),
        (error) => error instanceof BrowserSessionBrokerError &&
          error.code === 'concurrent_session_forbidden',
      );
    } finally {
      await first.close();
      await site.close();
    }
  });

  it('expires idle sessions with a value-free code', async () => {
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const site = await startFakeLoginSite({
      credentials,
      hiddenFields: { csrf: 'token-1' },
    });
    const policy = validatePolicy({
      ...(await loadPolicy(samplePath)),
      login_origin: site.baseUrl,
      bind: 'http://127.0.0.1:0',
      hidden_fields: ['csrf'],
      allowed_paths: ['/home', '/api/me'],
      session_ttl_ms: 5000,
      idle_ttl_ms: 1000,
    });
    const broker = await startBrowserSessionBroker({ policy, credentials });
    try {
      await delay(1100);
      const replay = await fetch(broker.replayUrl);
      assert.equal(replay.status, 401);
      assert.deepEqual(await replay.json(), { error: 'session_expired' });
    } finally {
      await broker.close();
      await site.close();
    }
  });

  it('blocks cross-origin redirects during login', async () => {
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const site = await startFakeLoginSite({
      credentials,
      hiddenFields: { csrf: 'token-1' },
    });
    // Replace form action responses via fetch shim after a successful CSRF parse.
    const realFetch = globalThis.fetch;
    let posts = 0;
    const fetchImpl = async (input, init) => {
      const response = await realFetch(input, init);
      if ((init?.method ?? 'GET') === 'POST') {
        posts += 1;
        if (posts === 1) {
          return new Response(null, {
            status: 302,
            headers: { location: 'https://evil.example/steal' },
          });
        }
      }
      return response;
    };
    try {
      const policy = await basePolicy(site.baseUrl);
      await assert.rejects(
        () => startBrowserSessionBroker({
          policy,
          credentials,
          fetchImpl,
        }),
        (error) => error instanceof BrowserSessionBrokerError &&
          error.code === 'cross_origin_redirect',
      );
    } finally {
      await site.close();
    }
  });
});
