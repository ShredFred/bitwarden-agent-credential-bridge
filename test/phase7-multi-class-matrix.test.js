import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startBroker } from '../src/broker.js';
import { startBrowserSessionBroker } from '../src/browser-session-broker.mjs';
import { generateFakeSentinel } from '../src/constants.js';
import { startFakeApi } from '../src/fake-api.js';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import {
  loadPolicy,
  withBind,
  withLoginOrigin,
  withUpstream,
} from '../src/policy.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'policies');

describe('phase7 multi-class concurrent matrix', () => {
  it('runs bearer, header key, basic, query key, and browser sessions without cross-contamination', async () => {
    const bearerSentinel = generateFakeSentinel();
    const headerSentinel = generateFakeSentinel();
    const querySentinel = generateFakeSentinel();
    const basicCreds = {
      username: 'user_matrix01',
      password: generateFakeSentinel(),
    };
    const browserCreds = {
      username: 'user_browser1',
      password: generateFakeSentinel(),
    };

    const bearerPolicy = await loadPolicy(path.join(root, 'sample-fake-service.json'));
    const headerPolicy = await loadPolicy(path.join(root, 'sample-fake-api-key-service.json'));
    const basicPolicy = await loadPolicy(path.join(root, 'sample-fake-basic-service.json'));
    const queryPolicy = await loadPolicy(path.join(root, 'sample-fake-api-key-query-service.json'));
    const browserPolicy = await loadPolicy(path.join(root, 'sample-fake-browser-login.json'));

    const bearerApi = await startFakeApi({
      sentinel: bearerSentinel,
      path: bearerPolicy.path,
      method: bearerPolicy.method,
      credentialClass: 'http_bearer',
    });
    const headerApi = await startFakeApi({
      sentinel: headerSentinel,
      path: headerPolicy.path,
      method: headerPolicy.method,
      credentialClass: 'http_api_key_header',
      headerName: headerPolicy.header_name,
    });
    const basicApi = await startFakeApi({
      credentials: basicCreds,
      path: basicPolicy.path,
      method: basicPolicy.method,
      credentialClass: 'http_basic',
    });
    const queryApi = await startFakeApi({
      sentinel: querySentinel,
      path: queryPolicy.path,
      method: queryPolicy.method,
      credentialClass: 'http_api_key_query',
      queryName: queryPolicy.query_name,
    });
    const loginSite = await startFakeLoginSite({
      credentials: browserCreds,
      hiddenFields: { csrf: 'token-matrix' },
    });

    const closers = [];
    try {
      const bearerBroker = await startBroker({
        policy: withUpstream(bearerPolicy, bearerApi.baseUrl),
        sentinel: bearerSentinel,
      });
      closers.push(bearerBroker);
      const headerBroker = await startBroker({
        policy: withUpstream(headerPolicy, headerApi.baseUrl),
        sentinel: headerSentinel,
      });
      closers.push(headerBroker);
      const basicBroker = await startBroker({
        policy: withUpstream(basicPolicy, basicApi.baseUrl),
        credentials: basicCreds,
      });
      closers.push(basicBroker);
      const queryBroker = await startBroker({
        policy: withUpstream(queryPolicy, queryApi.baseUrl),
        sentinel: querySentinel,
      });
      closers.push(queryBroker);
      const browserBroker = await startBrowserSessionBroker({
        policy: withBind(
          withLoginOrigin(browserPolicy, loginSite.baseUrl),
          'http://127.0.0.1:0',
        ),
        credentials: browserCreds,
      });
      closers.push(browserBroker);

      const [bearerRes, headerRes, basicRes, queryRes, browserRes] = await Promise.all([
        fetch(`${bearerBroker.baseUrl}${bearerPolicy.path}`),
        fetch(`${headerBroker.baseUrl}${headerPolicy.path}`),
        fetch(`${basicBroker.baseUrl}${basicPolicy.path}`),
        fetch(`${queryBroker.baseUrl}${queryPolicy.path}`),
        fetch(browserBroker.replayUrl),
      ]);

      assert.equal(bearerRes.status, 200);
      assert.equal(headerRes.status, 200);
      assert.equal(basicRes.status, 200);
      assert.equal(queryRes.status, 200);
      assert.equal(browserRes.status, 200);

      const bodies = await Promise.all([
        bearerRes.text(),
        headerRes.text(),
        basicRes.text(),
        queryRes.text(),
        browserRes.text(),
      ]);
      for (const secret of [
        bearerSentinel,
        headerSentinel,
        querySentinel,
        basicCreds.password,
        browserCreds.password,
      ]) {
        for (const body of bodies) {
          assert.equal(body.includes(secret), false);
        }
      }

      // Cross-wiring: browser class cannot start through HTTP broker.
      await assert.rejects(
        () => startBroker({
          policy: browserPolicy,
          credentials: browserCreds,
        }),
        (error) => error && error.code === 'wrong_broker',
      );
    } finally {
      for (const item of closers.reverse()) {
        await item.close().catch(() => {});
      }
      await loginSite.close().catch(() => {});
      await queryApi.close().catch(() => {});
      await basicApi.close().catch(() => {});
      await headerApi.close().catch(() => {});
      await bearerApi.close().catch(() => {});
    }
  });
});
