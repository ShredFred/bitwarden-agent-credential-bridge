import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startBrokerWithFakeVault } from '../src/broker-from-vault.mjs';
import { FAKE_API_CONSTANT_BODY } from '../src/constants.js';
import { loadPolicy, withUpstream } from '../src/policy.js';

const samplePolicyPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-service.json',
);

describe('broker from fake vault', () => {
  it('starts broker with alias-resolved fake sentinel and keeps Authorization out of logs', async () => {
    const basePolicy = await loadPolicy(samplePolicyPath);
    const logs = [];
    let capturedAuth = '';
    const broker = await startBrokerWithFakeVault({
      policy: withUpstream(basePolicy, 'http://127.0.0.1:9'),
      aliasMap: { sample_api: { credential_class: 'http_bearer' } },
      alias: 'sample_api',
      fetchImpl: async (_url, init) => {
        const headers = init?.headers;
        if (headers instanceof Headers) {
          capturedAuth = headers.get('authorization') ?? '';
        } else if (headers && typeof headers === 'object') {
          capturedAuth = String(headers.authorization ?? headers.Authorization ?? '');
        }
        return new Response(JSON.stringify(FAKE_API_CONSTANT_BODY), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
      log: (entry) => logs.push(entry),
    });

    try {
      const response = await fetch(new URL(basePolicy.path, broker.baseUrl), {
        method: basePolicy.method,
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), FAKE_API_CONSTANT_BODY);
      assert.match(capturedAuth, /^Bearer\s.+/);
      const token = capturedAuth.slice('Bearer '.length);
      assert.ok(token.length >= 16);
      const logText = JSON.stringify(logs);
      assert.equal(logText.includes(token), false);
      assert.equal(logText.includes(Buffer.from(token, 'utf8').toString('base64')), false);
    } finally {
      await broker.close();
    }
  });
});
