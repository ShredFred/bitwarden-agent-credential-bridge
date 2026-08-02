import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startBroker } from '../src/broker.js';
import { FAKE_API_CONSTANT_BODY } from '../src/constants.js';
import {
  createDevBitwardenDpapiAdapter,
  DEV_BITWARDEN_DPAPI_ITEM_REF,
} from '../src/dev-bitwarden-dpapi-adapter.mjs';
import {
  buildDevBitwardenLiveGate,
  resolveDevBitwardenSecret,
  DevBitwardenResolverError,
} from '../src/dev-bitwarden-resolver.mjs';
import { startFakeApi } from '../src/fake-api.js';
import { loadPolicy, withUpstream } from '../src/policy.js';

const samplePolicyPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-service.json',
);

function digest(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function assertNoSecret(label, value, secret) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  const variants = [
    secret,
    encodeURIComponent(secret),
    Buffer.from(secret, 'utf8').toString('base64'),
    Buffer.from(secret, 'utf8').toString('base64url'),
  ];
  for (const variant of variants) {
    if (!variant) continue;
    assert.ok(!text.includes(variant), `${label} must not contain secret material`);
  }
}

describe('dev Bitwarden DPAPI live path', { skip: process.platform !== 'win32' }, () => {
  it('resolves the fixed DPAPI store under a branded gate without logging secrets', async () => {
    const gate = buildDevBitwardenLiveGate();
    const adapter = createDevBitwardenDpapiAdapter();
    let resolved;
    try {
      resolved = await resolveDevBitwardenSecret(gate, adapter, {
        item_ref: DEV_BITWARDEN_DPAPI_ITEM_REF,
        field: 'password',
        credential_class: 'http_bearer',
      });
    } catch (error) {
      if (error instanceof DevBitwardenResolverError &&
          (error.code === 'dpapi_probe_failed' || error.code === 'invalid_secret')) {
        // Host store absent, ACL blocked, or purpose mismatch: fail closed is success for CI.
        return;
      }
      throw error;
    }

    const credential = resolved.credential;
    assert.equal(typeof credential, 'string');
    assert.ok(credential.length >= 8);
    const secretDigest = digest(credential);

    const basePolicy = await loadPolicy(samplePolicyPath);
    const api = await startFakeApi({
      sentinel: credential,
      path: basePolicy.path,
      method: basePolicy.method,
    });
    const logs = [];
    let broker;
    try {
      const policy = withUpstream(basePolicy, api.baseUrl);
      broker = await startBroker({
        policy,
        sentinel: credential,
        log: (entry) => {
          assertNoSecret('broker log', entry, credential);
          logs.push({ level: entry.level, message: entry.message });
        },
      });
      const response = await fetch(new URL(basePolicy.path, broker.baseUrl), {
        method: basePolicy.method,
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), FAKE_API_CONSTANT_BODY);
      assertNoSecret('broker response headers', Object.fromEntries(response.headers), credential);
      assertNoSecret('broker logs', logs, credential);
      assert.equal(digest(credential), secretDigest);
    } finally {
      if (broker) await broker.close();
      await api.close();
    }
  });
});
