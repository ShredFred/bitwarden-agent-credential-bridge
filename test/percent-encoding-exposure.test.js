import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { it } from 'node:test';
import { loadPolicy, withBind } from '../src/policy.js';
import { redactSentinel, startBroker } from '../src/broker.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const sentinel = 'FAKE-MixedCase-Token/~?=012345';
const lowerHex = (text) => text.replace(/%[0-9A-F]{2}/g, (part) => part.toLowerCase());

it('redacts lowercase percent escapes without changing literal credential letters', () => {
  const encoded = lowerHex(encodeURIComponent(sentinel));
  const redacted = redactSentinel({ [encoded]: ['prefix ' + encoded] }, sentinel);
  assert.equal(JSON.stringify(redacted).includes(encoded), false);
});

for (const policyFile of [
  'sample-fake-service.json',
  'sample-fake-api-key-service.json',
  'sample-fake-api-key-query-service.json',
]) {
  for (const surface of ['body', 'header', 'error']) {
    it(`blocks lowercase percent escapes in ${surface} for ${policyFile}`, async () => {
      const policy = withBind(await loadPolicy(path.join(root, 'policies', policyFile)), 'http://127.0.0.1:0');
      const encoded = lowerHex(encodeURIComponent(sentinel));
      const logs = [];
      const broker = await startBroker({
        policy, sentinel, log: (entry) => logs.push(entry),
        fetchImpl: async () => {
          if (surface === 'error') throw new Error(encoded);
          return new Response(surface === 'body' ? encoded : 'safe', {
            headers: surface === 'header' ? { 'x-echo': encoded } : {},
          });
        },
      });
      try {
        const response = await fetch(broker.url);
        const body = await response.text();
        assert.equal(response.status, 502);
        const readable = JSON.stringify({ body, headers: [...response.headers], logs });
        assert.equal(readable.includes(encoded), false);
        assert.equal(readable.includes(sentinel), false);
      } finally {
        await broker.close();
      }
    });
  }
}

it('blocks form-encoded query values with lowercase escapes and literal mixed-case text', async () => {
  const policy = withBind(await loadPolicy(path.join(root, 'policies', 'sample-fake-api-key-query-service.json')), 'http://127.0.0.1:0');
  const value = 'FAKE-MixedCase with/~012345';
  const encoded = lowerHex(new URLSearchParams({ key: value }).toString().slice(4));
  const broker = await startBroker({ policy, sentinel: value, fetchImpl: async () => new Response(encoded) });
  try {
    const response = await fetch(broker.url);
    assert.equal(response.status, 502);
    assert.equal((await response.text()).includes(encoded), false);
  } finally {
    await broker.close();
  }
});
