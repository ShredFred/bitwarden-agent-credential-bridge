import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  FAKE_API_CONSTANT_BODY,
  generateFakeSentinel,
} from '../src/constants.js';
import { startFakeApi } from '../src/fake-api.js';

describe('fake HTTP API', () => {
  const sentinel = generateFakeSentinel();

  /** @type {Awaited<ReturnType<typeof startFakeApi>>} */
  let api;

  before(async () => {
    api = await startFakeApi({ sentinel });
  });

  after(async () => {
    await api.close();
  });

  it('requires an explicit runtime sentinel', async () => {
    await assert.rejects(
      async () =>
        startFakeApi(/** @type {any} */ ({})),
      /explicit runtime sentinel/,
    );
  });

  it('returns the constant body when the bearer sentinel is presented', async () => {
    const res = await fetch(`${api.baseUrl}/v1/resource`, {
      headers: { Authorization: `Bearer ${sentinel}` },
    });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), FAKE_API_CONSTANT_BODY);
  });

  it('rejects missing authorization', async () => {
    const res = await fetch(`${api.baseUrl}/v1/resource`);
    assert.equal(res.status, 401);
  });

  it('rejects a wrong bearer token', async () => {
    const res = await fetch(`${api.baseUrl}/v1/resource`, {
      headers: { Authorization: 'Bearer wrong-token' },
    });
    assert.equal(res.status, 401);
  });

  it('returns 404 for unknown paths', async () => {
    const res = await fetch(`${api.baseUrl}/nope`, {
      headers: { Authorization: `Bearer ${sentinel}` },
    });
    assert.equal(res.status, 404);
  });
});
