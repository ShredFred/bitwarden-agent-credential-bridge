import assert from 'node:assert/strict';
import http from 'node:http';
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

  it('validates exactly one configured API-key header without echoing it', async () => {
    const apiKeyApi = await startFakeApi({
      sentinel,
      credentialClass: 'http_api_key_header',
      headerName: 'x-fake-api-key',
    });

    try {
      const res = await fetch(`${apiKeyApi.baseUrl}/v1/resource`, {
        headers: { 'x-fake-api-key': sentinel },
      });
      const body = await res.text();
      assert.equal(res.status, 200);
      assert.deepEqual(JSON.parse(body), FAKE_API_CONSTANT_BODY);
      assert.ok(!body.includes(sentinel));
      assert.ok(
        !JSON.stringify(Object.fromEntries(res.headers.entries())).includes(
          sentinel,
        ),
      );
    } finally {
      await apiKeyApi.close();
    }
  });

  it('rejects duplicate case-varied API-key headers', async () => {
    const apiKeyApi = await startFakeApi({
      sentinel,
      credentialClass: 'http_api_key_header',
      headerName: 'x-fake-api-key',
    });

    try {
      const result = await rawGet(apiKeyApi.baseUrl, [
        ['X-Fake-Api-Key', sentinel],
        ['x-fake-api-key', sentinel],
      ]);
      assert.equal(result.status, 401);
      assert.ok(!result.body.includes(sentinel));
    } finally {
      await apiKeyApi.close();
    }
  });

  it('validates exactly one raw HTTP Basic authorization header', async () => {
    const credentials = generatedBasicCredentials();
    const basicApi = await startFakeApi({
      credentialClass: 'http_basic',
      credentials,
    });
    const expected = `Basic ${Buffer.from(
      `${credentials.username}:${credentials.password}`,
      'ascii',
    ).toString('base64')}`;

    try {
      const accepted = await rawGet(basicApi.baseUrl, [
        ['Authorization', expected],
      ]);
      assert.equal(accepted.status, 200);
      assert.deepEqual(JSON.parse(accepted.body), FAKE_API_CONSTANT_BODY);
      assert.ok(!accepted.body.includes(credentials.username));
      assert.ok(!accepted.body.includes(credentials.password));

      for (const headers of [
        [],
        [['Authorization', 'Basic wrong-fake-value']],
        [
          ['Authorization', expected],
          ['authorization', expected],
        ],
      ]) {
        const rejected = await rawGet(
          basicApi.baseUrl,
          /** @type {[string, string][]} */ (headers),
        );
        assert.equal(rejected.status, 401);
        assert.ok(!rejected.body.includes(credentials.username));
        assert.ok(!rejected.body.includes(credentials.password));
      }
    } finally {
      await basicApi.close();
    }
  });

  it('rejects invalid or ambiguous HTTP Basic runtime bundles', async () => {
    const credentials = generatedBasicCredentials();
    for (const options of [
      { credentialClass: 'http_basic' },
      { credentialClass: 'http_basic', sentinel },
      { credentialClass: 'http_basic', sentinel, credentials },
      {
        credentialClass: 'http_basic',
        credentials: { ...credentials, extra: true },
      },
      {
        credentialClass: 'http_basic',
        credentials: { ...credentials, username: `${credentials.username}:x` },
      },
    ]) {
      await assert.rejects(
        () =>
          startFakeApi(
            /** @type {Parameters<typeof startFakeApi>[0]} */ (options),
          ),
      );
    }
  });
});

function generatedBasicCredentials() {
  const material = generateFakeSentinel().replace(/[^A-Za-z0-9]/g, 'x');
  return {
    username: `user-${material}`,
    password: `pass-${material}:${material}`,
  };
}

/**
 * @param {string} baseUrl
 * @param {[string, string][]} headers
 */
function rawGet(baseUrl, headers) {
  const url = new URL('/v1/resource', baseUrl);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'GET',
        headers: [['Host', url.host], ...headers].flat(),
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          resolve({ status: res.statusCode, body });
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}
