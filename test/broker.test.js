import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  BrokerError,
  MAX_REQUEST_BODY_BYTES,
  startBroker,
} from '../src/broker.js';
import {
  FAKE_API_CONSTANT_BODY,
  generateFakeSentinel,
} from '../src/constants.js';
import { startFakeApi } from '../src/fake-api.js';
import { loadPolicy, validatePolicy, withUpstream } from '../src/policy.js';

const samplePolicyPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-service.json',
);

describe('foreground HTTP broker', () => {
  const sentinel = generateFakeSentinel();

  /** @type {Awaited<ReturnType<typeof startFakeApi>>} */
  let api;
  /** @type {Awaited<ReturnType<typeof startBroker>>} */
  let broker;
  /** @type {import('../src/policy.js').Policy} */
  let policy;
  /** @type {import('../src/broker.js').BrokerLogEntry[]} */
  let logs;

  before(async () => {
    const sample = await loadPolicy(samplePolicyPath);
    api = await startFakeApi({
      sentinel,
      path: sample.path,
      method: sample.method,
    });
    policy = withUpstream(sample, api.baseUrl);
    logs = [];
    broker = await startBroker({
      policy,
      sentinel,
      log: (entry) => {
        logs.push(entry);
      },
    });
  });

  after(async () => {
    await broker.close();
    await api.close();
  });

  it('injects the sentinel only on the outbound request and returns the constant body', async () => {
    /** @type {string | null} */
    let seenAuth = null;

    const localApi = await startFakeApi({ sentinel });
    const localPolicy = withUpstream(
      await loadPolicy(samplePolicyPath),
      localApi.baseUrl,
    );
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];

    const localBroker = await startBroker({
      policy: localPolicy,
      sentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async (url, init) => {
        const headers = new Headers(init?.headers);
        seenAuth = headers.get('authorization');
        return fetch(url, init);
      },
    });

    try {
      const res = await fetch(localBroker.url, {
        method: 'GET',
        headers: { Authorization: 'Bearer caller-supplied-should-be-stripped' },
      });
      assert.equal(res.status, 200);
      assert.deepEqual(await res.json(), FAKE_API_CONSTANT_BODY);
      assert.equal(seenAuth, `Bearer ${sentinel}`);
      assert.equal(res.headers.get('authorization'), null);
    } finally {
      await localBroker.close();
      await localApi.close();
    }
  });

  it('rejects wrong method', async () => {
    const res = await fetch(broker.url, { method: 'POST' });
    assert.equal(res.status, 404);
    assert.ok(
      logs.some(
        (entry) =>
          entry.message.includes('method or path not allowed') &&
          entry.meta?.method === 'POST',
      ),
    );
  });

  it('rejects wrong path', async () => {
    const res = await fetch(`${broker.baseUrl}/v1/other`, { method: 'GET' });
    assert.equal(res.status, 404);
  });

  it('fails closed for unsupported credential classes at broker start', async () => {
    const badPolicy = {
      version: 1,
      service: 'fake-sample-api',
      credential_class: 'process_env',
      bind: 'http://127.0.0.1:0',
      upstream: api.baseUrl,
      method: 'GET',
      path: '/v1/resource',
      authorization: '{{credential}}',
    };

    assert.throws(() => validatePolicy(badPolicy), /unsupported credential_class/);

    await assert.rejects(
      () =>
        startBroker({
          policy: /** @type {import('../src/policy.js').Policy} */ (badPolicy),
          sentinel,
        }),
      (err) =>
        err instanceof BrokerError &&
        err.code === 'unsupported_credential_class',
    );
  });

  it('fails closed on upstream 3xx without returning Location', async () => {
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () =>
        new Response(null, {
          status: 302,
          headers: {
            Location: `http://127.0.0.1:9/leak?token=${sentinel}`,
          },
        }),
    });

    try {
      const res = await fetch(localBroker.url, { method: 'GET' });
      const bodyText = await res.text();
      const headerObj = Object.fromEntries(res.headers.entries());

      assert.equal(res.status, 502);
      assert.equal(res.headers.get('location'), null);
      assert.ok(!Object.keys(headerObj).some((k) => k.toLowerCase() === 'location'));
      assert.ok(!bodyText.includes(sentinel));
      assert.ok(!JSON.stringify(headerObj).includes(sentinel));
      assert.ok(!JSON.stringify(localLogs).includes(sentinel));
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
    } finally {
      await localBroker.close();
    }
  });

  it('returns generic 502 when upstream body echoes the sentinel', async () => {
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () =>
        new Response(JSON.stringify({ echoed: sentinel }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    });

    try {
      const res = await fetch(localBroker.url, { method: 'GET' });
      const bodyText = await res.text();
      const headerObj = Object.fromEntries(res.headers.entries());

      assert.equal(res.status, 502);
      assert.ok(!bodyText.includes(sentinel));
      assert.ok(!JSON.stringify(headerObj).includes(sentinel));
      assert.ok(!JSON.stringify(localLogs).includes(sentinel));
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
    } finally {
      await localBroker.close();
    }
  });

  it('returns generic 502 when upstream header echoes the sentinel', async () => {
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'x-debug-token': sentinel,
          },
        }),
    });

    try {
      const res = await fetch(localBroker.url, { method: 'GET' });
      const bodyText = await res.text();
      const headerObj = Object.fromEntries(res.headers.entries());

      assert.equal(res.status, 502);
      assert.equal(res.headers.get('x-debug-token'), null);
      assert.ok(!bodyText.includes(sentinel));
      assert.ok(!JSON.stringify(headerObj).includes(sentinel));
      assert.ok(!JSON.stringify(localLogs).includes(sentinel));
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
    } finally {
      await localBroker.close();
    }
  });

  it('redacts sentinel from fetch error strings before logging and returns 502', async () => {
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () => {
        throw new Error(`connect failed while using Bearer ${sentinel}`);
      },
    });

    try {
      const res = await fetch(localBroker.url, { method: 'GET' });
      const bodyText = await res.text();

      assert.equal(res.status, 502);
      assert.ok(!bodyText.includes(sentinel));
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });

      const errorLog = localLogs.find(
        (entry) => entry.message === 'upstream request failed',
      );
      assert.ok(errorLog);
      assert.ok(!JSON.stringify(errorLog).includes(sentinel));
      assert.match(String(errorLog.meta?.error ?? ''), /\[REDACTED\]/);
    } finally {
      await localBroker.close();
    }
  });

  it('returns generic 413 for oversized request bodies without buffering more', async () => {
    const postPolicy = validatePolicy({
      version: 1,
      service: 'fake-sample-api',
      credential_class: 'http_bearer',
      bind: 'http://127.0.0.1:0',
      upstream: 'http://127.0.0.1:0',
      method: 'POST',
      path: '/v1/resource',
      authorization: '{{credential}}',
    });

    let upstreamSeenBytes = 0;
    const upstream = await startCountingUpstream((bytes) => {
      upstreamSeenBytes += bytes;
    });

    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy: withUpstream(postPolicy, upstream.baseUrl),
      sentinel,
      log: (entry) => localLogs.push(entry),
    });

    const oversized = Buffer.alloc(MAX_REQUEST_BODY_BYTES + 1, 0x61);

    try {
      const res = await fetch(localBroker.url, {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: oversized,
      });
      const bodyText = await res.text();
      const headerObj = Object.fromEntries(res.headers.entries());

      assert.equal(res.status, 413);
      assert.deepEqual(JSON.parse(bodyText), { error: 'payload_too_large' });
      assert.ok(!bodyText.includes(sentinel));
      assert.ok(!JSON.stringify(headerObj).includes(sentinel));
      assert.ok(!JSON.stringify(localLogs).includes(sentinel));
      assert.equal(upstreamSeenBytes, 0);
    } finally {
      await localBroker.close();
      await upstream.close();
    }
  });
});

/**
 * Minimal POST upstream that counts received body bytes.
 * @param {(bytes: number) => void} onBytes
 * @returns {Promise<{ baseUrl: string, close: () => Promise<void> }>}
 */
function startCountingUpstream(onBytes) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      req.on('data', (chunk) => {
        onBytes(Buffer.byteLength(chunk));
      });
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: true }));
      });
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      if (address === null || typeof address === 'string') {
        reject(new Error('counting upstream failed to bind'));
        return;
      }
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        close: () =>
          new Promise((resClose, rejClose) => {
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }
            server.close((err) => (err ? rejClose(err) : resClose()));
          }),
      });
    });
  });
}
