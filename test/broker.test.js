import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  BrokerError,
  MAX_REQUEST_BODY_BYTES,
  MAX_UPSTREAM_RESPONSE_BODY_BYTES,
  redactSentinel,
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
const sampleV2PolicyPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-api-key-service.json',
);
const sampleV3PolicyPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-basic-service.json',
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

  it('supports a strict v2 pinned API-key header while stripping caller spoofing', async () => {
    const sample = await loadPolicy(sampleV2PolicyPath);
    assert.equal(sample.credential_class, 'http_api_key_header');
    const headerName = sample.header_name;
    const localApi = await startFakeApi({
      sentinel,
      path: sample.path,
      method: sample.method,
      credentialClass: sample.credential_class,
      headerName,
    });
    /** @type {Record<string, string> | null} */
    let seenHeaders = null;
    const localBroker = await startBroker({
      policy: withUpstream(sample, localApi.baseUrl),
      sentinel,
      fetchImpl: async (url, init) => {
        seenHeaders = Object.fromEntries(new Headers(init?.headers).entries());
        return fetch(url, init);
      },
    });

    try {
      const response = await rawRequest(localBroker.baseUrl, sample.path, [
        ['X-Fake-Api-Key', 'caller-spoof-one'],
        ['x-fake-api-key', 'caller-spoof-two'],
        ['Authorization', 'Bearer caller-value'],
        ['Proxy-Authorization', 'Basic caller-value'],
        ['Cookie', 'session=caller-value'],
        ['Connection', 'keep-alive, x-remove-me'],
        ['Keep-Alive', 'timeout=5'],
        ['TE', 'trailers'],
        ['Upgrade', 'websocket'],
        ['Content-Length', '0'],
        ['Content-Type', 'application/x-caller-value'],
        ['X-Forwarded-For', '203.0.113.10'],
        ['X-Remove-Me', 'connection-nominated'],
      ]);

      assert.equal(response.status, 200);
      assert.deepEqual(JSON.parse(response.body), FAKE_API_CONSTANT_BODY);
      assert.ok(seenHeaders);
      assert.equal(seenHeaders[headerName], sentinel);
      assert.equal(
        Object.keys(seenHeaders).filter(
          (name) => name.toLowerCase() === headerName,
        ).length,
        1,
      );
      for (const stripped of [
        'authorization',
        'proxy-authorization',
        'cookie',
        'connection',
        'keep-alive',
        'te',
        'upgrade',
        'content-length',
        'content-type',
        'x-forwarded-for',
        'x-remove-me',
      ]) {
        assert.equal(seenHeaders[stripped], undefined, stripped);
      }
    } finally {
      await localBroker.close();
      await localApi.close();
    }
  });

  it('injects exactly one HTTP Basic authorization value for version 3', async () => {
    const credentials = generatedBasicCredentials();
    const sample = await loadPolicy(sampleV3PolicyPath);
    const localApi = await startFakeApi({
      credentials,
      path: sample.path,
      method: sample.method,
      credentialClass: sample.credential_class,
    });
    /** @type {Record<string, string> | null} */
    let seenHeaders = null;
    const localBroker = await startBroker({
      policy: withUpstream(sample, localApi.baseUrl),
      credentials,
      fetchImpl: async (url, init) => {
        seenHeaders = Object.fromEntries(new Headers(init?.headers).entries());
        return fetch(url, init);
      },
    });

    try {
      const response = await rawRequest(localBroker.baseUrl, sample.path, [
        ['Authorization', 'Basic caller-one'],
        ['authorization', 'Basic caller-two'],
        ['Proxy-Authorization', 'Basic caller-proxy'],
        ['Cookie', 'caller-cookie=value'],
      ]);
      const payload = Buffer.from(
        `${credentials.username}:${credentials.password}`,
        'ascii',
      ).toString('base64');
      assert.equal(response.status, 200);
      assert.deepEqual(JSON.parse(response.body), FAKE_API_CONSTANT_BODY);
      assert.ok(seenHeaders);
      assert.equal(seenHeaders.authorization, `Basic ${payload}`);
      assert.equal(
        Object.keys(seenHeaders).filter(
          (name) => name.toLowerCase() === 'authorization',
        ).length,
        1,
      );
      assert.equal(seenHeaders['proxy-authorization'], undefined);
      assert.equal(seenHeaders.cookie, undefined);
    } finally {
      await localBroker.close();
      await localApi.close();
    }
  });

  it('revalidates v2 class, header, placeholder, and exact schema at broker start', async () => {
    const sample = await loadPolicy(sampleV2PolicyPath);
    const invalidPolicies = [
      { ...sample, header_name: 'Authorization' },
      { ...sample, header_value: 'literal-value' },
      { ...sample, credential_class: 'http_bearer' },
      { ...sample, extra: true },
    ];

    for (const invalidPolicy of invalidPolicies) {
      await assert.rejects(
        () =>
          startBroker({
            policy: /** @type {import('../src/policy.js').Policy} */ (
              invalidPolicy
            ),
            sentinel,
          }),
        (err) =>
          err instanceof BrokerError &&
          (err.code === 'invalid_policy' ||
            err.code === 'invalid_authorization_placeholder') &&
          !err.message.includes(sentinel),
      );
    }
  });

  it('requires unambiguous runtime material for every policy version', async () => {
    const v1 = await loadPolicy(samplePolicyPath);
    const v2 = await loadPolicy(sampleV2PolicyPath);
    const v3 = await loadPolicy(sampleV3PolicyPath);
    const credentials = generatedBasicCredentials();

    for (const options of [
      { policy: v3 },
      { policy: v3, sentinel },
      { policy: v3, sentinel, credentials },
      { policy: v3, credentials: { username: credentials.username } },
      { policy: v3, credentials: { ...credentials, extra: true } },
      { policy: v1, sentinel, credentials },
      { policy: v2, sentinel, credentials },
    ]) {
      await assert.rejects(
        () =>
          startBroker(
            /** @type {Parameters<typeof startBroker>[0]} */ (options),
          ),
        (err) =>
          err instanceof BrokerError &&
          ['invalid_credentials', 'ambiguous_runtime_material'].includes(
            err.code,
          ) &&
          !err.message.includes(credentials.username) &&
          !err.message.includes(credentials.password),
      );
    }
  });

  it('revalidates strict version-3 policy fields at broker start', async () => {
    const sample = await loadPolicy(sampleV3PolicyPath);
    const credentials = generatedBasicCredentials();
    for (const invalidPolicy of [
      { ...sample, username_value: '{{credential}}' },
      { ...sample, password_value: '{{username}}' },
      { ...sample, credential_class: 'http_bearer' },
      { ...sample, extra: true },
    ]) {
      await assert.rejects(
        () =>
          startBroker({
            policy: /** @type {import('../src/policy.js').Policy} */ (
              invalidPolicy
            ),
            credentials,
          }),
        (err) => err instanceof BrokerError && err.code === 'invalid_policy',
      );
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

  it('rejects query and fragment-like request targets without calling upstream', async () => {
    let upstreamCalls = 0;
    const localBroker = await startBroker({
      policy,
      sentinel,
      fetchImpl: async () => {
        upstreamCalls += 1;
        return new Response('{}');
      },
    });

    try {
      const queryResponse = await fetch(`${localBroker.url}?unconfigured=1`);
      assert.equal(queryResponse.status, 400);
      assert.deepEqual(await queryResponse.json(), {
        error: 'invalid_request_target',
      });

      const fragmentLikeResponse = await rawRequest(
        localBroker.baseUrl,
        `${policy.path}#ambiguous`,
        [],
      );
      assert.equal(fragmentLikeResponse.status, 400);
      assert.equal(upstreamCalls, 0);
    } finally {
      await localBroker.close();
    }
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

  it('returns generic 502 when an upstream body echoes the Base64 sentinel', async () => {
    const encodedSentinel = `${generateFakeSentinel()}:\u00ff?`;
    const base64Sentinel = Buffer.from(encodedSentinel, 'utf8').toString('base64');
    const variants = sensitiveVariantsForTest(encodedSentinel);
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel: encodedSentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () =>
        new Response(`echoed:${base64Sentinel}`, {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        }),
    });

    try {
      const res = await fetch(localBroker.url);
      const bodyText = await res.text();
      const headerObj = Object.fromEntries(res.headers.entries());
      assert.equal(res.status, 502);
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
      assertNoSensitiveVariants('response body', bodyText, variants);
      assertNoSensitiveVariants('response headers', headerObj, variants);
      assertNoSensitiveVariants('broker logs', localLogs, variants);
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

  it('returns generic 502 when an upstream header echoes the Base64url sentinel', async () => {
    const encodedSentinel = `${generateFakeSentinel()}:\u00ff?`;
    const base64urlSentinel = Buffer.from(encodedSentinel, 'utf8').toString(
      'base64url',
    );
    const variants = sensitiveVariantsForTest(encodedSentinel);
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel: encodedSentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () =>
        new Response('safe-body', {
          status: 200,
          headers: { 'x-debug-token': base64urlSentinel },
        }),
    });

    try {
      const res = await fetch(localBroker.url);
      const bodyText = await res.text();
      const headerObj = Object.fromEntries(res.headers.entries());
      assert.equal(res.status, 502);
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
      assert.equal(res.headers.get('x-debug-token'), null);
      assertNoSensitiveVariants('response body', bodyText, variants);
      assertNoSensitiveVariants('response headers', headerObj, variants);
      assertNoSensitiveVariants('broker logs', localLogs, variants);
    } finally {
      await localBroker.close();
    }
  });

  it('blocks a version-3 credential echoed in an upstream header name', async () => {
    const credentials = {
      username: `fake-user-${generateFakeSentinel()
        .replace(/[^a-z0-9]/gi, 'x')
        .toLowerCase()}`,
      password: `fake-pass-${generateFakeSentinel()}`,
    };
    const sample = await loadPolicy(sampleV3PolicyPath);
    const localBroker = await startBroker({
      policy: sample,
      credentials,
      fetchImpl: async () =>
        new Response('safe-body', {
          status: 200,
          headers: { [credentials.username]: 'safe-value' },
        }),
    });

    try {
      const response = await fetch(localBroker.url);
      assert.equal(response.status, 502);
      assert.deepEqual(await response.json(), { error: 'upstream_failed' });
      assert.equal(response.headers.get(credentials.username), null);
    } finally {
      await localBroker.close();
    }
  });

  it('removes the pinned API-key and connection-nominated response headers', async () => {
    const sample = await loadPolicy(sampleV2PolicyPath);
    const localBroker = await startBroker({
      policy: sample,
      sentinel,
      fetchImpl: async () =>
        new Response('safe-body', {
          status: 200,
          headers: {
            [sample.header_name]: 'non-credential-debug-value',
            connection: 'x-hop-by-hop',
            'x-hop-by-hop': 'remove-me',
            'x-safe': 'keep-me',
          },
        }),
    });

    try {
      const res = await fetch(localBroker.url);
      assert.equal(res.status, 200);
      assert.equal(await res.text(), 'safe-body');
      assert.equal(res.headers.get(sample.header_name), null);
      assert.equal(res.headers.get('x-hop-by-hop'), null);
      assert.equal(res.headers.get('x-safe'), 'keep-me');
    } finally {
      await localBroker.close();
    }
  });

  it('removes content-encoding after fetch exposes decoded response bytes', async () => {
    const localBroker = await startBroker({
      policy,
      sentinel,
      fetchImpl: async () =>
        new Response('already-decoded', {
          status: 200,
          headers: {
            'content-encoding': 'gzip',
            'content-type': 'text/plain',
          },
        }),
    });

    try {
      const response = await rawRequest(localBroker.baseUrl, policy.path, []);
      assert.equal(response.status, 200);
      assert.equal(response.body, 'already-decoded');
      assert.equal(response.headers['content-encoding'], undefined);
      assert.equal(
        response.headers['content-length'],
        String(Buffer.byteLength('already-decoded')),
      );
    } finally {
      await localBroker.close();
    }
  });

  it('rejects a declared oversized upstream response and cancels its body', async () => {
    let cancelled = false;
    const localBroker = await startBroker({
      policy,
      sentinel,
      fetchImpl: async () =>
        new Response(
          new ReadableStream({
            pull(controller) {
              controller.enqueue(Buffer.from('not-read'));
            },
            cancel() {
              cancelled = true;
            },
          }),
          {
            status: 200,
            headers: {
              'content-length': String(MAX_UPSTREAM_RESPONSE_BODY_BYTES + 1),
            },
          },
        ),
    });

    try {
      const res = await fetch(localBroker.url);
      const bodyText = await res.text();
      assert.equal(res.status, 502);
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
      assert.ok(cancelled);
      assert.ok(!bodyText.includes(sentinel));
    } finally {
      await localBroker.close();
    }
  });

  it('rejects a chunked oversized upstream response and cancels on overflow', async () => {
    let cancelled = false;
    let emitted = false;
    const localBroker = await startBroker({
      policy,
      sentinel,
      fetchImpl: async () =>
        new Response(
          new ReadableStream({
            pull(controller) {
              if (!emitted) {
                emitted = true;
                controller.enqueue(
                  Buffer.alloc(MAX_UPSTREAM_RESPONSE_BODY_BYTES, 0x61),
                );
                return;
              }
              controller.enqueue(Buffer.from('b'));
            },
            cancel() {
              cancelled = true;
            },
          }),
          { status: 200 },
        ),
    });

    try {
      const res = await fetch(localBroker.url);
      const bodyText = await res.text();
      assert.equal(res.status, 502);
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
      assert.ok(cancelled);
      assert.ok(!bodyText.includes(sentinel));
    } finally {
      await localBroker.close();
    }
  });

  it('best-effort cancels a reader after read failure and keeps that error authoritative', async () => {
    let cancelled = false;
    let released = false;
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () =>
        /** @type {Response} */ ({
          type: 'basic',
          status: 200,
          headers: new Headers(),
          body: {
            getReader() {
              return {
                async read() {
                  throw new Error('original read failure');
                },
                async cancel() {
                  cancelled = true;
                  throw new Error('secondary cancellation failure');
                },
                releaseLock() {
                  released = true;
                  throw new Error('secondary release failure');
                },
              };
            },
          },
        }),
    });

    try {
      const res = await fetch(localBroker.url);
      assert.equal(res.status, 502);
      assert.deepEqual(await res.json(), { error: 'upstream_failed' });
      assert.ok(cancelled);
      assert.ok(released);
      const errorLog = localLogs.find(
        (entry) => entry.message === 'failed to read upstream response',
      );
      assert.equal(errorLog?.meta?.error, 'original read failure');
    } finally {
      await localBroker.close();
    }
  });

  it('scans the concatenated response buffer for a sentinel split across chunks', async () => {
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const splitAt = Math.floor(sentinel.length / 2);
    const localBroker = await startBroker({
      policy,
      sentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(Buffer.from(`prefix:${sentinel.slice(0, splitAt)}`));
              controller.enqueue(Buffer.from(`${sentinel.slice(splitAt)}:suffix`));
              controller.close();
            },
          }),
          { status: 200 },
        ),
    });

    try {
      const res = await fetch(localBroker.url);
      const bodyText = await res.text();
      assert.equal(res.status, 502);
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
      assert.ok(!bodyText.includes(sentinel));
      assert.ok(!JSON.stringify(localLogs).includes(sentinel));
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

  it('redacts Base64 and Base64url sentinel variants from error logs and caller surfaces', async () => {
    const encodedSentinel = `${generateFakeSentinel()}:\u00ff?`;
    const variants = sensitiveVariantsForTest(encodedSentinel);
    const base64Sentinel = Buffer.from(encodedSentinel, 'utf8').toString('base64');
    const base64urlSentinel = Buffer.from(encodedSentinel, 'utf8').toString(
      'base64url',
    );
    const percentEncodedSentinel = encodeURIComponent(encodedSentinel);
    /** @type {import('../src/broker.js').BrokerLogEntry[]} */
    const localLogs = [];
    const localBroker = await startBroker({
      policy,
      sentinel: encodedSentinel,
      log: (entry) => localLogs.push(entry),
      fetchImpl: async () => {
        throw new Error(
          `encoded failure ${percentEncodedSentinel}, ${base64Sentinel}, then ${base64urlSentinel}`,
        );
      },
    });

    try {
      const res = await fetch(localBroker.url);
      const bodyText = await res.text();
      const headerObj = Object.fromEntries(res.headers.entries());
      assert.equal(res.status, 502);
      assert.deepEqual(JSON.parse(bodyText), { error: 'upstream_failed' });
      const errorLog = localLogs.find(
        (entry) => entry.message === 'upstream request failed',
      );
      assert.ok(errorLog);
      assert.match(String(errorLog.meta?.error ?? ''), /\[REDACTED\]/);
      assertNoSensitiveVariants('response body', bodyText, variants);
      assertNoSensitiveVariants('response headers', headerObj, variants);
      assertNoSensitiveVariants('broker logs', localLogs, variants);
    } finally {
      await localBroker.close();
    }
  });

  it('preserves redactSentinel while recursively redacting every sensitive variant', () => {
    const encodedSentinel = `${generateFakeSentinel()}:\u00ff?`;
    const variants = sensitiveVariantsForTest(encodedSentinel);
    const nested = {
      detail: [
        variants.join('|'),
        { [variants.at(-1) ?? 'variant']: { error: variants } },
      ],
    };

    const redacted = redactSentinel(nested, encodedSentinel);
    assertNoSensitiveVariants('nested redaction result', redacted, variants);
    assert.match(JSON.stringify(redacted), /\[REDACTED\]/);
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
 * Mirror the required runtime transforms only to assert caller non-disclosure.
 * @param {string} sentinel
 * @returns {string[]}
 */
function sensitiveVariantsForTest(sentinel) {
  return [
    ...new Set([
      sentinel,
      encodeURIComponent(sentinel),
      Buffer.from(sentinel, 'utf8').toString('base64'),
      Buffer.from(sentinel, 'utf8').toString('base64url'),
    ]),
  ].filter((value) => value.length > 0);
}

function generatedBasicCredentials() {
  const material = generateFakeSentinel().replace(/[^A-Za-z0-9]/g, 'x');
  return {
    username: `user-${material}`,
    password: `pass-${material}-${material}`,
  };
}

/**
 * @param {string} label
 * @param {unknown} value
 * @param {string[]} variants
 */
function assertNoSensitiveVariants(label, value, variants) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const variant of variants) {
    assert.ok(!text.includes(variant), `${label} exposed a sensitive variant`);
  }
}

/**
 * Send raw header pairs so duplicate case variants reach the broker unchanged.
 * @param {string} baseUrl
 * @param {string} requestPath
 * @param {[string, string][]} headers
 * @returns {Promise<{ status: number | undefined, body: string, headers: http.IncomingHttpHeaders }>}
 */
function rawRequest(baseUrl, requestPath, headers) {
  const url = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: url.hostname,
        port: url.port,
        path: requestPath,
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
          resolve({
            status: res.statusCode,
            body,
            headers: res.headers,
          });
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

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
