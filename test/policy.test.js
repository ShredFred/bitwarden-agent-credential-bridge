import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  loadPolicy,
  parseLoopbackHttpUrl,
  PolicyValidationError,
  validatePolicy,
} from '../src/policy.js';

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

function validPolicy(overrides = {}) {
  return {
    version: 1,
    service: 'fake-sample-api',
    credential_class: 'http_bearer',
    bind: 'http://127.0.0.1:0',
    upstream: 'http://127.0.0.1:0',
    method: 'GET',
    path: '/v1/resource',
    authorization: '{{credential}}',
    ...overrides,
  };
}

function validV2Policy(overrides = {}) {
  return {
    version: 2,
    service: 'fake-sample-api',
    credential_class: 'http_api_key_header',
    bind: 'http://127.0.0.1:0',
    upstream: 'http://127.0.0.1:0',
    method: 'GET',
    path: '/v1/resource',
    header_name: 'x-fake-api-key',
    header_value: '{{credential}}',
    ...overrides,
  };
}

describe('policy validation', () => {
  it('accepts the sample policy file', async () => {
    const policy = await loadPolicy(samplePolicyPath);
    assert.equal(policy.service, 'fake-sample-api');
    assert.equal(policy.credential_class, 'http_bearer');
    assert.equal(policy.bind, 'http://127.0.0.1:0');
    assert.equal(policy.upstream, 'http://127.0.0.1:0');
    assert.equal(policy.method, 'GET');
    assert.equal(policy.path, '/v1/resource');
    assert.equal(policy.authorization, '{{credential}}');
  });

  it('accepts localhost and explicit ports', () => {
    const policy = validatePolicy(
      validPolicy({
        bind: 'http://localhost:0',
        upstream: 'http://127.0.0.1:8080',
      }),
    );
    assert.equal(policy.bind, 'http://localhost:0');
    assert.equal(policy.upstream, 'http://127.0.0.1:8080');
  });

  it('accepts the strict version-2 API-key sample', async () => {
    const policy = await loadPolicy(sampleV2PolicyPath);
    assert.deepEqual(Object.keys(policy).sort(), [
      'bind',
      'credential_class',
      'header_name',
      'header_value',
      'method',
      'path',
      'service',
      'upstream',
      'version',
    ]);
    assert.equal(policy.version, 2);
    assert.equal(policy.credential_class, 'http_api_key_header');
    assert.equal(policy.header_name, 'x-fake-api-key');
    assert.equal(policy.header_value, '{{credential}}');
  });

  it('rejects uppercase and syntactically invalid API-key header names', () => {
    for (const headerName of [
      'X-Fake-Api-Key',
      'x api key',
      'x-api-key:',
      'x-api-key\u00e9',
      '',
    ]) {
      assert.throws(
        () => validatePolicy(validV2Policy({ header_name: headerName })),
        /canonical lowercase ASCII HTTP header name/,
      );
    }
  });

  it('accepts API-key header names through 128 ASCII characters and rejects longer names', () => {
    const maximumName = `x-${'a'.repeat(126)}`;
    const tooLongName = `${maximumName}a`;

    assert.equal(
      validatePolicy(validV2Policy({ header_name: maximumName })).header_name,
      maximumName,
    );
    assert.throws(
      () => validatePolicy(validV2Policy({ header_name: tooLongName })),
      /at most 128 ASCII characters/,
    );
  });

  it('rejects forbidden API-key protocol, credential, framing, and content headers', () => {
    const forbidden = [
      'authorization',
      'proxy-authorization',
      'host',
      'connection',
      'keep-alive',
      'upgrade',
      'transfer-encoding',
      'te',
      'trailer',
      'content-length',
      'cookie',
      'set-cookie',
      'content-type',
      'content-encoding',
      'proxy-connection',
      'http2-settings',
      'x-forwarded-for',
    ];
    for (const headerName of forbidden) {
      assert.throws(
        () => validatePolicy(validV2Policy({ header_name: headerName })),
        /forbidden for API-key injection/,
        headerName,
      );
    }
  });

  it('rejects literal or non-exact version-2 placeholders', () => {
    for (const headerValue of [
      'literal-value',
      '{{secret}}',
      'prefix {{credential}}',
    ]) {
      assert.throws(
        () => validatePolicy(validV2Policy({ header_value: headerValue })),
        /policy\.header_value must be exactly \{\{credential\}\}/,
      );
    }
  });

  it('rejects unknown fields in either policy version', () => {
    assert.throws(
      () => validatePolicy(validPolicy({ extra: true })),
      /unknown field\(s\): extra/,
    );
    assert.throws(
      () => validatePolicy(validV2Policy({ authorization: '{{credential}}' })),
      /unknown field\(s\): authorization/,
    );
  });

  it('requires each version to use its single credential class', () => {
    assert.throws(
      () =>
        validatePolicy(
          validPolicy({ credential_class: 'http_api_key_header' }),
        ),
      /version 1 requires credential_class "http_bearer"/,
    );
    assert.throws(
      () => validatePolicy(validV2Policy({ credential_class: 'http_bearer' })),
      /version 2 requires credential_class "http_api_key_header"/,
    );
  });

  it('rejects unsupported credential classes (fail closed)', () => {
    assert.throws(
      () => validatePolicy(validPolicy({ credential_class: 'ssh_private_key' })),
      (err) =>
        err instanceof PolicyValidationError &&
        /unsupported credential_class/.test(err.message),
    );
  });

  it('rejects literal Authorization credential values', () => {
    assert.throws(
      () =>
        validatePolicy(
          validPolicy({ authorization: 'Bearer literal-secret-value' }),
        ),
      (err) =>
        err instanceof PolicyValidationError &&
        /literal credential values are rejected/.test(err.message),
    );
  });

  it('rejects unsupported Authorization placeholders', () => {
    assert.throws(
      () => validatePolicy(validPolicy({ authorization: '{{secret}}' })),
      (err) =>
        err instanceof PolicyValidationError &&
        /unsupported placeholder rejected/.test(err.message),
    );
    assert.throws(
      () =>
        validatePolicy(
          validPolicy({ authorization: 'Bearer {{credential}}' }),
        ),
      (err) =>
        err instanceof PolicyValidationError &&
        /unsupported placeholder rejected/.test(err.message),
    );
  });

  it('rejects non-loopback bind URLs', () => {
    assert.throws(
      () => validatePolicy(validPolicy({ bind: 'http://192.168.1.10:8080' })),
      (err) =>
        err instanceof PolicyValidationError &&
        /non-loopback/.test(err.message),
    );
    assert.throws(
      () => validatePolicy(validPolicy({ bind: 'http://0.0.0.0:8080' })),
      PolicyValidationError,
    );
  });

  it('rejects non-loopback upstream URLs', () => {
    assert.throws(
      () =>
        validatePolicy(validPolicy({ upstream: 'http://example.com:443' })),
      (err) =>
        err instanceof PolicyValidationError &&
        /non-loopback/.test(err.message),
    );
  });

  it('rejects https and missing explicit ports', () => {
    assert.throws(
      () => validatePolicy(validPolicy({ bind: 'https://127.0.0.1:8443' })),
      /http scheme/,
    );
    assert.throws(
      () => validatePolicy(validPolicy({ upstream: 'http://127.0.0.1' })),
      /explicit port/,
    );
  });

  it('rejects missing path slash and non-object policies', () => {
    assert.throws(
      () => validatePolicy(validPolicy({ path: 'v1/resource' })),
      PolicyValidationError,
    );
    assert.throws(() => validatePolicy(null), PolicyValidationError);
    assert.throws(() => validatePolicy([]), PolicyValidationError);
  });
});

describe('parseLoopbackHttpUrl', () => {
  it('accepts ephemeral port 0', () => {
    const url = parseLoopbackHttpUrl('http://127.0.0.1:0', 'bind');
    assert.equal(url.port, '0');
  });

  it('rejects non-loopback hosts', () => {
    assert.throws(
      () => parseLoopbackHttpUrl('http://10.0.0.2:9', 'upstream'),
      /non-loopback/,
    );
  });
});
