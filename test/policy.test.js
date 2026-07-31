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
