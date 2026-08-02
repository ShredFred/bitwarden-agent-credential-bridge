import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startBroker } from '../src/broker.js';
import { loadPolicy, validatePolicy, withLoginOrigin } from '../src/policy.js';
import { generateFakeSentinel } from '../src/constants.js';

const samplePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-browser-login.json',
);

function samplePolicy(overrides = {}) {
  return {
    version: 5,
    service: 'fake-browser-login',
    credential_class: 'browser_form_login',
    bind: 'http://127.0.0.1:0',
    login_origin: 'http://127.0.0.1:0',
    login_path: '/login',
    form_action: '/login',
    username_field: 'username',
    password_field: 'password',
    hidden_fields: ['csrf'],
    success_path: '/home',
    allowed_paths: ['/home', '/api/me'],
    replay_method: 'GET',
    replay_path: '/api/me',
    username_value: '{{username}}',
    password_value: '{{password}}',
    max_redirect_hops: 3,
    session_ttl_ms: 60000,
    idle_ttl_ms: 30000,
    ...overrides,
  };
}

describe('browser_form_login policy v5', () => {
  it('loads the sample policy and rejects wildcards / non-loopback / wrong broker', async () => {
    const policy = await loadPolicy(samplePath);
    assert.equal(policy.version, 5);
    assert.equal(policy.credential_class, 'browser_form_login');
    assert.deepEqual(policy.hidden_fields, ['csrf']);

    assert.throws(() => validatePolicy(samplePolicy({ allowed_paths: ['/home/*'] })), /wildcard|path/i);
    assert.throws(
      () => validatePolicy(samplePolicy({ login_origin: 'http://example.com:443' })),
      /loopback/i,
    );
    assert.throws(
      () => validatePolicy(samplePolicy({ hidden_fields: ['csrf*'] })),
      /field/i,
    );
    assert.throws(
      () => validatePolicy({
        version: 4,
        service: 'x',
        credential_class: 'browser_form_login',
        bind: 'http://127.0.0.1:0',
        gateway: 'http://127.0.0.1:9',
        target_host: 'example.com',
        target_port: 443,
        method: 'GET',
        path: '/v1',
        agent_token: '{{credential}}',
      }),
      /onecli_proxy|credential_class/,
    );

    await assert.rejects(
      () => startBroker({
        policy,
        credentials: { username: 'user_abcdefgh', password: generateFakeSentinel() },
      }),
      (error) => error?.code === 'wrong_broker',
    );
  });

  it('preserves version-4 onecli_proxy policies', async () => {
    const text = await readFile(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'policies', 'sample-onecli-proxy.json'),
      'utf8',
    ).catch(() => null);
    if (text === null) return;
    const raw = JSON.parse(text);
    const policy = validatePolicy(raw);
    assert.equal(policy.version, 4);
    assert.equal(policy.credential_class, 'onecli_proxy');
  });

  it('rebinds login_origin through withLoginOrigin', () => {
    const policy = withLoginOrigin(validatePolicy(samplePolicy()), 'http://127.0.0.1:3456');
    assert.equal(policy.login_origin, 'http://127.0.0.1:3456');
  });
});
