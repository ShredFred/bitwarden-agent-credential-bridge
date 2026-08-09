import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  fetchSecretsManagerSecretValue,
  SecretsManagerBwsAdapterError,
} from '../src/secrets-manager-bws-adapter.mjs';

const PROJECT = 'e186495e-8667-436f-9f78-b49800eba251';
const SECRET_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

describe('secrets manager bws adapter', () => {
  it('lists then gets a secret through an injected runner without leaking the token into assertions', async () => {
    const token = '0.deadbeef-token-value-not-for-logs==';
    const calls = [];
    const value = await fetchSecretsManagerSecretValue({
      accessToken: token,
      projectId: PROJECT,
      secretKey: 'mivia_demo_bearer',
      runCommand: async (_exe, args) => {
        calls.push(args);
        if (args[0] === 'secret' && args[1] === 'list') {
          return JSON.stringify([
            { id: SECRET_ID, key: 'mivia_demo_bearer', projectId: PROJECT },
            { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', key: 'other', projectId: PROJECT },
          ]);
        }
        if (args[0] === 'secret' && args[1] === 'get') {
          return JSON.stringify({
            id: SECRET_ID,
            key: 'mivia_demo_bearer',
            value: 'SM-FAKE-SENTINEL-VALUE-001',
          });
        }
        throw new Error('unexpected');
      },
    });
    assert.equal(value, 'SM-FAKE-SENTINEL-VALUE-001');
    assert.equal(calls.length, 2);
    assert.ok(calls[0].includes('--access-token'));
    assert.ok(calls[0].includes(token));
    const surface = JSON.stringify({ calls: calls.map((a) => a.filter((x) => x !== token)) });
    assert.equal(surface.includes(token), false);
    assert.equal(surface.includes(value), false);
  });

  it('fails closed when the secret key is missing', async () => {
    await assert.rejects(
      () => fetchSecretsManagerSecretValue({
        accessToken: '0.deadbeef-token-value-not-for-logs==',
        projectId: PROJECT,
        secretKey: 'missing_key',
        runCommand: async () => JSON.stringify([
          { id: SECRET_ID, key: 'other', projectId: PROJECT },
        ]),
      }),
      (error) => error instanceof SecretsManagerBwsAdapterError &&
        error.code === 'secret_not_found',
    );
  });
});
