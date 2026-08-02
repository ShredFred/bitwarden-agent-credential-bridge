import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  resolveFakeVaultSecrets,
  selectFakeVaultSecret,
  FakeVaultResolverError,
} from '../src/fake-vault-resolver.mjs';

describe('fake vault resolver', () => {
  it('resolves alias maps into in-memory fake secrets without network', () => {
    const secrets = resolveFakeVaultSecrets({
      sample_api: { credential_class: 'http_bearer' },
      sample_basic: { credential_class: 'http_basic' },
    });
    const bearer = selectFakeVaultSecret(secrets, 'sample_api');
    assert.equal(bearer.credential_class, 'http_bearer');
    assert.equal(typeof bearer.credential, 'string');
    assert.ok(bearer.credential.length >= 16);
    const basic = selectFakeVaultSecret(secrets, 'sample_basic');
    assert.equal(basic.username, 'user_sample_basic');
    assert.equal(typeof basic.password, 'string');
  });

  it('rejects unknown aliases and unsupported classes', () => {
    assert.throws(
      () => resolveFakeVaultSecrets({ BadAlias: { credential_class: 'http_bearer' } }),
      (error) => error instanceof FakeVaultResolverError,
    );
    const secrets = resolveFakeVaultSecrets({ ok: { credential_class: 'http_bearer' } });
    assert.throws(
      () => selectFakeVaultSecret(secrets, 'missing'),
      (error) => error instanceof FakeVaultResolverError && error.code === 'unknown_alias',
    );
  });
});
