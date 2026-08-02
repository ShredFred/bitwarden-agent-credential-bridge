import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  buildDevBitwardenLiveGate,
  isDevBitwardenLiveGate,
  resolveDevBitwardenSecret,
  DevBitwardenResolverError,
} from '../src/dev-bitwarden-resolver.mjs';

function digest(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

describe('dev Bitwarden resolver', () => {
  it('resolves through an injected adapter under a branded live gate', async () => {
    const gate = buildDevBitwardenLiveGate();
    assert.equal(isDevBitwardenLiveGate(gate), true);
    assert.equal(isDevBitwardenLiveGate({ ...gate }), false);
    const sentinel = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG';
    const secret = await resolveDevBitwardenSecret(gate, () => ({
      credential: sentinel,
    }), {
      item_ref: 'dev-item-1',
      field: 'password',
      credential_class: 'http_bearer',
    });
    assert.equal(secret.credential.length, sentinel.length);
    assert.equal(digest(secret.credential), digest(sentinel));
    assert.equal(gate.helper_vault_free, true);
    assert.equal(gate.personal_vault_forbidden, true);
  });

  it('fails closed on forged gates and malformed adapter output', async () => {
    await assert.rejects(
      () => resolveDevBitwardenSecret({ schema_version: 1 }, () => ({ credential: 'x'.repeat(16) }), {
        item_ref: 'dev-item-1',
        field: 'password',
        credential_class: 'http_bearer',
      }),
      (error) => error instanceof DevBitwardenResolverError && error.code === 'invalid_gate',
    );
    const gate = buildDevBitwardenLiveGate();
    await assert.rejects(
      () => resolveDevBitwardenSecret(gate, () => ({ credential: 'short' }), {
        item_ref: 'dev-item-1',
        field: 'password',
        credential_class: 'http_bearer',
      }),
      (error) => error instanceof DevBitwardenResolverError && error.code === 'invalid_secret',
    );
  });
});
