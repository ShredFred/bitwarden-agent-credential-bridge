import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { buildPersonalBitwardenLiveScope } from '../src/personal-bitwarden-live-gate.mjs';
import {
  buildPersonalBitwardenResolverGate,
  isPersonalBitwardenResolverGate,
  resolvePersonalBitwardenSecret,
  PersonalBitwardenResolverError,
} from '../src/personal-bitwarden-resolver.mjs';
import { buildDevBitwardenLiveGate } from '../src/dev-bitwarden-resolver.mjs';

function digest(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

describe('personal Bitwarden resolver', () => {
  it('resolves under a branded personal gate and rejects forged gates', async () => {
    const liveScope = buildPersonalBitwardenLiveScope();
    const gate = buildPersonalBitwardenResolverGate(liveScope);
    assert.equal(isPersonalBitwardenResolverGate(gate), true);
    assert.equal(isPersonalBitwardenResolverGate({ ...gate }), false);
    assert.equal(gate.personal_vault_allowed, true);
    assert.equal(gate.company_vault_forbidden, true);
    assert.equal(gate.organization_vault_forbidden, true);
    assert.equal(gate.helper_vault_free, true);
    assert.equal(gate.authorization_ready, false);

    const sentinel = 'PERS-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF';
    const secret = await resolvePersonalBitwardenSecret(gate, () => ({
      credential: sentinel,
    }), {
      item_ref: 'personal-item-1',
      field: 'password',
      credential_class: 'http_bearer',
    });
    assert.equal(digest(secret.credential), digest(sentinel));

    await assert.rejects(
      () => resolvePersonalBitwardenSecret({ schema_version: 1 }, () => ({
        credential: 'x'.repeat(16),
      }), {
        item_ref: 'personal-item-1',
        field: 'password',
        credential_class: 'http_bearer',
      }),
      (error) => error instanceof PersonalBitwardenResolverError && error.code === 'invalid_gate',
    );

    assert.throws(
      () => buildPersonalBitwardenResolverGate(buildDevBitwardenLiveGate()),
      (error) => error instanceof PersonalBitwardenResolverError &&
        error.code === 'invalid_live_scope',
    );
  });

  it('rejects permanently forbidden credential classes', async () => {
    const gate = buildPersonalBitwardenResolverGate(buildPersonalBitwardenLiveScope());
    await assert.rejects(
      () => resolvePersonalBitwardenSecret(gate, () => ({ credential: 'x'.repeat(16) }), {
        item_ref: 'personal-item-1',
        field: 'password',
        credential_class: 'oauth',
      }),
      (error) => error instanceof PersonalBitwardenResolverError &&
        error.code === 'rejected_credential_class',
    );
  });
});
