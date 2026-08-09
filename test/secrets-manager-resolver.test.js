import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  buildSecretsManagerResolverGate,
  isSecretsManagerResolverGate,
  resolveSecretsManagerSecret,
  SecretsManagerResolverError,
} from '../src/secrets-manager-resolver.mjs';

const PROJECT = 'e186495e-8667-436f-9f78-b49800eba251';
const OTHER = '1d9a72dc-75aa-4bf3-a528-b49800ebbf68';

describe('secrets manager resolver', () => {
  it('resolves under a branded gate and rejects non-allowlisted projects', async () => {
    const scope = buildSecretsManagerLiveScope();
    const gate = buildSecretsManagerResolverGate(scope, {
      allowed_project_ids: [PROJECT],
    });
    assert.equal(isSecretsManagerResolverGate(gate), true);
    assert.equal(isSecretsManagerResolverGate({ ...gate }), false);

    const sentinel = 'SM-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF';
    const secret = await resolveSecretsManagerSecret(gate, async () => ({
      credential: sentinel,
    }), {
      project_id: PROJECT,
      secret_key: 'mivia_demo_bearer',
      credential_class: 'http_bearer',
    });
    assert.equal(secret.credential, sentinel);
    assert.equal(gate.authorization_ready, false);
    assert.equal(gate.helper_vault_free, true);

    await assert.rejects(
      () => resolveSecretsManagerSecret(gate, async () => ({
        credential: sentinel,
      }), {
        project_id: OTHER,
        secret_key: 'privatehq_demo_bearer',
        credential_class: 'http_bearer',
      }),
      (error) => error instanceof SecretsManagerResolverError &&
        error.code === 'project_not_allowed',
    );
  });

  it('rejects forged gates and oauth classes', async () => {
    await assert.rejects(
      () => resolveSecretsManagerSecret({ schema_version: 1 }, async () => ({
        credential: 'x'.repeat(16),
      }), {
        project_id: PROJECT,
        secret_key: 'k',
        credential_class: 'http_bearer',
      }),
      (error) => error instanceof SecretsManagerResolverError && error.code === 'invalid_gate',
    );

    const gate = buildSecretsManagerResolverGate(buildSecretsManagerLiveScope(), {
      allowed_project_ids: [PROJECT],
    });
    await assert.rejects(
      () => resolveSecretsManagerSecret(gate, async () => ({ credential: 'x'.repeat(16) }), {
        project_id: PROJECT,
        secret_key: 'k',
        credential_class: 'oauth',
      }),
      (error) => error instanceof SecretsManagerResolverError &&
        error.code === 'rejected_credential_class',
    );
  });
});
