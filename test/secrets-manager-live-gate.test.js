import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildSecretsManagerLiveScope,
  isSecretsManagerLiveScope,
  evaluateSecretsManagerEvidence,
  SecretsManagerLiveGateError,
} from '../src/secrets-manager-live-gate.mjs';

describe('secrets manager live gate', () => {
  it('brands an SM same-user scope with helper vault-free', () => {
    const scope = buildSecretsManagerLiveScope();
    assert.equal(isSecretsManagerLiveScope(scope), true);
    assert.equal(isSecretsManagerLiveScope({ ...scope }), false);
    assert.equal(scope.secrets_manager_allowed, true);
    assert.equal(scope.helper_vault_free, true);
    assert.equal(scope.env_inject_forbidden, true);
    assert.equal(scope.localservice_vault_forbidden, true);
    assert.equal(scope.authorization_ready, false);
  });

  it('rejects forged evidence and keeps authorization_ready false', () => {
    const scope = buildSecretsManagerLiveScope();
    assert.throws(
      () => evaluateSecretsManagerEvidence(scope, { token_present: true }),
      (error) => error instanceof SecretsManagerLiveGateError && error.code === 'invalid_evidence',
    );
    const report = evaluateSecretsManagerEvidence(scope, {
      machine_config_loaded: true,
      token_present: true,
      adapter_fixed: true,
      projects_allowlisted: true,
    });
    assert.equal(report.sm_preflight_passed, true);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.helper_vault_free, true);
  });
});
