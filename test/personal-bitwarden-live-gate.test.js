import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildPersonalBitwardenLiveScope,
  isPersonalBitwardenLiveScope,
  evaluatePersonalBitwardenEvidence,
  PersonalBitwardenLiveGateError,
} from '../src/personal-bitwarden-live-gate.mjs';

describe('personal Bitwarden live gate', () => {
  it('brands a personal-allowed scope with company/org forbidden and helper vault-free', () => {
    const scope = buildPersonalBitwardenLiveScope();
    assert.equal(isPersonalBitwardenLiveScope(scope), true);
    assert.equal(isPersonalBitwardenLiveScope({ ...scope }), false);
    assert.equal(scope.personal_vault_allowed, true);
    assert.equal(scope.company_vault_forbidden, true);
    assert.equal(scope.organization_vault_forbidden, true);
    assert.equal(scope.helper_vault_free, true);
    assert.equal(scope.authorization_ready, false);
    assert.equal(scope.mutation_authorized, false);
  });

  it('rejects forged evidence and keeps authorization_ready false on success', () => {
    const scope = buildPersonalBitwardenLiveScope();
    assert.throws(
      () => evaluatePersonalBitwardenEvidence(scope, { personal_account_digest_matched: true }),
      (error) => error instanceof PersonalBitwardenLiveGateError && error.code === 'invalid_evidence',
    );
    assert.throws(
      () => evaluatePersonalBitwardenEvidence({ ...scope }, {
        personal_account_digest_matched: true,
        organization_membership_absent: true,
        company_vault_absent: true,
        adapter_fixed: true,
      }),
      (error) => error instanceof PersonalBitwardenLiveGateError && error.code === 'invalid_scope',
    );

    const report = evaluatePersonalBitwardenEvidence(scope, {
      personal_account_digest_matched: true,
      organization_membership_absent: true,
      company_vault_absent: true,
      adapter_fixed: true,
    });
    assert.equal(report.personal_preflight_passed, true);
    assert.equal(report.authorization_ready, false);
    assert.equal(report.company_vault_forbidden, true);
    assert.equal(report.organization_vault_forbidden, true);
    assert.equal(report.helper_vault_free, true);
  });

  it('fails closed when digest match is false', () => {
    const scope = buildPersonalBitwardenLiveScope();
    const report = evaluatePersonalBitwardenEvidence(scope, {
      personal_account_digest_matched: false,
      organization_membership_absent: true,
      company_vault_absent: true,
      adapter_fixed: true,
    });
    assert.equal(report.personal_preflight_passed, false);
    assert.equal(report.authorization_ready, false);
  });
});
