#!/usr/bin/env node
/**
 * Operator-approved disposable/dev Bitwarden live preflight (Phase 7 / 1B).
 *
 * Does not resolve secrets or pair personal/company vaults. Without a verified
 * disposable collector it fails closed. authorization_ready stays false.
 * DPAPI unlock is not MFA.
 */
import process from 'node:process';
import {
  buildDisposableBitwardenLiveScope,
  evaluateDisposableBitwardenEvidence,
} from '../src/disposable-bitwarden-live-gate.mjs';

const APPROVAL_FLAG = '--i-approve-disposable-dev-bitwarden';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

if (!process.argv.includes(APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: APPROVAL_FLAG,
    authorization_ready: false,
    dpapi_is_not_mfa: true,
  }, 1);
} else {
  const scope = buildDisposableBitwardenLiveScope();
  // Live collectors that can prove disposable/non-org accounts are not wired
  // into this repo yet. Fail closed rather than inventing vault evidence.
  emit({
    ok: false,
    code: 'disposable_vault_unavailable',
    mode: scope.mode,
    live_secret_resolved: false,
    authorization_ready: false,
    company_vault_forbidden: true,
    personal_vault_forbidden: true,
    organization_membership_forbidden: true,
    oauth_forbidden: true,
    mfa_interactive_forbidden: true,
    dpapi_is_not_mfa: true,
    note: 'Provide a disposable Bitwarden account/item collector in a later live gate; forged evidence is rejected',
  }, 1);

  // Keep evaluate path loadable for operators debugging schema only.
  void evaluateDisposableBitwardenEvidence;
}
