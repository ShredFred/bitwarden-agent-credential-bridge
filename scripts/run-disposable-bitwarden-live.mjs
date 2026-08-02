#!/usr/bin/env node
/**
 * Operator-approved disposable/dev Bitwarden live runner (Phase 7 / 1B).
 *
 * Uses the pinned disposable account identity from the DPAPI store under an
 * explicit approval flag. Never prints username/password. authorization_ready
 * stays false. DPAPI unlock is not MFA.
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startBroker } from '../src/broker.js';
import { FAKE_API_CONSTANT_BODY } from '../src/constants.js';
import {
  collectDisposableBitwardenDpapiBundle,
  DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL_SHA256,
  DisposableBitwardenCollectorError,
} from '../src/disposable-bitwarden-dpapi-collector.mjs';
import { buildDisposableBitwardenLiveScope } from '../src/disposable-bitwarden-live-gate.mjs';
import { startFakeApi } from '../src/fake-api.js';
import { loadPolicy, withUpstream } from '../src/policy.js';

const APPROVAL_FLAG = '--i-approve-disposable-dev-bitwarden';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const samplePolicyPath = path.join(root, 'policies', 'sample-fake-service.json');

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function assertNoSecret(surface, value, secrets) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of secrets) {
    if (typeof secret !== 'string' || secret.length < 1) continue;
    if (text.includes(secret)) {
      throw new Error(`secret_leak:${surface}`);
    }
  }
}

if (!process.argv.includes(APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: APPROVAL_FLAG,
    authorization_ready: false,
    dpapi_is_not_mfa: true,
  }, 1);
} else if (process.platform !== 'win32') {
  emit({
    ok: false,
    code: 'unsupported_platform',
    authorization_ready: false,
    dpapi_is_not_mfa: true,
  }, 1);
} else {
  const scope = buildDisposableBitwardenLiveScope();
  let bundle;
  try {
    bundle = await collectDisposableBitwardenDpapiBundle(scope);
  } catch (error) {
    const code = error instanceof DisposableBitwardenCollectorError
      ? error.code
      : 'disposable_vault_unavailable';
    emit({
      ok: false,
      code,
      live_secret_resolved: false,
      authorization_ready: false,
      company_vault_forbidden: true,
      personal_vault_forbidden: true,
      dpapi_is_not_mfa: true,
      account_email_digest: DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL_SHA256,
    }, 1);
    bundle = null;
  }

  if (bundle) {
    const { credentials, evidence, account_email_digest } = bundle;
    const secrets = [credentials.username, credentials.password];
    const basePolicy = await loadPolicy(samplePolicyPath);
    const api = await startFakeApi({
      sentinel: credentials.password,
      path: basePolicy.path,
      method: basePolicy.method,
      credentialClass: 'http_bearer',
    });
    let broker;
    try {
      const logs = [];
      broker = await startBroker({
        policy: withUpstream(basePolicy, api.baseUrl),
        sentinel: credentials.password,
        log: (entry) => {
          assertNoSecret('log', entry, secrets);
          logs.push({ level: entry.level, message: entry.message });
        },
      });
      const response = await fetch(new URL(basePolicy.path, broker.baseUrl), {
        method: basePolicy.method,
      });
      const body = await response.json();
      assertNoSecret('response', body, secrets);
      assertNoSecret('logs', logs, secrets);
      const ok = response.status === 200 &&
        body.ok === FAKE_API_CONSTANT_BODY.ok &&
        evidence.disposable_preflight_passed === true;
      emit({
        ok,
        mode: 'disposable_bitwarden_dpapi',
        live_secret_resolved: true,
        broker_smoke_ok: ok,
        disposable_preflight_passed: evidence.disposable_preflight_passed,
        account_email_digest,
        authorization_ready: false,
        company_vault_forbidden: true,
        personal_vault_forbidden: true,
        organization_membership_forbidden: true,
        oauth_forbidden: true,
        mfa_interactive_forbidden: true,
        dpapi_is_not_mfa: true,
        helper_vault_free: true,
      }, ok ? 0 : 1);
    } catch {
      emit({
        ok: false,
        code: 'broker_smoke_failed',
        live_secret_resolved: true,
        authorization_ready: false,
        dpapi_is_not_mfa: true,
        account_email_digest,
      }, 1);
    } finally {
      if (broker) await broker.close().catch(() => {});
      await api.close().catch(() => {});
      credentials.password = '';
      credentials.username = '';
    }
  }
}
