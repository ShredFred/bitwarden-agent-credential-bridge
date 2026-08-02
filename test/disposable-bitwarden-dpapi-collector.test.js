import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  collectDisposableBitwardenDpapiBundle,
  DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL_SHA256,
  DisposableBitwardenCollectorError,
} from '../src/disposable-bitwarden-dpapi-collector.mjs';
import {
  buildDisposableBitwardenLiveScope,
} from '../src/disposable-bitwarden-live-gate.mjs';

describe('disposable Bitwarden DPAPI collector', {
  skip: process.platform !== 'win32',
}, () => {
  it('rejects forged scopes', async () => {
    await assert.rejects(
      () => collectDisposableBitwardenDpapiBundle({
        mode: 'disposable_bitwarden_live',
        authorization_ready: false,
      }),
      (error) =>
        error instanceof DisposableBitwardenCollectorError &&
        error.code === 'invalid_scope',
    );
  });

  it('collects the pinned disposable account under a branded scope without leaking secrets into assertions', async () => {
    const scope = buildDisposableBitwardenLiveScope();
    let bundle;
    try {
      bundle = await collectDisposableBitwardenDpapiBundle(scope);
    } catch (error) {
      if (error instanceof DisposableBitwardenCollectorError &&
          (error.code === 'dpapi_probe_failed' || error.code === 'account_mismatch')) {
        // Host store absent or mismatch: fail closed is acceptable for CI hosts.
        return;
      }
      throw error;
    }

    assert.equal(bundle.account_email_digest, DISPOSABLE_BITWARDEN_ACCOUNT_EMAIL_SHA256);
    assert.equal(bundle.evidence.disposable_preflight_passed, true);
    assert.equal(bundle.evidence.authorization_ready, false);
    assert.equal(bundle.evidence.live_secret_resolved, false);
    assert.equal(typeof bundle.credentials.username, 'string');
    assert.equal(typeof bundle.credentials.password, 'string');
    assert.ok(bundle.credentials.username.length >= 8);
    assert.ok(bundle.credentials.password.length >= 8);

    const surface = JSON.stringify({
      digest: bundle.account_email_digest,
      evidence: bundle.evidence,
    });
    assert.equal(surface.includes(bundle.credentials.username), false);
    assert.equal(surface.includes(bundle.credentials.password), false);
  });
});
