import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BrokerError, startBroker } from '../src/broker.js';
import {
  REJECTED_CREDENTIAL_CLASSES,
  generateFakeSentinel,
} from '../src/constants.js';
import {
  buildDisposableBitwardenLiveScope,
  evaluateDisposableBitwardenEvidence,
  DisposableBitwardenLiveGateError,
} from '../src/disposable-bitwarden-live-gate.mjs';
import { startFakeApi } from '../src/fake-api.js';
import {
  PolicyValidationError,
  loadPolicy,
  validatePolicy,
  withUpstream,
} from '../src/policy.js';

const sampleQueryPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-api-key-query-service.json',
);

describe('phase7 http_api_key_query policy', () => {
  it('loads the sample query policy and rejects bad query names', async () => {
    const policy = await loadPolicy(sampleQueryPath);
    assert.equal(policy.version, 6);
    assert.equal(policy.credential_class, 'http_api_key_query');
    assert.equal(policy.query_name, 'api_key');
    assert.equal(policy.query_value, '{{credential}}');

    assert.throws(
      () => validatePolicy({ ...policy, query_name: 'Api_Key' }),
      PolicyValidationError,
    );
    assert.throws(
      () => validatePolicy({ ...policy, query_value: 'literal' }),
      PolicyValidationError,
    );
    assert.throws(
      () => validatePolicy({ ...policy, path: '/v1/resource?x=1' }),
      PolicyValidationError,
    );
  });

  it('rejects named unsupported HQ auth classes with stable messaging', () => {
    for (const name of REJECTED_CREDENTIAL_CLASSES) {
      assert.throws(
        () => validatePolicy({
          version: 1,
          service: 'x',
          credential_class: name,
          bind: 'http://127.0.0.1:0',
          upstream: 'http://127.0.0.1:9',
          method: 'GET',
          path: '/v1/resource',
          authorization: '{{credential}}',
        }),
        (error) =>
          error instanceof PolicyValidationError &&
          error.message.includes('rejected credential_class'),
      );
    }
  });
});

describe('phase7 query broker injection', () => {
  it('appends exactly one outbound query param and keeps agent targets query-free', async () => {
    const sentinel = generateFakeSentinel();
    const sample = await loadPolicy(sampleQueryPath);
    const api = await startFakeApi({
      sentinel,
      path: sample.path,
      method: sample.method,
      credentialClass: 'http_api_key_query',
      queryName: sample.query_name,
    });
    const logs = [];
    const broker = await startBroker({
      policy: withUpstream(sample, api.baseUrl),
      sentinel,
      log: (entry) => logs.push(entry),
    });
    try {
      const ok = await fetch(`${broker.baseUrl}${sample.path}`);
      assert.equal(ok.status, 200);
      assert.deepEqual(await ok.json(), {
        ok: true,
        service: 'fake-sample-api',
        message: 'constant-response-from-fake-sample-api',
      });

      const denied = await fetch(`${broker.baseUrl}${sample.path}?api_key=spoof`);
      assert.equal(denied.status, 400);
      assert.deepEqual(await denied.json(), { error: 'invalid_request_target' });

      const serialized = JSON.stringify(logs);
      assert.equal(serialized.includes(sentinel), false);
      assert.equal(serialized.includes(`${sample.query_name}=`), false);
      assert.equal(serialized.includes('?'), false);
    } finally {
      await broker.close();
      await api.close();
    }
  });

  it('rejects non-printable or short query sentinels', async () => {
    const sample = await loadPolicy(sampleQueryPath);
    await assert.rejects(
      () => startBroker({
        policy: sample,
        sentinel: 'short',
      }),
      (error) => error instanceof BrokerError && error.code === 'invalid_sentinel',
    );
  });

  it('rejects query class on the wrong broker shape via rejected oauth class', async () => {
    await assert.rejects(
      () => startBroker({
        policy: {
          version: 1,
          service: 'x',
          credential_class: 'oauth',
          bind: 'http://127.0.0.1:0',
          upstream: 'http://127.0.0.1:9',
          method: 'GET',
          path: '/v1/resource',
          authorization: '{{credential}}',
        },
        sentinel: generateFakeSentinel(),
      }),
      (error) =>
        error instanceof BrokerError && error.code === 'rejected_credential_class',
    );
  });
});

describe('phase7 disposable Bitwarden live scope', () => {
  it('accepts only branded scopes and never authorizes', () => {
    const scope = buildDisposableBitwardenLiveScope();
    assert.equal(scope.authorization_ready, false);
    assert.equal(scope.dpapi_is_not_mfa, true);

    assert.throws(
      () => evaluateDisposableBitwardenEvidence({ ...scope }, {
        disposable_account_verified: true,
        organization_membership_absent: true,
        item_personal_only: true,
        adapter_fixed: true,
      }),
      DisposableBitwardenLiveGateError,
    );

    const report = evaluateDisposableBitwardenEvidence(scope, {
      disposable_account_verified: true,
      organization_membership_absent: true,
      item_personal_only: true,
      adapter_fixed: true,
    });
    assert.equal(report.disposable_preflight_passed, true);
    assert.equal(report.live_secret_resolved, false);
    assert.equal(report.authorization_ready, false);
  });
});
