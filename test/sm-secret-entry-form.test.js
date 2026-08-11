import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  parseSmSecretEntryForm,
  validateSmSecretEntryValues,
  extractSmSecretEntryPublicValues,
  sanitizeSmSecretEntryPublicValues,
  SmSecretEntryFormError,
} from '../src/sm-secret-entry-form.mjs';

describe('sm secret entry form', () => {
  it('accepts a multi-field agent form without secret values', () => {
    const form = parseSmSecretEntryForm({
      version: 1,
      project: 'mivia',
      title: 'KlickTipp Zugang',
      info: 'Benutzername und Passwort (kein API-Key).',
      fields: [
        {
          sm_key: 'mivia_klicktipp_user',
          label: 'Benutzername',
          kind: 'text',
          required: true,
          hint: 'KlickTipp login user',
        },
        {
          sm_key: 'mivia_klicktipp_pass',
          label: 'Passwort',
          kind: 'password',
          required: true,
          min_length: 8,
        },
      ],
    });
    assert.equal(form.project, 'mivia');
    assert.equal(form.fields.length, 2);
    assert.equal(form.fields[0].kind, 'text');
    assert.equal(form.fields[0].secret, false);
    assert.equal(form.fields[1].secret, true);
    assert.equal(form.fields[1].min_length, 8);
  });

  it('rejects invalid keys and duplicate fields', () => {
    assert.throws(
      () => parseSmSecretEntryForm({
        version: 1,
        project: 'mivia',
        title: 'x',
        info: '',
        fields: [{ sm_key: 'bad key', label: 'A', kind: 'text' }],
      }),
      (error) => error instanceof SmSecretEntryFormError && error.code === 'invalid_sm_key',
    );
    assert.throws(
      () => parseSmSecretEntryForm({
        version: 1,
        project: 'mivia',
        title: 'x',
        info: '',
        fields: [
          { sm_key: 'mivia_demo', label: 'A', kind: 'text' },
          { sm_key: 'mivia_demo', label: 'B', kind: 'password' },
        ],
      }),
      (error) => error instanceof SmSecretEntryFormError && error.code === 'duplicate_sm_key',
    );
  });

  it('validates collected values by length only', () => {
    const form = parseSmSecretEntryForm({
      version: 1,
      project: 'private-hq',
      title: 'Demo',
      info: '',
      fields: [
        { sm_key: 'phq_demo_user', label: 'User', kind: 'text', required: true },
        { sm_key: 'phq_demo_pass', label: 'Pass', kind: 'password', required: true, min_length: 4 },
      ],
    });
    assert.deepEqual(
      validateSmSecretEntryValues(form, {
        phq_demo_user: 'alice',
        phq_demo_pass: 'abcd',
      }),
      { ok: true },
    );
    assert.equal(
      validateSmSecretEntryValues(form, { phq_demo_user: 'alice' }).code,
      'missing_field',
    );
    assert.equal(
      validateSmSecretEntryValues(form, {
        phq_demo_user: 'alice',
        phq_demo_pass: 'ab',
      }).code,
      'invalid_value_length',
    );
  });

  it('returns only non-secret values; key names bind the account', () => {
    const form = parseSmSecretEntryForm({
      version: 1,
      project: 'mivia',
      title: 'API',
      info: '',
      fields: [
        { sm_key: 'mivia_acme_label', label: 'Bezeichnung', kind: 'text', secret: false },
        { sm_key: 'mivia_acme_user', label: 'User', kind: 'text' },
        { sm_key: 'mivia_acme_api_key', label: 'API Key', kind: 'password' },
      ],
    });
    assert.equal(form.fields[0].secret, false);
    assert.equal(form.fields[1].secret, false);
    assert.equal(form.fields[2].secret, true);

    const publicValues = extractSmSecretEntryPublicValues(form, {
      mivia_acme_label: 'Acme Produktion',
      mivia_acme_user: 'ops@acme.example',
      mivia_acme_api_key: 'sk-live-SHOULD-NOT-ESCAPE',
    });
    assert.deepEqual(publicValues, {
      mivia_acme_label: 'Acme Produktion',
      mivia_acme_user: 'ops@acme.example',
    });
    assert.equal(JSON.stringify(publicValues).includes('sk-live'), false);

    assert.deepEqual(
      sanitizeSmSecretEntryPublicValues(form, {
        mivia_acme_user: 'ops@acme.example',
        mivia_acme_api_key: 'sk-live-SHOULD-NOT-ESCAPE',
        forged: 'nope',
      }),
      { mivia_acme_user: 'ops@acme.example' },
    );

    assert.throws(
      () => parseSmSecretEntryForm({
        version: 1,
        project: 'mivia',
        title: 'x',
        info: '',
        fields: [{ sm_key: 'mivia_x', label: 'P', kind: 'password', secret: false }],
      }),
      (error) => error instanceof SmSecretEntryFormError && error.code === 'password_must_be_secret',
    );
  });
});
