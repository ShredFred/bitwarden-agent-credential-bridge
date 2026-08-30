import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { collectLinuxSecretEntryValues } from '../src/linux-sm-secret-entry.mjs';

describe('linux SM secret entry', () => {
  it('collects injected field values without a display', async () => {
    const form = {
      title: 'Test',
      fields: [
        { sm_key: 'phq_api_bearer', label: 'API token', secret: true },
        { sm_key: 'note', label: 'Note', secret: false },
      ],
    };
    const got = await collectLinuxSecretEntryValues({
      form,
      promptField: async (field) => {
        if (field.sm_key === 'phq_api_bearer') return '0.fake-entry-token==';
        return 'public-note';
      },
    });
    assert.equal(got.ok, true);
    assert.equal(got.values.note, 'public-note');
    assert.equal(got.values.phq_api_bearer.length >= 16, true);
    assert.equal(got.cancelled, false);
  });

  it('maps a null prompt to cancelled', async () => {
    const form = {
      title: 'Test',
      fields: [{ sm_key: 'phq_api_bearer', label: 'API token', secret: true }],
    };
    const got = await collectLinuxSecretEntryValues({
      form,
      promptField: async () => null,
    });
    assert.equal(got.ok, false);
    assert.equal(got.cancelled, true);
    assert.equal(got.code, 'cancelled');
  });
});
