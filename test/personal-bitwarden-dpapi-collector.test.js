import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { buildPersonalBitwardenLiveScope } from '../src/personal-bitwarden-live-gate.mjs';
import {
  collectPersonalBitwardenDpapiBundle,
  PERSONAL_BITWARDEN_PURPOSE_SHA256,
  PersonalBitwardenCollectorError,
} from '../src/personal-bitwarden-dpapi-collector.mjs';

const FAKE_EMAIL = 'personal-operator@example.test';
const FAKE_PASSWORD = 'PERS-FAKE-SENTINEL-PASSWORD-001';

async function writeAllow(digest) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-personal-collector-'));
  const filePath = path.join(dir, 'personal-vault.allow.json');
  await fs.writeFile(filePath, JSON.stringify({
    schema_version: 1,
    account_email_sha256: digest,
  }), 'utf8');
  return { dir, filePath };
}

describe('personal Bitwarden DPAPI collector', () => {
  it('pins the personal purpose digest', () => {
    assert.equal(
      PERSONAL_BITWARDEN_PURPOSE_SHA256,
      createHash('sha256')
        .update('bitwarden-agent-credential-bridge-personal-dpapi-v1', 'utf8')
        .digest('hex'),
    );
  });

  it('rejects forged scopes without reading secrets', async () => {
    await assert.rejects(
      () => collectPersonalBitwardenDpapiBundle({
        personal_vault_allowed: true,
        company_vault_forbidden: true,
      }),
      (error) => error instanceof PersonalBitwardenCollectorError &&
        error.code === 'invalid_scope',
    );
  });

  it('matches allowlist digest and keeps secrets off evidence surfaces', async () => {
    const digest = createHash('sha256').update(FAKE_EMAIL, 'utf8').digest('hex');
    const { dir, filePath } = await writeAllow(digest);
    try {
      const scope = buildPersonalBitwardenLiveScope();
      const bundle = await collectPersonalBitwardenDpapiBundle(scope, {
        allowConfigPath: filePath,
        readField: async (field) => (field === 'username' ? FAKE_EMAIL : FAKE_PASSWORD),
      });
      assert.equal(bundle.account_email_digest, digest);
      assert.equal(bundle.evidence.personal_preflight_passed, true);
      assert.equal(bundle.evidence.authorization_ready, false);
      assert.equal(bundle.evidence.company_vault_forbidden, true);
      assert.equal(bundle.evidence.organization_vault_forbidden, true);
      assert.equal(bundle.evidence.helper_vault_free, true);
      assert.equal(bundle.credentials.username, FAKE_EMAIL);
      assert.equal(bundle.credentials.password, FAKE_PASSWORD);

      const surface = JSON.stringify({
        digest: bundle.account_email_digest,
        evidence: bundle.evidence,
      });
      assert.equal(surface.includes(FAKE_EMAIL), false);
      assert.equal(surface.includes(FAKE_PASSWORD), false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('fails closed on digest mismatch', async () => {
    const wrong = createHash('sha256').update('other@example.test', 'utf8').digest('hex');
    const { dir, filePath } = await writeAllow(wrong);
    try {
      await assert.rejects(
        () => collectPersonalBitwardenDpapiBundle(buildPersonalBitwardenLiveScope(), {
          allowConfigPath: filePath,
          readField: async (field) => (field === 'username' ? FAKE_EMAIL : FAKE_PASSWORD),
        }),
        (error) => error instanceof PersonalBitwardenCollectorError &&
          error.code === 'account_mismatch',
      );
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects the disposable bridge identity even when allowlisted', async () => {
    const disposable = 'frederikstadler+bridge@gmail.com';
    const digest = createHash('sha256').update(disposable, 'utf8').digest('hex');
    const { dir, filePath } = await writeAllow(digest);
    try {
      await assert.rejects(
        () => collectPersonalBitwardenDpapiBundle(buildPersonalBitwardenLiveScope(), {
          allowConfigPath: filePath,
          readField: async (field) => (
            field === 'username' ? disposable : FAKE_PASSWORD
          ),
        }),
        (error) => error instanceof PersonalBitwardenCollectorError &&
          error.code === 'disposable_identity_forbidden',
      );
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
