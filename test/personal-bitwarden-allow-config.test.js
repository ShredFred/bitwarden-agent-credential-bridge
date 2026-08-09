import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  digestPersonalAccountEmail,
  loadPersonalVaultAllowConfig,
  safeEqualHexDigest,
  PersonalBitwardenAllowConfigError,
} from '../src/personal-bitwarden-allow-config.mjs';

describe('personal Bitwarden allow config', () => {
  it('digests emails and loads an exact schema file', async () => {
    const email = 'operator-personal@example.test';
    const digest = digestPersonalAccountEmail(email);
    assert.equal(digest, createHash('sha256').update(email, 'utf8').digest('hex'));
    assert.equal(safeEqualHexDigest(digest, digest), true);
    assert.equal(safeEqualHexDigest(digest, '0'.repeat(64)), false);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-personal-allow-'));
    const filePath = path.join(dir, 'personal-vault.allow.json');
    await fs.writeFile(filePath, JSON.stringify({
      schema_version: 1,
      account_email_sha256: digest,
    }), 'utf8');

    const loaded = await loadPersonalVaultAllowConfig(filePath);
    assert.equal(loaded.schema_version, 1);
    assert.equal(loaded.account_email_sha256, digest);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('rejects absent, oversized, and malformed allow configs', async () => {
    await assert.rejects(
      () => loadPersonalVaultAllowConfig(path.join(os.tmpdir(), 'missing-personal-allow.json')),
      (error) => error instanceof PersonalBitwardenAllowConfigError &&
        error.code === 'allow_config_absent',
    );

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-personal-allow-bad-'));
    const filePath = path.join(dir, 'bad.json');
    await fs.writeFile(filePath, JSON.stringify({
      schema_version: 1,
      account_email_sha256: 'not-a-digest',
      extra: true,
    }), 'utf8');
    await assert.rejects(
      () => loadPersonalVaultAllowConfig(filePath),
      (error) => error instanceof PersonalBitwardenAllowConfigError &&
        error.code === 'allow_config_invalid',
    );
    await fs.rm(dir, { recursive: true, force: true });
  });
});
