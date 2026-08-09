import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SM_MACHINE_TOKEN_PURPOSE_SHA256,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import { createHash } from 'node:crypto';

describe('secrets manager token collector', () => {
  it('pins the SM machine token purpose digest', () => {
    assert.equal(
      SM_MACHINE_TOKEN_PURPOSE_SHA256,
      createHash('sha256')
        .update('bitwarden-agent-credential-bridge-sm-machine-token-v1', 'utf8')
        .digest('hex'),
    );
  });

  it('rejects forged scopes', async () => {
    await assert.rejects(
      () => collectSecretsManagerMachineBundle({ secrets_manager_allowed: true }),
      (error) => error instanceof SecretsManagerTokenCollectorError &&
        error.code === 'invalid_scope',
    );
  });

  it('collects allowlist + token via injected reader without putting token on evidence', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-collector-'));
    const filePath = path.join(dir, 'sm-machine.allow.json');
    await fs.writeFile(filePath, JSON.stringify({
      schema_version: 1,
      machine_id: 'desktop-home',
      allowed_project_ids: [
        'e186495e-8667-436f-9f78-b49800eba251',
        '1d9a72dc-75aa-4bf3-a528-b49800ebbf68',
      ],
    }), 'utf8');
    try {
      const token = '0.injected-access-token-value==';
      const bundle = await collectSecretsManagerMachineBundle(
        buildSecretsManagerLiveScope(),
        {
          allowConfigPath: filePath,
          readToken: async () => token,
        },
      );
      assert.equal(bundle.machine_id, 'desktop-home');
      assert.equal(bundle.accessToken, token);
      assert.equal(bundle.evidence.sm_preflight_passed, true);
      assert.equal(bundle.evidence.authorization_ready, false);
      const surface = JSON.stringify(bundle.evidence);
      assert.equal(surface.includes(token), false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
