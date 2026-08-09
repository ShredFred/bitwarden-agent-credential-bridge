import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  loadSecretsManagerAllowConfig,
  isProjectAllowed,
  SecretsManagerAllowConfigError,
} from '../src/secrets-manager-allow-config.mjs';

describe('secrets manager allow config', () => {
  it('loads an exact schema and checks project allowlist', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-allow-'));
    const filePath = path.join(dir, 'sm-machine.allow.json');
    const projectA = 'e186495e-8667-436f-9f78-b49800eba251';
    const projectB = '1d9a72dc-75aa-4bf3-a528-b49800ebbf68';
    await fs.writeFile(filePath, JSON.stringify({
      schema_version: 1,
      machine_id: 'laptop-company',
      allowed_project_ids: [projectA, projectB],
    }), 'utf8');
    const loaded = await loadSecretsManagerAllowConfig(filePath);
    assert.equal(loaded.machine_id, 'laptop-company');
    assert.equal(loaded.allowed_project_ids.length, 2);
    assert.equal(isProjectAllowed(loaded, projectA), true);
    assert.equal(isProjectAllowed(loaded, '00000000-0000-4000-8000-000000000099'), false);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('rejects malformed allow configs', async () => {
    await assert.rejects(
      () => loadSecretsManagerAllowConfig(path.join(os.tmpdir(), 'missing-sm-allow.json')),
      (error) => error instanceof SecretsManagerAllowConfigError &&
        error.code === 'allow_config_absent',
    );
  });
});
