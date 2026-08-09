import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  loadSecretsManagerAllowConfig,
  resolveBwsServerOptions,
  SecretsManagerAllowConfigError,
} from '../src/secrets-manager-allow-config.mjs';
import { fetchSecretsManagerSecretValue } from '../src/secrets-manager-bws-adapter.mjs';

const PROJECT = 'e186495e-8667-436f-9f78-b49800eba251';

describe('secrets manager endpoints (phase 15)', () => {
  it('loads optional server_url and maps to bws --server-url', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-ep-'));
    const filePath = path.join(dir, 'sm-machine.allow.json');
    await fs.writeFile(filePath, JSON.stringify({
      schema_version: 1,
      machine_id: 'pc-selfhost',
      allowed_project_ids: [PROJECT],
      server_url: 'https://vault.example.test',
    }), 'utf8');
    try {
      const loaded = await loadSecretsManagerAllowConfig(filePath);
      assert.equal(loaded.server_url, 'https://vault.example.test');
      const resolved = resolveBwsServerOptions(loaded);
      assert.equal(resolved.usesCloudDefault, false);
      assert.equal(resolved.serverUrlArg, 'https://vault.example.test');

      const seen = [];
      await fetchSecretsManagerSecretValue({
        accessToken: '0.deadbeef-token-value-not-for-logs==',
        projectId: PROJECT,
        secretKey: 'demo',
        allowConfig: loaded,
        runCommand: async (_exe, args) => {
          seen.push(args);
          if (args.includes('list')) {
            return JSON.stringify([
              { id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', key: 'demo' },
            ]);
          }
          return JSON.stringify({
            id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
            key: 'demo',
            value: 'SM-FAKE-SENTINEL-VALUE-001',
          });
        },
      });
      assert.ok(seen[0].includes('--server-url'));
      assert.ok(seen[0].includes('https://vault.example.test'));
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects http endpoints and incomplete api/identity pairs', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-ep-bad-'));
    const filePath = path.join(dir, 'bad.json');
    await fs.writeFile(filePath, JSON.stringify({
      schema_version: 1,
      machine_id: 'pc-bad',
      allowed_project_ids: [PROJECT],
      api_url: 'https://api.example.test',
    }), 'utf8');
    try {
      await assert.rejects(
        () => loadSecretsManagerAllowConfig(filePath),
        (error) => error instanceof SecretsManagerAllowConfigError,
      );
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('defaults to cloud when no endpoint fields are present', () => {
    const resolved = resolveBwsServerOptions({
      allowed_project_ids: [PROJECT],
    });
    assert.equal(resolved.usesCloudDefault, true);
    assert.equal(resolved.serverUrlArg, null);
  });
});
