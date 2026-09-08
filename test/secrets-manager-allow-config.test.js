import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  loadSecretsManagerAllowConfig,
  validateSecretsManagerAllowConfig,
  isProjectAllowed,
  defaultSecretsManagerAllowPath,
  SecretsManagerAllowConfigError,
} from '../src/secrets-manager-allow-config.mjs';

describe('secrets manager allow config', () => {
  it('validates an immutable normalized snapshot without evaluating getters or proxies', () => {
    const project = 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE';
    const input = { schema_version: 1, machine_id: 'pc-test', allowed_project_ids: [project] };
    const config = validateSecretsManagerAllowConfig(input);
    input.allowed_project_ids[0] = 'changed';
    assert.deepEqual(config.allowed_project_ids, [project.toLowerCase()]);
    assert.equal(Object.isFrozen(config), true);
    assert.equal(Object.isFrozen(config.allowed_project_ids), true);
    assert.equal(Object.hasOwn(config, 'path'), false);
    let calls = 0;
    const accessor = [project];
    Object.defineProperty(accessor, '0', { get() { calls += 1; return project; } });
    const proxy = new Proxy([project], { get() { calls += 1; throw new Error('must not run'); } });
    for (const ids of [accessor, proxy, [,], [project, project.toLowerCase()], Object.assign([project], { extra: true })]) {
      assert.throws(() => validateSecretsManagerAllowConfig({ ...input, allowed_project_ids: ids }), SecretsManagerAllowConfigError);
    }
    assert.equal(calls, 0);
  });

  it('rejects present endpoint fields with invalid types instead of selecting cloud defaults', () => {
    for (const field of ['server_url', 'api_url', 'identity_url']) {
      for (const value of [null, false, 0, {}, []]) {
        assert.throws(() => validateSecretsManagerAllowConfig({
          schema_version: 1,
          machine_id: 'pc-test',
          allowed_project_ids: ['aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'],
          [field]: value,
        }), SecretsManagerAllowConfigError);
      }
    }
  });

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

  it('places the Linux allowlist under XDG config, not AppData', () => {
    const linuxPath = defaultSecretsManagerAllowPath({
      platform: 'linux',
      home: '/tmp/fake-linux-home',
      configHome: '/tmp/fake-xdg-config',
    });
    assert.equal(
      linuxPath,
      '/tmp/fake-xdg-config/BitwardenAgentCredentialBridge/sm-machine.allow.json',
    );
    assert.equal(linuxPath.includes('AppData'), false);
  });

  it('rejects malformed allow configs', async () => {
    await assert.rejects(
      () => loadSecretsManagerAllowConfig(path.join(os.tmpdir(), 'missing-sm-allow.json')),
      (error) => error instanceof SecretsManagerAllowConfigError &&
        error.code === 'allow_config_absent',
    );
  });
});
