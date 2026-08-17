import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  writeSecretsManagerAllowConfig,
  storeSecretsManagerAccessToken,
  uninstallSecretsManagerLocalState,
  inspectSecretsManagerLocalState,
  checkBwsAvailable,
  SecretsManagerLifecycleError,
} from '../src/secrets-manager-local-lifecycle.mjs';
import { SM_DEFAULT_ALLOWED_PROJECT_IDS } from '../src/secrets-manager-defaults.mjs';

describe('secrets manager local lifecycle', () => {
  it('writes allowlist defaults, stores token via inject, and uninstalls cleanly', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-life-'));
    const allowPath = path.join(dir, 'sm-machine.allow.json');
    const tokenPath = path.join(dir, 'sm-machine.token');
    try {
      const allow = await writeSecretsManagerAllowConfig({
        machine_id: 'pc-test',
      }, { allowPath });
      assert.equal(allow.project_count, SM_DEFAULT_ALLOWED_PROJECT_IDS.length);
      const raw = JSON.parse(await fs.readFile(allowPath, 'utf8'));
      assert.deepEqual(raw.allowed_project_ids, [...SM_DEFAULT_ALLOWED_PROJECT_IDS]);

      const token = '0.fake-access-token-value==';
      await storeSecretsManagerAccessToken({
        accessToken: token,
        machine_id: 'pc-test',
        storeToken: async (value) => {
          await fs.writeFile(tokenPath, value, 'utf8');
        },
      });
      assert.equal(await fs.readFile(tokenPath, 'utf8'), token);

      const before = await inspectSecretsManagerLocalState({ allowPath, tokenPath });
      assert.equal(before.allow_config_present, true);
      assert.equal(before.token_store_present, true);

      const removed = await uninstallSecretsManagerLocalState({ allowPath, tokenPath });
      assert.equal(removed.uninstall_complete, true);
      assert.equal(removed.allow_config_absent, true);
      assert.equal(removed.token_store_absent, true);
      assert.equal(removed.authorization_ready, false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects bad machine ids and reports bws check without secrets', async () => {
    await assert.rejects(
      () => writeSecretsManagerAllowConfig({ machine_id: 'BAD ID' }),
      (error) => error instanceof SecretsManagerLifecycleError &&
        error.code === 'invalid_machine_id',
    );
    const bws = await checkBwsAvailable({
      runCommand: async () => 'bws 1.0.0',
    });
    assert.equal(bws.bws_available, true);
    const missing = await checkBwsAvailable({
      bwsPath: path.join(os.tmpdir(), 'no-such-bws-executable'),
    });
    assert.equal(missing.bws_available, false);

    const local = path.join(os.tmpdir(), 'fake-localappdata');
    const expected = path.join(local, 'Programs', 'Bitwarden', 'bws.exe');
    let seen = null;
    const fromDefault = await checkBwsAvailable({
      platform: 'win32',
      env: { LOCALAPPDATA: local },
      pathExists: (filePath) => filePath === expected,
      runCommand: async (exe) => {
        seen = exe;
        return 'bws 2.1.0';
      },
    });
    assert.equal(fromDefault.bws_available, true);
    assert.equal(seen, expected);
  });
});
