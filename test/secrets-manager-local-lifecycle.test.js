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
  slugSecretsManagerMachineLabel,
  defaultSecretsManagerMachineId,
  renameSecretsManagerMachineId,
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

  it('slugs ComputerName and drops ISP hostname fragments', () => {
    assert.equal(slugSecretsManagerMachineLabel('MacBook Andrada'), 'macbook-andrada');
    assert.equal(slugSecretsManagerMachineLabel('macbookm1 andrada'), 'macbookm1-andrada');
    assert.equal(
      slugSecretsManagerMachineLabel('MacBookPro.vodafone.ultrahub'),
      'macbookpro-ultrahub',
    );
    assert.equal(
      defaultSecretsManagerMachineId({
        computerName: 'macbookm1 andrada',
        hostname: 'MacBookPro.vodafone.ultrahub',
      }),
      'pc-macbookm1-andrada',
    );
    assert.equal(
      defaultSecretsManagerMachineId({
        hostname: 'MacBookPro.home.vodafone',
      }),
      'pc-macbookpro',
    );
    assert.equal(
      defaultSecretsManagerMachineId({
        platform: 'linux',
        hostname: 'devbox.home.vodafone',
      }),
      'pc-devbox',
    );
  });

  it('renames machine_id and re-homes a mocked Keychain token', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-rename-'));
    const allowPath = path.join(dir, 'sm-machine.allow.json');
    const token = '0.fake-access-token-value==';
    try {
      await writeSecretsManagerAllowConfig({
        machine_id: 'pc-old-isp',
      }, { allowPath });
      const calls = [];
      const result = await renameSecretsManagerMachineId('pc-macbookm1-andrada', {
        allowPath,
        platform: 'darwin',
        runSecurity: async (script) => {
          calls.push(script.split(' ')[0]);
          if (script.startsWith('find-generic-password') && script.endsWith(' -w')) {
            assert.match(script, /-a "pc-old-isp"/);
            return { code: 0, stdout: `${token}\n`, stderr: '' };
          }
          if (script.startsWith('add-generic-password')) {
            assert.match(script, /-a "pc-macbookm1-andrada"/);
            assert.equal(script.includes(token), true);
            return { code: 0, stdout: '', stderr: '' };
          }
          if (script.startsWith('delete-generic-password')) {
            assert.match(script, /-a "pc-old-isp"/);
            return { code: 0, stdout: '', stderr: '' };
          }
          return { code: 1, stdout: '', stderr: 'unexpected' };
        },
      });
      assert.equal(result.ok, true);
      assert.equal(result.renamed, true);
      assert.equal(result.machine_id, 'pc-macbookm1-andrada');
      assert.equal(result.previous_machine_id, 'pc-old-isp');
      assert.equal(result.authorization_ready, false);
      assert.deepEqual(calls, [
        'find-generic-password',
        'add-generic-password',
        'delete-generic-password',
      ]);
      const raw = JSON.parse(await fs.readFile(allowPath, 'utf8'));
      assert.equal(raw.machine_id, 'pc-macbookm1-andrada');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('renames machine_id on Linux without touching a mocked token file', {
    skip: process.platform === 'win32',
  }, async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-linux-rename-'));
    const allowPath = path.join(dir, 'sm-machine.allow.json');
    const tokenPath = path.join(dir, 'sm-machine.token');
    try {
      await writeSecretsManagerAllowConfig({
        machine_id: 'pc-old-linux',
      }, { allowPath });
      await fs.writeFile(tokenPath, '0.fake-linux-token-value==', { mode: 0o600 });
      await fs.chmod(tokenPath, 0o600);
      const result = await renameSecretsManagerMachineId('pc-linux-box', {
        allowPath,
        tokenPath,
        platform: 'linux',
      });
      assert.equal(result.ok, true);
      assert.equal(result.renamed, true);
      assert.equal(result.machine_id, 'pc-linux-box');
      assert.equal(result.previous_machine_id, 'pc-old-linux');
      const raw = JSON.parse(await fs.readFile(allowPath, 'utf8'));
      assert.equal(raw.machine_id, 'pc-linux-box');
      assert.equal(await fs.readFile(tokenPath, 'utf8'), '0.fake-linux-token-value==');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('does not unlink an allowlist for a different machine_id', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-keep-allow-'));
    const allowPath = path.join(dir, 'sm-machine.allow.json');
    try {
      await writeSecretsManagerAllowConfig({
        machine_id: 'pc-keep',
      }, { allowPath });
      const removed = await uninstallSecretsManagerLocalState({
        allowPath,
        machine_id: 'pc-other',
        tokenPath: path.join(dir, 'no-token'),
      });
      assert.equal(removed.allow_config_removed, false);
      const raw = JSON.parse(await fs.readFile(allowPath, 'utf8'));
      assert.equal(raw.machine_id, 'pc-keep');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
