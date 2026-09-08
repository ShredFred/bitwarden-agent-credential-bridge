import assert from 'node:assert/strict';
import childProcess, { execFile } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';
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
  it('reports a missing Windows token-store process without crashing or leaking raw errors', {
    skip: process.platform !== 'win32',
  }, async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-missing-process-'));
    const moduleUrl = new URL('../src/secrets-manager-local-lifecycle.mjs', import.meta.url).href;
    const script = `
      import { storeSecretsManagerAccessToken } from ${JSON.stringify(moduleUrl)};
      process.env.SystemRoot = process.argv[1];
      try {
        await storeSecretsManagerAccessToken({
          accessToken: 'FAKE-token-for-missing-process-only', machine_id: 'pc-test',
        });
        process.exitCode = 2;
      } catch (error) {
        process.stdout.write(JSON.stringify({ name: error.name, code: error.code }));
      }
    `;
    try {
      const { stdout, stderr } = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', script, dir], {
        env: { SystemRoot: process.env.SystemRoot, USERPROFILE: dir, LOCALAPPDATA: dir },
        windowsHide: true, timeout: 5000, maxBuffer: 8192, encoding: 'utf8',
      });
      assert.equal(stderr, '');
      assert.deepEqual(JSON.parse(stdout), {
        name: 'SecretsManagerLifecycleError', code: 'token_store_failed',
      });
      assert.deepEqual(await fs.readdir(dir), []);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('accepts only silent successful Windows token-store children and contains pipe failures', {
    skip: process.platform !== 'win32',
  }, async (t) => {
    const token = 'FAKE-only-for-injected-token-store';
    const originalSpawn = childProcess.spawn;
    t.after(() => { childProcess.spawn = originalSpawn; syncBuiltinESMExports(); });
    for (const mode of ['silent', 'stdout', 'stderr', 'stdin_error', 'nonzero']) {
      const child = new EventEmitter();
      child.stdin = new PassThrough();
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      let killed = false;
      child.kill = () => { killed = true; setImmediate(() => child.emit('close', 1)); return true; };
      child.stdin.once('finish', () => {
        if (mode === 'stdout' || mode === 'stderr') child[mode].emit('data', Buffer.from(token));
        if (mode === 'stdin_error') child.stdin.emit('error', new Error(token));
        setImmediate(() => child.emit('close', mode === 'nonzero' ? 1 : 0));
      });
      childProcess.spawn = (_exe, args, options) => {
        assert.equal(JSON.stringify({ args, env: options.env }).includes(token), false);
        assert.equal(options.windowsHide, true);
        return child;
      };
      syncBuiltinESMExports();
      const result = storeSecretsManagerAccessToken({ accessToken: token, machine_id: 'pc-test' });
      if (mode === 'silent') {
        assert.equal((await result).stored, true);
        assert.equal(killed, false);
      } else {
        await assert.rejects(() => result, (error) => error.code === 'token_store_failed' &&
          !String(error).includes(token));
        assert.equal(killed, mode !== 'nonzero');
      }
    }
  });

  it('preserves the existing allowlist when replacement input is invalid', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-preserve-'));
    const allowPath = path.join(dir, 'allow.json');
    try {
      await writeSecretsManagerAllowConfig({ machine_id: 'pc-original' }, { allowPath });
      const original = await fs.readFile(allowPath, 'utf8');
      for (const invalid of [
        { server_url: 'http://invalid.example.test' },
        { allowed_project_ids: ['not-a-uuid'] },
        { allowed_project_ids: [] },
        { allowed_project_ids: [null] },
        { server_url: false },
        { api_url: 'https://api.example.test' },
      ]) {
        await assert.rejects(
          () => writeSecretsManagerAllowConfig({ machine_id: 'pc-new', ...invalid }, { allowPath }),
          (error) => error instanceof SecretsManagerLifecycleError,
        );
        assert.equal(await fs.readFile(allowPath, 'utf8'), original);
      }
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('validates before creating directories and atomically replaces a valid config', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-atomic-'));
    const allowPath = path.join(dir, 'new', 'allow.json');
    try {
      await assert.rejects(() => writeSecretsManagerAllowConfig({
        machine_id: 'pc-test', server_url: 'http://invalid.example.test',
      }, { allowPath }));
      assert.deepEqual(await fs.readdir(dir), []);
      await writeSecretsManagerAllowConfig({ machine_id: 'pc-old' }, { allowPath });
      await writeSecretsManagerAllowConfig({
        machine_id: 'pc-new', server_url: 'https://vault.example.test/',
      }, { allowPath });
      const result = JSON.parse(await fs.readFile(allowPath, 'utf8'));
      assert.equal(result.machine_id, 'pc-new');
      assert.equal(result.server_url, 'https://vault.example.test');
      assert.deepEqual(await fs.readdir(path.dirname(allowPath)), ['allow.json']);
      if (process.platform !== 'win32') {
        assert.equal((await fs.stat(allowPath)).mode & 0o777, 0o600);
      }
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('preserves a colliding directory and cleans only its own staging file', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-collision-'));
    const allowPath = path.join(dir, 'allow.json');
    try {
      await fs.mkdir(allowPath);
      await fs.writeFile(path.join(allowPath, 'keep.txt'), 'synthetic unrelated data');
      await assert.rejects(() => writeSecretsManagerAllowConfig({
        machine_id: 'pc-test',
      }, { allowPath }), (error) => error instanceof SecretsManagerLifecycleError &&
        error.code === 'allow_config_write_failed' && !String(error).includes(dir));
      assert.deepEqual(await fs.readdir(dir), ['allow.json']);
      assert.equal(await fs.readFile(path.join(allowPath, 'keep.txt'), 'utf8'), 'synthetic unrelated data');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

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
