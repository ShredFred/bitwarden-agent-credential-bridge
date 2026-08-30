import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  fetchSecretsManagerSecretValue,
  upsertSecretsManagerSecret,
  verifySecretsManagerMachineToken,
  SecretsManagerBwsAdapterError,
  resolveBwsExecutable,
  withBwsDiagnostic,
} from '../src/secrets-manager-bws-adapter.mjs';

const PROJECT = 'e186495e-8667-436f-9f78-b49800eba251';
const SECRET_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

describe('secrets manager bws adapter', () => {
  it('lists then gets a secret through an injected runner without leaking the token into assertions', async () => {
    const token = '0.deadbeef-token-value-not-for-logs==';
    const calls = [];
    const value = await fetchSecretsManagerSecretValue({
      accessToken: token,
      projectId: PROJECT,
      secretKey: 'mivia_demo_bearer',
      runCommand: async (_exe, args) => {
        calls.push(args);
        if (args[0] === 'secret' && args[1] === 'list') {
          return JSON.stringify([
            { id: SECRET_ID, key: 'mivia_demo_bearer', projectId: PROJECT },
            { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', key: 'other', projectId: PROJECT },
          ]);
        }
        if (args[0] === 'secret' && args[1] === 'get') {
          return JSON.stringify({
            id: SECRET_ID,
            key: 'mivia_demo_bearer',
            value: 'SM-FAKE-SENTINEL-VALUE-001',
          });
        }
        throw new Error('unexpected');
      },
    });
    assert.equal(value, 'SM-FAKE-SENTINEL-VALUE-001');
    assert.equal(calls.length, 2);
    assert.equal(calls[0][0], 'secret');
    assert.equal(calls[0][1], 'list');
    assert.equal(calls[0][2], PROJECT);
    assert.ok(calls[0].includes('--access-token'));
    assert.ok(calls[0].includes(token));
    const surface = JSON.stringify({ calls: calls.map((a) => a.filter((x) => x !== token)) });
    assert.equal(surface.includes(token), false);
    assert.equal(surface.includes(value), false);
  });

  it('fails closed when the secret key is missing', async () => {
    await assert.rejects(
      () => fetchSecretsManagerSecretValue({
        accessToken: '0.deadbeef-token-value-not-for-logs==',
        projectId: PROJECT,
        secretKey: 'missing_key',
        runCommand: async () => JSON.stringify([
          { id: SECRET_ID, key: 'other', projectId: PROJECT },
        ]),
      }),
      (error) => error instanceof SecretsManagerBwsAdapterError &&
        error.code === 'secret_not_found',
    );
  });

  it('creates or updates secrets without returning the value', async () => {
    const token = '0.deadbeef-token-value-not-for-logs==';
    const secretValue = 'WRITE-FAKE-SECRET-VALUE-001';
    const calls = [];
    const created = await upsertSecretsManagerSecret({
      accessToken: token,
      projectId: PROJECT,
      secretKey: 'mivia_demo_bearer',
      secretValue,
      runCommand: async (_exe, args) => {
        calls.push(args.slice(0, 3).join(' '));
        if (args[0] === 'secret' && args[1] === 'list') {
          return JSON.stringify([]);
        }
        if (args[0] === 'secret' && args[1] === 'create') {
          return JSON.stringify({ id: SECRET_ID, key: 'mivia_demo_bearer' });
        }
        throw new Error(`unexpected:${args.join(' ')}`);
      },
    });
    assert.deepEqual(created, { ok: true, action: 'created' });
    assert.equal(JSON.stringify(created).includes(secretValue), false);

    const updated = await upsertSecretsManagerSecret({
      accessToken: token,
      projectId: PROJECT,
      secretKey: 'mivia_demo_bearer',
      secretValue,
      runCommand: async (_exe, args) => {
        if (args[0] === 'secret' && args[1] === 'list') {
          return JSON.stringify([
            { id: SECRET_ID, key: 'mivia_demo_bearer', projectId: PROJECT },
          ]);
        }
        if (args[0] === 'secret' && args[1] === 'edit') {
          return JSON.stringify({ id: SECRET_ID, key: 'mivia_demo_bearer' });
        }
        throw new Error(`unexpected:${args.join(' ')}`);
      },
    });
    assert.deepEqual(updated, { ok: true, action: 'updated' });
    assert.equal(JSON.stringify(updated).includes(secretValue), false);
    assert.ok(calls.some((c) => c.startsWith('secret list')));
  });

  it('resolves the default Windows bws.exe without requiring PATH', () => {
    const local = path.join(os.tmpdir(), 'fake-localappdata');
    const expected = path.join(local, 'Programs', 'Bitwarden', 'bws.exe');
    assert.equal(resolveBwsExecutable({
      platform: 'win32',
      env: { LOCALAPPDATA: local },
      pathExists: (filePath) => filePath === expected,
    }), expected);
    assert.equal(resolveBwsExecutable({
      platform: 'win32',
      env: { LOCALAPPDATA: local },
      pathExists: () => false,
    }), 'bws');
    assert.equal(resolveBwsExecutable({
      bwsPath: '/custom/bws',
      platform: 'win32',
      env: { LOCALAPPDATA: local },
      pathExists: () => true,
    }), '/custom/bws');
    assert.equal(resolveBwsExecutable({
      platform: 'darwin',
      env: { LOCALAPPDATA: local },
      pathExists: () => false,
    }), 'bws');
    assert.equal(resolveBwsExecutable({
      platform: 'darwin',
      env: {},
      pathExists: (filePath) => filePath === '/opt/homebrew/bin/bws',
    }), '/opt/homebrew/bin/bws');
    assert.equal(resolveBwsExecutable({
      platform: 'darwin',
      env: { HOME: '/tmp/fake-home' },
      pathExists: (filePath) => filePath === '/tmp/fake-home/.local/bin/bws',
    }), '/tmp/fake-home/.local/bin/bws');
    assert.equal(resolveBwsExecutable({
      platform: 'linux',
      env: { HOME: '/tmp/fake-linux-home' },
      pathExists: (filePath) => filePath === '/tmp/fake-linux-home/.local/bin/bws',
    }), '/tmp/fake-linux-home/.local/bin/bws');
    assert.equal(resolveBwsExecutable({
      platform: 'linux',
      env: { HOME: '/tmp/fake-linux-home' },
      pathExists: (filePath) => filePath === '/usr/bin/bws',
    }), '/usr/bin/bws');
  });

  it('maps a missing executable to bws_missing rather than a generic failure', async () => {
    await assert.rejects(
      () => fetchSecretsManagerSecretValue({
        accessToken: '0.deadbeef-token-value-not-for-logs==',
        projectId: PROJECT,
        secretKey: 'mivia_demo_bearer',
        bwsPath: path.join(os.tmpdir(), 'no-such-bws-executable'),
      }),
      (error) => error instanceof SecretsManagerBwsAdapterError &&
        error.code === 'bws_missing',
    );
  });

  it('verifies a machine token by project-list counts only', async () => {
    const token = '0.deadbeef-token-value-not-for-logs==';
    const empty = await verifySecretsManagerMachineToken({
      accessToken: token,
      allowedProjectIds: [PROJECT],
      runCommand: async (_exe, args) => {
        assert.equal(args[0], 'project');
        assert.equal(args[1], 'list');
        assert.ok(args.includes(token));
        return '[]';
      },
    });
    assert.equal(empty.ok, true);
    assert.equal(empty.projects_listed, 0);
    assert.equal(empty.allowed_projects_visible, 0);
    const hit = await verifySecretsManagerMachineToken({
      accessToken: token,
      allowedProjectIds: [PROJECT],
      runCommand: async () => JSON.stringify([
        { id: PROJECT, name: 'should-not-escape' },
        { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', name: 'other' },
      ]),
    });
    assert.equal(hit.projects_listed, 2);
    assert.equal(hit.allowed_projects_visible, 1);
    assert.equal(JSON.stringify(hit).includes('should-not-escape'), false);
    assert.equal(JSON.stringify(hit).includes(token), false);
  });

  it('keeps bws_missing as the primary code and does not leak host paths', () => {
    const payload = withBwsDiagnostic({
      ok: false,
      code: 'bws_missing',
      authorization_ready: false,
    });
    assert.equal(payload.code, 'bws_missing');
    assert.equal(payload.bws_available, false);
    assert.equal(payload.authorization_ready, false);
    assert.match(payload.hint, /bws/i);
    assert.match(payload.hint, /authorization_ready/i);
    assert.doesNotMatch(payload.hint, /C:\\Users\\/i);
    assert.equal(
      withBwsDiagnostic({ ok: false, code: 'startup_failed' }).hint,
      undefined,
    );
  });
});
