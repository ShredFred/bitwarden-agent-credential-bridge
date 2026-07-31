import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  BootstrapPlanError,
  deriveUserRoots,
  planBootstrap,
  validateProjectConfig,
  validateUserConfig,
} from '../src/bootstrap-plan.mjs';

const itemId = '123e4567-e89b-42d3-a456-426614174000';
const project = { version: 1, services: [{ alias: 'github-api' }, { alias: 'internal-basic' }] };
const user = {
  version: 1,
  services: {
    'github-api': { credential_class: 'http_bearer', item_id: itemId, secret_field: 'token' },
    'internal-basic': { credential_class: 'http_basic', item_id: itemId, username_field: 'username', password_field: 'password' },
  },
};

describe('portable bootstrap planner', () => {
  it('allows an empty local service registry before the first alias is configured', () => {
    const result = validateUserConfig({ version: 1, services: {} });
    assert.equal(result.version, 1);
    assert.deepEqual(Object.keys(result.services), []);
  });

  it('derives deterministic Windows, macOS, and Linux per-user paths', () => {
    assert.deepEqual(deriveUserRoots('win32', 'C:\\Users\\fake', { LOCALAPPDATA: 'C:\\Users\\fake\\AppData\\Local' }), {
      configPath: 'C:\\Users\\fake\\AppData\\Local\\BitwardenAgentCredentialBridge\\config.json',
      installRoot: 'C:\\Users\\fake\\AppData\\Local\\Programs\\BitwardenAgentCredentialBridge',
      launcherPath: 'C:\\Users\\fake\\AppData\\Local\\Programs\\BitwardenAgentCredentialBridge\\bin\\bw-agent-bridge.cmd',
    });
    assert.equal(deriveUserRoots('darwin', '/Users/fake').configPath, '/Users/fake/Library/Application Support/BitwardenAgentCredentialBridge/config.json');
    assert.equal(deriveUserRoots('linux', '/home/fake').launcherPath, '/home/fake/.local/share/bitwarden-agent-credential-bridge/bin/bw-agent-bridge');
    assert.equal(deriveUserRoots('linux', '/home/fake', { XDG_CONFIG_HOME: '/cfg', XDG_DATA_HOME: '/data' }).configPath, '/cfg/bitwarden-agent-credential-bridge/config.json');
  });

  it('returns only aliases and derived paths, never local vault references', () => {
    const plan = planBootstrap({ platform: 'linux', homedir: '/home/fake', project, user });
    const serialized = JSON.stringify(plan);
    assert.deepEqual(plan.selected_services, ['github-api', 'internal-basic']);
    assert.ok(!serialized.includes(itemId));
    assert.ok(!serialized.includes('username_field'));
    assert.ok(!serialized.includes('password_field'));
    assert.ok(!serialized.includes('secret_field'));
  });

  it('requires project-selected aliases to be locally enabled', () => {
    assert.throws(
      () => planBootstrap({ platform: 'linux', homedir: '/home/fake', project: { version: 1, services: [{ alias: 'repo-added' }] }, user }),
      (error) => error instanceof BootstrapPlanError && error.code === 'service_not_enabled',
    );
  });

  it('rejects project paths, commands, urls, vault references, duplicates, and unknown fields', () => {
    const accessorService = {};
    Object.defineProperty(accessorService, 'alias', { enumerable: true, get: () => 'ok' });
    for (const candidate of [
      { version: 1, services: [{ alias: '../escape' }] },
      { version: 1, services: [{ alias: 'ok', command: 'evil' }] },
      { version: 1, services: [{ alias: 'ok' }, { alias: 'ok' }] },
      { version: 1, services: [{ alias: 'ok' }], url: 'https://example.test' },
      { version: 1, services: [{ alias: 'ok', item_id: itemId }] },
      { version: 1, services: [accessorService] },
    ]) assert.throws(() => validateProjectConfig(candidate), BootstrapPlanError);
  });

  it('enforces exact credential-class-specific local reference fields', () => {
    for (const service of [
      { credential_class: 'http_basic', item_id: itemId, username_field: 'username' },
      { credential_class: 'http_basic', item_id: itemId, username_field: 'username', password_field: 'password', secret_field: 'token' },
      { credential_class: 'http_bearer', item_id: itemId, username_field: 'username', password_field: 'password' },
      { credential_class: 'shell', item_id: itemId, secret_field: 'token' },
      { credential_class: 'http_bearer', item_id: '../vault', secret_field: 'token' },
    ]) assert.throws(() => validateUserConfig({ version: 1, services: { valid: service } }), BootstrapPlanError);

    const accessor = { credential_class: 'http_bearer', item_id: itemId };
    Object.defineProperty(accessor, 'secret_field', { enumerable: true, get: () => 'token' });
    assert.throws(
      () => validateUserConfig({ version: 1, services: { valid: accessor } }),
      /explicit data values/,
    );
  });

  it('fails closed for unsupported platforms and relative OS roots', () => {
    assert.throws(() => deriveUserRoots('freebsd', '/home/fake'), /platform/);
    assert.throws(() => deriveUserRoots('win32', 'C:\\Users\\fake', { LOCALAPPDATA: 'relative' }), /LOCALAPPDATA/);
    assert.throws(() => deriveUserRoots('linux', '/home/fake', { XDG_CONFIG_HOME: 'relative' }), /XDG_CONFIG_HOME/);
  });
});
