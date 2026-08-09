import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
  validateOperationalBindings,
  OperationalBridgeError,
} from '../src/operational-bridge.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

function runNode(scriptPath, args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scriptPath, ...args], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      env: process.env,
    });
    let stdout = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout });
    });
  });
}

describe('phase14 secrets manager operational wiring', () => {
  it('validates the SM sample binding profile', async () => {
    const table = await loadOperationalBindingsFile(
      root,
      'samples/operational/bindings-sm.example.json',
    );
    assert.equal(table.profile, 'operational_sm_same_user');
    assert.equal(table.bindings.length, 2);
    assert.equal(table.bindings[0].sm_secret_key, 'mivia_demo_bearer');
  });

  it('requires an injected SM resolver and starts with fake adapter secrets', async () => {
    const bindings = validateOperationalBindings({
      version: 1,
      profile: 'operational_sm_same_user',
      bindings: [
        {
          alias: 'mivia_demo_bearer',
          policy: 'policies/sample-fake-service.json',
          credential_class: 'http_bearer',
          sm_project_id: '00000000-0000-4000-8000-000000000001',
          sm_secret_key: 'mivia_demo_bearer',
        },
      ],
    });

    await assert.rejects(
      () => startOperationalBridge({ repoRoot: root, bindings }),
      (error) => error instanceof OperationalBridgeError &&
        error.code === 'sm_resolver_required',
    );

    const sentinel = 'SM-OPERATIONAL-FAKE-SENTINEL-001';
    const bridge = await startOperationalBridge({
      repoRoot: root,
      bindings,
      resolveSecret: async (binding) => ({
        credential_class: binding.credential_class,
        credential: sentinel,
      }),
    });
    try {
      assert.equal(bridge.secrets_manager_mode, true);
      assert.equal(bridge.authorization_ready, false);
      assert.equal(bridge.helper_vault_free, true);
      const smoke = await bridge.smoke();
      assert.equal(smoke.mivia_demo_bearer, true);
      const surface = JSON.stringify({
        profile: bridge.profile,
        services: bridge.services,
        smoke,
      });
      assert.equal(surface.includes(sentinel), false);
    } finally {
      await bridge.close();
    }
  });

  it('rejects SM CLIs without the approval flag', async () => {
    const live = await runNode(
      path.join(root, 'scripts', 'run-secrets-manager-live.mjs'),
    );
    assert.notEqual(live.code, 0);
    const livePayload = JSON.parse(live.stdout.trim().split(/\r?\n/).pop());
    assert.equal(livePayload.code, 'approval_flag_required');
    assert.equal(livePayload.authorization_ready, false);

    const ops = await runNode(
      path.join(root, 'scripts', 'run-operational-bridge-sm.mjs'),
    );
    assert.notEqual(ops.code, 0);
    const opsPayload = JSON.parse(ops.stdout.trim().split(/\r?\n/).pop());
    assert.equal(opsPayload.code, 'approval_flag_required');
  });
});
