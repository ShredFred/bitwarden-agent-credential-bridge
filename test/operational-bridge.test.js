import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
  validateOperationalBindings,
  OperationalBridgeError,
} from '../src/operational-bridge.mjs';
import { REJECTED_CREDENTIAL_CLASSES } from '../src/constants.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

describe('phase8 operational bridge', () => {
  it('validates the sample binding table and rejects bad paths/classes', async () => {
    const table = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    assert.equal(table.bindings.length, 5);
    assert.throws(
      () => validateOperationalBindings({
        version: 1,
        profile: 'operational_disposable_dev',
        bindings: [{
          alias: 'x',
          policy: '../secrets.json',
          credential_class: 'http_bearer',
        }],
      }),
      OperationalBridgeError,
    );
    assert.throws(
      () => validateOperationalBindings({
        version: 1,
        profile: 'operational_disposable_dev',
        bindings: [{
          alias: 'demo_oauth',
          policy: 'policies/sample-fake-service.json',
          credential_class: REJECTED_CREDENTIAL_CLASSES[0],
        }],
      }),
      (error) => error instanceof OperationalBridgeError &&
        error.code === 'rejected_credential_class',
    );
  });

  it('starts all bound services, smokes them, and keeps authorization_ready false', async () => {
    const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    const bridge = await startOperationalBridge({
      repoRoot: root,
      bindings,
    });
    try {
      assert.equal(bridge.harness_ready, true);
      assert.equal(bridge.disposable_dev_ready, false);
      assert.equal(bridge.authorization_ready, false);
      assert.equal(bridge.services.length, 5);
      const smoke = await bridge.smoke();
      assert.deepEqual(smoke, {
        demo_bearer: true,
        demo_api_key_header: true,
        demo_basic: true,
        demo_api_key_query: true,
        demo_browser: true,
      });
    } finally {
      await bridge.close();
    }
  });

  it('rolls back already-started services when a later binding fails', async () => {
    const bindings = {
      version: 1,
      profile: 'operational_disposable_dev',
      bindings: [
        {
          alias: 'demo_bearer',
          policy: 'policies/sample-fake-service.json',
          credential_class: 'http_bearer',
        },
        {
          alias: 'demo_bad',
          policy: 'policies/sample-fake-service.json',
          credential_class: 'http_api_key_header',
        },
      ],
    };
    await assert.rejects(
      () => startOperationalBridge({ repoRoot: root, bindings }),
      (error) => error instanceof OperationalBridgeError &&
        error.code === 'binding_class_mismatch',
    );
  });
});
