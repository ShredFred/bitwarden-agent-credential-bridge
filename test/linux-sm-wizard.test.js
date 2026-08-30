import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  LINUX_WIZARD_SELF_TEST_MACHINE_ID,
  LINUX_WIZARD_SELF_TEST_TOKEN,
  collectLinuxWizardAnswers,
} from '../src/linux-sm-wizard.mjs';
import { applySecretsManagerWizardSetup } from '../src/macos-sm-wizard.mjs';
import { uninstallSecretsManagerLocalState } from '../src/secrets-manager-local-lifecycle.mjs';

describe('linux SM wizard', () => {
  it('self-test returns the fake token without GUI', async () => {
    const got = await collectLinuxWizardAnswers({
      selfTest: true,
      machineId: LINUX_WIZARD_SELF_TEST_MACHINE_ID,
      bwsOk: true,
    });
    assert.equal(got.ok, true);
    if (got.ok === true) {
      assert.equal(got.machineId, LINUX_WIZARD_SELF_TEST_MACHINE_ID);
      assert.equal(got.token, LINUX_WIZARD_SELF_TEST_TOKEN);
      assert.equal(JSON.stringify(got).includes(LINUX_WIZARD_SELF_TEST_TOKEN), true);
    }
  });

  it('applies via injected prompts and uninstalls the temp store', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-linux-wiz-'));
    const allowPath = path.join(dir, 'sm-machine.allow.json');
    const tokenPath = path.join(dir, 'sm-machine.token');
    const token = LINUX_WIZARD_SELF_TEST_TOKEN;
    try {
      const interpreted = await collectLinuxWizardAnswers({
        machineId: 'pc-linux-test',
        promptMachineId: async () => 'pc-linux-test',
        promptToken: async () => token,
      });
      assert.equal(interpreted.ok, true);
      if (interpreted.ok !== true) return;
      const applied = await applySecretsManagerWizardSetup({
        machineId: interpreted.machineId,
        token: interpreted.token,
      }, {
        allowPath,
        storeToken: async (value) => {
          await fs.writeFile(tokenPath, value, { encoding: 'utf8', mode: 0o600 });
        },
      });
      assert.equal(applied.setup_complete, true);
      assert.equal(applied.authorization_ready, false);
      assert.equal(JSON.stringify(applied).includes(token), false);
      const removed = await uninstallSecretsManagerLocalState({
        allowPath,
        tokenPath,
        machine_id: interpreted.machineId,
      });
      assert.equal(removed.uninstall_complete, true);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
