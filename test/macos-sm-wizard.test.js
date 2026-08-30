import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { parseOsascriptJson } from '../src/macos-osascript-json.mjs';
import {
  MACOS_WIZARD_SELF_TEST_MACHINE_ID,
  MACOS_WIZARD_SELF_TEST_TOKEN,
  applySecretsManagerWizardSetup,
  interpretMacosWizardDialog,
  runMacosWizardJxaSelfTest,
} from '../src/macos-sm-wizard.mjs';
import { uninstallSecretsManagerLocalState } from '../src/secrets-manager-local-lifecycle.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptsDir = path.join(root, 'scripts');

describe('macos SM wizard interpret', () => {
  it('maps cancel, invalid ids, short tokens, and newlines', () => {
    assert.deepEqual(
      interpretMacosWizardDialog({ ok: false, code: 'cancelled' }),
      { ok: false, code: 'cancelled' },
    );
    assert.equal(interpretMacosWizardDialog(null).code, 'wizard_output_invalid');
    assert.equal(interpretMacosWizardDialog({ ok: true, machine_id: 'BAD ID', token: '0.fake-token-value==' }).code, 'invalid_machine_id');
    assert.equal(interpretMacosWizardDialog({ ok: true, machine_id: 'pc-ok', token: 'short' }).code, 'invalid_token');
    assert.equal(interpretMacosWizardDialog({
      ok: true,
      machine_id: 'pc-ok',
      token: '0.fake-token-with-nl\n==',
    }).code, 'invalid_token');
    assert.equal(interpretMacosWizardDialog({
      ok: true,
      machine_id: 'pc-ok',
      token: '0.fake-token-value==',
      server_url: 'http://example.invalid',
    }).code, 'invalid_server_url');
  });

  it('accepts a bounded fake token and cloud default', () => {
    const got = interpretMacosWizardDialog({
      ok: true,
      machine_id: 'pc-macbookm1-andrada',
      token: MACOS_WIZARD_SELF_TEST_TOKEN,
      server_url: '',
    });
    assert.equal(got.ok, true);
    if (got.ok === true) {
      assert.equal(got.machineId, 'pc-macbookm1-andrada');
      assert.equal(got.serverUrl, '');
      assert.equal(got.token.length >= 16, true);
    }
  });
});

describe('macos SM wizard apply', () => {
  it('writes allowlist and stores via inject without echoing the token', async () => {
    const dir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'bw-sm-wiz-apply-'));
    const allowPath = path.join(dir, 'sm-machine.allow.json');
    const tokenPath = path.join(dir, 'token');
    const token = MACOS_WIZARD_SELF_TEST_TOKEN;
    try {
      const applied = await applySecretsManagerWizardSetup({
        machineId: 'pc-selftest-apply',
        token,
      }, {
        allowPath,
        storeToken: async (value) => {
          await fsPromises.writeFile(tokenPath, value, 'utf8');
        },
      });
      assert.equal(applied.ok, true);
      assert.equal(applied.setup_complete, true);
      assert.equal(applied.machine_id, 'pc-selftest-apply');
      assert.equal(applied.authorization_ready, false);
      assert.equal(JSON.stringify(applied).includes(token), false);
      const raw = JSON.parse(await fsPromises.readFile(allowPath, 'utf8'));
      assert.equal(raw.machine_id, 'pc-selftest-apply');
      assert.equal(await fsPromises.readFile(tokenPath, 'utf8'), token);
    } finally {
      await fsPromises.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('macos SM wizard JXA', () => {
  it('keeps wizard ASCII-only with displayDialog paste, no NSAlert', () => {
    const wizard = fs.readFileSync(path.join(scriptsDir, 'macos-sm-first-run-wizard.jxa'));
    for (let i = 0; i < wizard.length; i += 1) {
      assert.ok(wizard[i] < 0x80, `non-ASCII at ${i}`);
    }
    const src = wizard.toString('utf8');
    assert.equal(src.includes('console.log'), false);
    assert.match(src, /displayDialog/);
    assert.match(src, /hiddenAnswer: true/);
    assert.match(src, /fieldPad\(8192\)/);
    assert.match(src, /--self-test/);
    assert.equal(src.includes('NSAlert'), false);
    assert.equal(src.includes('NSSecureTextField'), false);
    assert.equal(src.includes('registerSubclass'), false);
    assert.equal(src.includes('sendActionToFrom'), false);
  });

  it('recovers JSON when osascript prepends a warning', () => {
    const parsed = parseOsascriptJson('warning: ignored\n{"ok":true,"code":"x"}\n');
    assert.deepEqual(parsed, { ok: true, code: 'x' });
  });

  it('runs --self-test without a GUI and never requires a live token', async (t) => {
    if (process.platform !== 'darwin') {
      t.skip('osascript JXA is macOS-only');
      return;
    }
    const result = await runMacosWizardJxaSelfTest();
    assert.equal(result.ok, true);
    if (result.ok === true) {
      assert.equal(result.machineId, MACOS_WIZARD_SELF_TEST_MACHINE_ID);
      assert.equal(result.token, MACOS_WIZARD_SELF_TEST_TOKEN);
    }
  });
});

describe('macos SM wizard CLI self-test', () => {
  it('applies and uninstalls a fake token without printing it', async (t) => {
    if (process.platform !== 'darwin') {
      t.skip('wizard CLI self-test is macOS-only');
      return;
    }
    const child = spawn(process.execPath, [
      path.join(scriptsDir, 'run-sm-wizard.mjs'),
      '--self-test',
    ], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    const code = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        resolve(1);
      }, 30000);
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
      });
      child.stderr.on('data', (chunk) => {
        stderr += chunk;
      });
      child.on('close', (exit) => {
        clearTimeout(timer);
        resolve(exit ?? 1);
      });
    });
    assert.equal(stdout.includes(MACOS_WIZARD_SELF_TEST_TOKEN), false);
    assert.equal(stderr.includes(MACOS_WIZARD_SELF_TEST_TOKEN), false);
    const line = stdout.trim().split('\n').at(-1) || '';
    const parsed = JSON.parse(line);
    assert.equal(code, 0, line);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.self_test, true);
    assert.equal(parsed.setup_complete, true);
    assert.equal(parsed.cleanup_complete, true);
    assert.equal(parsed.machine_id, MACOS_WIZARD_SELF_TEST_MACHINE_ID);
    assert.equal(parsed.authorization_ready, false);
    assert.equal(Object.hasOwn(parsed, 'token'), false);
    const leftover = await uninstallSecretsManagerLocalState({
      allowPath: path.join(os.tmpdir(), 'bw-sm-selftest-no-allow.json'),
      machine_id: MACOS_WIZARD_SELF_TEST_MACHINE_ID,
    });
    assert.equal(leftover.token_store_absent, true);
  });
});
