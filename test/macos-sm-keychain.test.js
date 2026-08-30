import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  MACOS_SM_KEYCHAIN_SERVICE,
  MacosSmKeychainError,
  deleteMacosKeychainToken,
  macosKeychainTokenPresent,
  macosSmKeychainServiceName,
  readMacosKeychainToken,
  storeMacosKeychainToken,
} from '../src/macos-sm-keychain.mjs';
import { parseOsascriptJson } from '../src/macos-osascript-json.mjs';
import { SM_MACHINE_TOKEN_PURPOSE } from '../src/secrets-manager-token-collector.mjs';

const scriptsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts');

describe('macos SM keychain', () => {
  it('pins the Keychain service to the SM machine token purpose', () => {
    assert.equal(macosSmKeychainServiceName(), SM_MACHINE_TOKEN_PURPOSE);
    assert.equal(MACOS_SM_KEYCHAIN_SERVICE, SM_MACHINE_TOKEN_PURPOSE);
  });

  it('stores via security -i with -A and never puts the token on thrown errors', async () => {
    const token = '0.fake-keychain-token-value==';
    let seen = '';
    await storeMacosKeychainToken(token, 'pc-test', {
      runSecurity: async (script) => {
        seen = script;
        assert.match(script, /add-generic-password/);
        assert.match(script, / -A /);
        assert.match(script, /-U/);
        assert.match(script, /pc-test/);
        return { code: 0, stdout: '', stderr: '' };
      },
    });
    assert.equal(seen.includes(token), true);
    await assert.rejects(
      () => storeMacosKeychainToken(token, 'pc-test', {
        runSecurity: async () => {
          throw new Error(token);
        },
      }),
      (error) => error instanceof MacosSmKeychainError &&
        error.code === 'token_store_failed' &&
        error.message.includes(token) === false,
    );
  });

  it('reads the password from stdout only and maps missing items', async () => {
    const token = '0.injected-keychain-token==';
    const got = await readMacosKeychainToken('pc-read', {
      runSecurity: async (script) => {
        assert.match(script, /find-generic-password/);
        assert.match(script, / -w$/);
        return { code: 0, stdout: `${token}\n`, stderr: '' };
      },
    });
    assert.equal(got, token);
    await assert.rejects(
      () => readMacosKeychainToken('pc-read', {
        runSecurity: async () => ({ code: 44, stdout: '', stderr: 'not found' }),
      }),
      (error) => error instanceof MacosSmKeychainError && error.code === 'token_absent',
    );
  });

  it('treats missing Keychain items as success on delete', async () => {
    await deleteMacosKeychainToken('pc-gone', {
      runSecurity: async () => ({ code: 44, stdout: '', stderr: '' }),
    });
    assert.equal(
      await macosKeychainTokenPresent('pc-gone', {
        runSecurity: async () => ({ code: 44, stdout: '', stderr: '' }),
      }),
      false,
    );
    assert.equal(
      await macosKeychainTokenPresent('pc-gone', {
        runSecurity: async () => ({ code: 0, stdout: 'keychain: ...', stderr: '' }),
      }),
      true,
    );
  });

  it('rejects invalid machine ids without calling security', async () => {
    let called = false;
    await assert.rejects(
      () => storeMacosKeychainToken('0.fake-token-value-xx', 'BAD ID', {
        runSecurity: async () => {
          called = true;
          return { code: 0, stdout: '', stderr: '' };
        },
      }),
      (error) => error instanceof MacosSmKeychainError && error.code === 'invalid_machine_id',
    );
    assert.equal(called, false);
  });
});

describe('macos SM dialog scripts', () => {
  it('recovers a JSON object when osascript prepends a warning', () => {
    const parsed = parseOsascriptJson('warning: ignored\n{"ok":true,"code":"x"}\n');
    assert.deepEqual(parsed, { ok: true, code: 'x' });
  });

  it('keeps wizard and secret-entry JXA ASCII-only and token-quiet', () => {
    for (const name of [
      'macos-sm-first-run-wizard.jxa',
      'macos-sm-secret-entry-dialog.jxa',
      'run-sm-wizard.mjs',
    ]) {
      const bytes = fs.readFileSync(path.join(scriptsDir, name));
      for (let i = 0; i < bytes.length; i += 1) {
        assert.ok(bytes[i] < 0x80, `non-ASCII byte in ${name} at offset ${i}`);
      }
      const src = bytes.toString('utf8');
      assert.equal(src.includes('console.log'), false);
      assert.match(src, /JSON/);
    }
    const wizard = fs.readFileSync(
      path.join(scriptsDir, 'macos-sm-first-run-wizard.jxa'),
      'utf8',
    );
    assert.match(wizard, /displayDialog/);
    assert.match(wizard, /hiddenAnswer: true/);
    assert.equal(wizard.includes('NSAlert'), false);
    assert.equal(wizard.includes('NSSecureTextField'), false);
    assert.equal(wizard.includes('sendActionToFrom'), false);
    assert.equal(wizard.includes('registerSubclass'), false);
  });
});
