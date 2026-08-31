import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  LinuxSmTokenFileError,
  defaultLinuxSecretsManagerTokenPath,
  deleteLinuxOwnerOnlyToken,
  linuxOwnerOnlyTokenPresent,
  readLinuxOwnerOnlyToken,
  storeLinuxOwnerOnlyToken,
} from '../src/linux-sm-token-file.mjs';
import { isSecretsManagerSameUserPlatform } from '../src/secrets-manager-platforms.mjs';

describe('linux SM owner-only token file', () => {
  it('treats linux as a same-user SM platform', () => {
    assert.equal(isSecretsManagerSameUserPlatform('linux'), true);
    assert.equal(isSecretsManagerSameUserPlatform('darwin'), true);
    assert.equal(isSecretsManagerSameUserPlatform('win32'), true);
    assert.equal(isSecretsManagerSameUserPlatform('freebsd'), false);
  });

  it('places the token file under XDG config with POSIX separators', () => {
    assert.equal(
      defaultLinuxSecretsManagerTokenPath({
        home: '/tmp/fake-linux-home',
        configHome: '/tmp/fake-xdg-config',
      }),
      '/tmp/fake-xdg-config/BitwardenAgentCredentialBridge/sm-machine.token',
    );
    assert.equal(
      defaultLinuxSecretsManagerTokenPath({
        home: '/tmp/fake-linux-home',
      }),
      '/tmp/fake-linux-home/.config/BitwardenAgentCredentialBridge/sm-machine.token',
    );
  });

  it('stores, reads, and deletes a fake token without echoing it', {
    skip: process.platform === 'win32',
  }, async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-linux-tok-'));
    const tokenPath = path.join(dir, 'sm-machine.token');
    const token = '0.fake-linux-token-value==';
    try {
      await storeLinuxOwnerOnlyToken(token, { tokenPath });
      const st = await fs.lstat(tokenPath);
      assert.equal(st.isFile(), true);
      assert.equal(st.isSymbolicLink(), false);
      assert.equal(st.mode & 0o077, 0);
      assert.equal(await linuxOwnerOnlyTokenPresent({ tokenPath }), true);
      assert.equal(await readLinuxOwnerOnlyToken({ tokenPath }), token);
      await deleteLinuxOwnerOnlyToken({ tokenPath });
      assert.equal(await linuxOwnerOnlyTokenPresent({ tokenPath }), false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects group/other-readable tokens and newlines', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-linux-bad-'));
    const tokenPath = path.join(dir, 'sm-machine.token');
    try {
      await assert.rejects(
        () => storeLinuxOwnerOnlyToken('short', { tokenPath }),
        (error) => error instanceof LinuxSmTokenFileError && error.code === 'invalid_token',
      );
      await fs.writeFile(tokenPath, '0.fake-linux-token-value==', { mode: 0o644 });
      await fs.chmod(tokenPath, 0o644);
      await assert.rejects(
        () => readLinuxOwnerOnlyToken({ tokenPath }),
        (error) => error instanceof LinuxSmTokenFileError && error.code === 'token_store_insecure',
      );
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
