import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import process from 'node:process';
import { describe, it } from 'node:test';
import { buildApplyManifest } from '../src/apply-manifest.mjs';
import { createDisposableWorkspace } from '../src/disposable-workspace.mjs';
import { buildHelperRequest } from '../src/helper-protocol.mjs';
import {
  parseWindowsPipeFacts,
  verifyWindowsHelperPipeSamePrincipal,
  WindowsHelperPipeSessionError,
} from '../src/windows-helper-pipe-session.mjs';

async function fixture() {
  const workspace = await createDisposableWorkspace();
  const launcherBytes = Buffer.from(`fake pipe-session launcher ${workspace.nonce}`);
  const launcherSha256 = createHash('sha256').update(launcherBytes).digest('hex');
  const manifest = buildApplyManifest({
    platform: workspace.platform, homedir: workspace.homedir, env: workspace.env,
    launcherBytes,
    observed: {
      config_dir: 'absent', config_file: 'absent', install_root: 'absent', bin_dir: 'absent',
      launcher: { kind: 'absent' },
    },
  });
  const request = buildHelperRequest({
    requestId: 'c'.repeat(32), workspace, manifest, launcherSha256,
    launcherByteLength: launcherBytes.byteLength,
  });
  return { workspace, launcherSha256, launcherByteLength: launcherBytes.byteLength, manifest, request };
}

async function cleanup(workspace) {
  await fs.rm(workspace.root, { recursive: true, force: true });
}

describe('Windows native helper named-pipe session', () => {
  it('proves local pipe and live token identity, then rejects the same principal', {
    skip: process.platform !== 'win32',
  }, async () => {
    const value = await fixture();
    try {
      const result = await verifyWindowsHelperPipeSamePrincipal({
        workspace: value.workspace,
        requestBytes: value.request.bytes,
        manifest: value.manifest,
        launcherSha256: value.launcherSha256,
        launcherByteLength: value.launcherByteLength,
      });
      assert.deepEqual(result, {
        local_transport: true,
        identity_verified: true,
        different_principal: false,
        authorization_code: 'same_principal_rejected',
      });
      assert.equal(JSON.stringify(result).includes('S-1-'), false);
    } finally {
      await cleanup(value.workspace);
    }
  });

  it('parses only the exact digest-only native fact schema', () => {
    const digest = 'a'.repeat(64);
    const raw = Buffer.from(`${JSON.stringify({
      schema_version: 1,
      transport_kind: 'windows_named_pipe',
      remote_clients_rejected: true,
      client_pid_verified: true,
      server_pid_verified: true,
      caller_token_verified: true,
      helper_token_verified: true,
      caller_token_user_sha256: digest,
      helper_token_user_sha256: digest,
      caller_is_restricted: false,
      caller_is_app_container: false,
      acl_checks_verified: false,
      all_targets_checked: false,
      caller_effective_write_denied: false,
      helper_required_write_allowed: false,
    })}\n`);
    const facts = parseWindowsPipeFacts(raw);
    assert.equal(facts.client_pid_verified, true);
    assert.equal(facts.caller_token_user_sha256, digest);
    assert.equal(parseWindowsPipeFacts(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw])).client_pid_verified, true);
    for (const invalid of [
      Buffer.from(''), Buffer.from('{}\n'), Buffer.from('not json\n'),
      Buffer.from(`${raw.toString('utf8').trimEnd()} `),
      Buffer.from(raw.toString('utf8').replace('"acl_checks_verified":false', '"acl_checks_verified":true,"caller_sid":"S-1-5-21"')),
      Buffer.from(raw.toString('utf8').replace(digest, 'S-1-5-21')),
    ]) {
      assert.throws(
        () => parseWindowsPipeFacts(invalid),
        (error) => error instanceof WindowsHelperPipeSessionError && error.code === 'invalid_probe_output',
      );
    }
  });

  it('accepts no caller-selected process, pipe, executable, or peer evidence', async () => {
    const value = await fixture();
    try {
      for (const extra of [
        { pipeName: 'unsafe' }, { clientPid: 123 }, { command: 'cmd.exe' },
        { peerEvidence: { different_principal: true } },
      ]) {
        await assert.rejects(
          verifyWindowsHelperPipeSamePrincipal({
            workspace: value.workspace,
            requestBytes: value.request.bytes,
            manifest: value.manifest,
            launcherSha256: value.launcherSha256,
            launcherByteLength: value.launcherByteLength,
            ...extra,
          }),
          (error) => error instanceof WindowsHelperPipeSessionError && error.code === 'invalid_input',
        );
      }
    } finally {
      await cleanup(value.workspace);
    }
  });
});
