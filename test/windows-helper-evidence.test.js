import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { buildApplyManifest } from '../src/apply-manifest.mjs';
import { authorizeHelperRequest, buildHelperRequest, HelperProtocolError } from '../src/helper-protocol.mjs';
import {
  evaluateWindowsHelperPeerEvidence,
  WindowsHelperEvidenceError,
} from '../src/windows-helper-evidence.mjs';

const callerDigest = createHash('sha256').update('synthetic caller SID').digest('hex');
const helperDigest = createHash('sha256').update('synthetic helper SID').digest('hex');

function evidence(overrides = {}) {
  return {
    schema_version: 1,
    transport_kind: 'windows_named_pipe',
    remote_clients_rejected: true,
    client_pid_verified: true,
    server_pid_verified: true,
    caller_token_verified: true,
    helper_token_verified: true,
    caller_token_user_sha256: callerDigest,
    helper_token_user_sha256: helperDigest,
    caller_is_restricted: false,
    caller_is_app_container: false,
    acl_checks_verified: true,
    all_targets_checked: true,
    caller_effective_write_denied: true,
    helper_required_write_allowed: true,
    ...overrides,
  };
}

describe('Windows helper peer-evidence evaluator', () => {
  it('returns only the five value-free authorization booleans for distinct verified principals', () => {
    const result = evaluateWindowsHelperPeerEvidence(evidence());
    assert.deepEqual(result, {
      local_transport: true,
      identity_verified: true,
      different_principal: true,
      caller_write_denied: true,
      helper_write_allowed: true,
    });
    assert.equal(JSON.stringify(result).includes(callerDigest), false);
    assert.equal(JSON.stringify(result).includes(helperDigest), false);
  });

  it('never treats a restricted token or AppContainer as a different principal with the same TokenUser', () => {
    for (const flags of [
      { caller_is_restricted: true },
      { caller_is_app_container: true },
      { caller_is_restricted: true, caller_is_app_container: true },
    ]) {
      const result = evaluateWindowsHelperPeerEvidence(evidence({
        ...flags,
        helper_token_user_sha256: callerDigest,
      }));
      assert.equal(result.different_principal, false);
    }
  });

  it('fails each transport, token, target, and ACL proof closed', () => {
    const cases = [
      ['remote_clients_rejected', 'local_transport'],
      ['client_pid_verified', 'local_transport'],
      ['server_pid_verified', 'local_transport'],
      ['caller_token_verified', 'identity_verified'],
      ['helper_token_verified', 'identity_verified'],
      ['caller_effective_write_denied', 'caller_write_denied'],
      ['helper_required_write_allowed', 'helper_write_allowed'],
    ];
    for (const [inputField, outputField] of cases) {
      const result = evaluateWindowsHelperPeerEvidence(evidence({ [inputField]: false }));
      assert.equal(result[outputField], false, `${inputField} must fail ${outputField} closed`);
    }
    for (const field of ['acl_checks_verified', 'all_targets_checked']) {
      const result = evaluateWindowsHelperPeerEvidence(evidence({ [field]: false }));
      assert.equal(result.caller_write_denied, false);
      assert.equal(result.helper_write_allowed, false);
    }
    for (const field of ['caller_token_verified', 'helper_token_verified']) {
      assert.equal(evaluateWindowsHelperPeerEvidence(evidence({ [field]: false })).different_principal, false);
    }
  });

  it('rejects missing, extra, accessor, non-boolean, and raw-SID-shaped evidence', () => {
    const missing = evidence();
    delete missing.client_pid_verified;
    const extra = { ...evidence(), caller_sid: 'S-1-5-21-synthetic' };
    const accessor = evidence();
    Object.defineProperty(accessor, 'caller_token_verified', { get: () => true });
    for (const invalid of [
      null,
      missing,
      extra,
      accessor,
      evidence({ caller_token_verified: 1 }),
      evidence({ caller_token_user_sha256: 'S-1-5-21-synthetic' }),
      evidence({ transport_kind: 'tcp' }),
    ]) {
      assert.throws(
        () => evaluateWindowsHelperPeerEvidence(invalid),
        (error) => error instanceof WindowsHelperEvidenceError && error.code === 'peer_identity_unverified',
      );
    }
  });

  it('feeds the helper protocol and rejects same-user sandbox evidence before apply', () => {
    const launcher = Buffer.from('fake Windows helper launcher');
    const launcherSha256 = createHash('sha256').update(launcher).digest('hex');
    const workspace = {
      platform: 'win32',
      root: 'C:\\Temp\\bw-agent-bridge-disposable-test',
      nonce: 'a'.repeat(64),
      homedir: 'C:\\Temp\\bw-agent-bridge-disposable-test\\home',
      env: { LOCALAPPDATA: 'C:\\Temp\\bw-agent-bridge-disposable-test\\home\\AppData\\Local' },
    };
    const manifest = buildApplyManifest({
      platform: workspace.platform,
      homedir: workspace.homedir,
      env: workspace.env,
      launcherBytes: launcher,
      observed: {
        config_dir: 'absent', config_file: 'absent', install_root: 'absent', bin_dir: 'absent',
        launcher: { kind: 'absent' },
      },
    });
    const request = buildHelperRequest({
      requestId: 'b'.repeat(32),
      workspace,
      manifest,
      launcherSha256,
      launcherByteLength: launcher.byteLength,
    });
    const peerEvidence = evaluateWindowsHelperPeerEvidence(evidence({
      caller_is_app_container: true,
      helper_token_user_sha256: callerDigest,
    }));
    assert.throws(
      () => authorizeHelperRequest(request.bytes, {
        workspace, manifest, launcherSha256, launcherByteLength: launcher.byteLength, peerEvidence,
      }),
      (error) => error instanceof HelperProtocolError && error.code === 'same_principal_rejected',
    );
  });
});
