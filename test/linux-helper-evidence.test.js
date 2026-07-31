import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { buildApplyManifest } from '../src/apply-manifest.mjs';
import { authorizeHelperRequest, buildHelperRequest, HelperProtocolError } from '../src/helper-protocol.mjs';
import {
  evaluateLinuxHelperPeerEvidence,
  LinuxHelperEvidenceError,
} from '../src/linux-helper-evidence.mjs';

const callerDigest = createHash('sha256').update('uid:1000').digest('hex');
const helperDigest = createHash('sha256').update('uid:1001').digest('hex');

function evidence(overrides = {}) {
  return {
    schema_version: 1,
    transport_kind: 'linux_af_unix',
    peercred_verified: true,
    peer_pid_verified: true,
    helper_pid_verified: true,
    caller_creds_verified: true,
    helper_creds_verified: true,
    caller_uid_translated_to_init_userns: true,
    helper_uid_translated_to_init_userns: true,
    helper_user_ns_is_init: true,
    peercred_uid_matches_caller_host_uid: true,
    caller_host_uid_sha256: callerDigest,
    helper_host_uid_sha256: helperDigest,
    caller_user_ns_is_init: true,
    caller_appears_uid0_in_own_userns: false,
    caller_uid_map_maps_root_to_noninit: false,
    target_access_checked_in_helper_mount_ns: true,
    access_checks_verified: true,
    all_targets_checked: true,
    caller_effective_write_denied: true,
    helper_required_write_allowed: true,
    caller_no_new_privs: true,
    helper_no_new_privs: true,
    caller_cap_effective_empty: true,
    helper_cap_effective_empty: true,
    caller_seccomp_mode_filter: true,
    helper_seccomp_mode_filter: true,
    caller_landlock_active: true,
    helper_landlock_active: true,
    ...overrides,
  };
}

describe('Linux helper peer-evidence evaluator', () => {
  it('returns only five value-free authorization booleans for distinct host UIDs', () => {
    const result = evaluateLinuxHelperPeerEvidence(evidence());
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

  it('never treats namespace-local uid 0 or sandbox hardening as a different host principal', () => {
    const result = evaluateLinuxHelperPeerEvidence(evidence({
      helper_host_uid_sha256: callerDigest,
      caller_user_ns_is_init: false,
      caller_appears_uid0_in_own_userns: true,
      caller_uid_map_maps_root_to_noninit: true,
      caller_no_new_privs: true,
      caller_cap_effective_empty: true,
      caller_seccomp_mode_filter: true,
      caller_landlock_active: true,
    }));
    assert.equal(result.different_principal, false);
  });

  it('fails transport and init-userns identity proofs closed independently', () => {
    for (const field of ['peercred_verified', 'peer_pid_verified', 'helper_pid_verified']) {
      assert.equal(evaluateLinuxHelperPeerEvidence(evidence({ [field]: false })).local_transport, false);
    }
    for (const field of [
      'caller_creds_verified',
      'helper_creds_verified',
      'caller_uid_translated_to_init_userns',
      'helper_uid_translated_to_init_userns',
      'helper_user_ns_is_init',
      'peercred_uid_matches_caller_host_uid',
    ]) {
      const result = evaluateLinuxHelperPeerEvidence(evidence({ [field]: false }));
      assert.equal(result.identity_verified, false);
      assert.equal(result.different_principal, false);
    }
  });

  it('keeps defense-in-depth signals separate from a fully verified host-principal comparison', () => {
    const result = evaluateLinuxHelperPeerEvidence(evidence({
      caller_user_ns_is_init: false,
      caller_appears_uid0_in_own_userns: false,
      caller_uid_map_maps_root_to_noninit: false,
      caller_no_new_privs: false,
      helper_no_new_privs: false,
      caller_cap_effective_empty: false,
      helper_cap_effective_empty: false,
      caller_seccomp_mode_filter: false,
      helper_seccomp_mode_filter: false,
      caller_landlock_active: false,
      helper_landlock_active: false,
    }));
    assert.equal(result.identity_verified, true);
    assert.equal(result.different_principal, true);
  });

  it('requires complete access checks in the helper mount namespace for both write claims', () => {
    for (const field of [
      'target_access_checked_in_helper_mount_ns',
      'access_checks_verified',
      'all_targets_checked',
    ]) {
      const result = evaluateLinuxHelperPeerEvidence(evidence({ [field]: false }));
      assert.equal(result.caller_write_denied, false);
      assert.equal(result.helper_write_allowed, false);
    }
    assert.equal(evaluateLinuxHelperPeerEvidence(evidence({ caller_effective_write_denied: false })).caller_write_denied, false);
    assert.equal(evaluateLinuxHelperPeerEvidence(evidence({ helper_required_write_allowed: false })).helper_write_allowed, false);
  });

  it('rejects missing, extra, accessor, proxy, non-boolean, raw-UID, and wrong-transport evidence', () => {
    const missing = evidence();
    delete missing.peercred_verified;
    const accessor = evidence();
    Object.defineProperty(accessor, 'helper_creds_verified', { get: () => true });
    for (const invalid of [
      null,
      missing,
      { ...evidence(), raw_uid: 0 },
      accessor,
      new Proxy(evidence(), {}),
      evidence({ helper_no_new_privs: 1 }),
      evidence({ caller_host_uid_sha256: '0' }),
      evidence({ transport_kind: 'tcp' }),
    ]) {
      assert.throws(
        () => evaluateLinuxHelperPeerEvidence(invalid),
        (error) => error instanceof LinuxHelperEvidenceError && error.code === 'peer_identity_unverified',
      );
    }
  });

  it('snapshots validated facts without consulting a poisoned Object.prototype', () => {
    let getterCalls = 0;
    let setterCalls = 0;
    const priorDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'helper_creds_verified');
    Object.defineProperty(Object.prototype, 'helper_creds_verified', {
      configurable: true,
      get() { getterCalls += 1; return true; },
      set() { setterCalls += 1; },
    });
    try {
      const result = evaluateLinuxHelperPeerEvidence(evidence({ helper_creds_verified: false }));
      assert.equal(result.identity_verified, false);
      assert.equal(result.different_principal, false);
      assert.equal(getterCalls, 0);
      assert.equal(setterCalls, 0);
    } finally {
      if (priorDescriptor === undefined) delete Object.prototype.helper_creds_verified;
      else Object.defineProperty(Object.prototype, 'helper_creds_verified', priorDescriptor);
    }
  });

  it('feeds the helper protocol and rejects user-namespace root cosplay before apply', () => {
    const launcher = Buffer.from('fake Linux helper launcher');
    const launcherSha256 = createHash('sha256').update(launcher).digest('hex');
    const workspace = {
      platform: 'linux',
      root: '/tmp/bw-agent-bridge-disposable-test',
      nonce: 'a'.repeat(64),
      homedir: '/tmp/bw-agent-bridge-disposable-test/home',
      env: {
        XDG_CONFIG_HOME: '/tmp/bw-agent-bridge-disposable-test/home/.config',
        XDG_DATA_HOME: '/tmp/bw-agent-bridge-disposable-test/home/.local/share',
      },
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
      requestId: 'b'.repeat(32), workspace, manifest, launcherSha256,
      launcherByteLength: launcher.byteLength,
    });
    const peerEvidence = evaluateLinuxHelperPeerEvidence(evidence({
      helper_host_uid_sha256: callerDigest,
      caller_user_ns_is_init: false,
      caller_appears_uid0_in_own_userns: true,
      caller_uid_map_maps_root_to_noninit: true,
    }));
    assert.throws(
      () => authorizeHelperRequest(request.bytes, {
        workspace, manifest, launcherSha256, launcherByteLength: launcher.byteLength, peerEvidence,
      }),
      (error) => error instanceof HelperProtocolError && error.code === 'same_principal_rejected',
    );
  });

  it('makes protocol authorization fail identity-first when init-userns or peercred agreement is absent', () => {
    const launcher = Buffer.from('fake Linux identity failure launcher');
    const launcherSha256 = createHash('sha256').update(launcher).digest('hex');
    const workspace = {
      platform: 'linux', root: '/tmp/bw-agent-bridge-disposable-identity', nonce: 'c'.repeat(64),
      homedir: '/tmp/bw-agent-bridge-disposable-identity/home',
      env: {
        XDG_CONFIG_HOME: '/tmp/bw-agent-bridge-disposable-identity/home/.config',
        XDG_DATA_HOME: '/tmp/bw-agent-bridge-disposable-identity/home/.local/share',
      },
    };
    const manifest = buildApplyManifest({
      platform: 'linux', homedir: workspace.homedir, env: workspace.env, launcherBytes: launcher,
      observed: {
        config_dir: 'absent', config_file: 'absent', install_root: 'absent', bin_dir: 'absent',
        launcher: { kind: 'absent' },
      },
    });
    const request = buildHelperRequest({
      requestId: 'd'.repeat(32), workspace, manifest, launcherSha256,
      launcherByteLength: launcher.byteLength,
    });
    for (const field of ['helper_user_ns_is_init', 'peercred_uid_matches_caller_host_uid']) {
      const peerEvidence = evaluateLinuxHelperPeerEvidence(evidence({ [field]: false }));
      assert.equal(peerEvidence.different_principal, false);
      assert.throws(
        () => authorizeHelperRequest(request.bytes, {
          workspace, manifest, launcherSha256, launcherByteLength: launcher.byteLength, peerEvidence,
        }),
        (error) => error instanceof HelperProtocolError && error.code === 'peer_identity_unverified',
      );
    }
  });
});
