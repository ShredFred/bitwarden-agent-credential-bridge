import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { buildApplyManifest } from '../src/apply-manifest.mjs';
import { authorizeHelperRequest, buildHelperRequest, HelperProtocolError } from '../src/helper-protocol.mjs';
import {
  evaluateMacosHelperPeerEvidence,
  MacosHelperEvidenceError,
} from '../src/macos-helper-evidence.mjs';

const callerDigest = createHash('sha256').update('euid:501').digest('hex');
const helperDigest = createHash('sha256').update('euid:0').digest('hex');

function evidence(overrides = {}) {
  return {
    schema_version: 1,
    transport_kind: 'macos_xpc_mach_service',
    mach_service_bound: true,
    xpc_peer_connection_verified: true,
    peer_audit_token_verified: true,
    peer_pid_verified: true,
    peer_pidversion_verified: true,
    helper_pid_verified: true,
    helper_pidversion_verified: true,
    caller_audit_token_verified: true,
    helper_audit_token_verified: true,
    caller_euid_verified: true,
    helper_euid_verified: true,
    audit_token_euid_matches_caller_euid: true,
    audit_token_euid_matches_helper_euid: true,
    helper_code_identity_verified: true,
    helper_code_requirement_satisfied: true,
    caller_euid_sha256: callerDigest,
    helper_euid_sha256: helperDigest,
    target_access_checked_symlink_safe: true,
    access_checks_verified: true,
    all_targets_checked: true,
    caller_effective_write_denied: true,
    helper_required_write_allowed: true,
    caller_app_sandbox_active: true,
    helper_app_sandbox_active: true,
    caller_hardened_runtime: true,
    helper_hardened_runtime: true,
    caller_code_signature_valid: true,
    caller_code_requirement_differs: true,
    caller_audit_session_differs: true,
    caller_sandbox_blocks_some_writes: true,
    ...overrides,
  };
}

function protocolFixture() {
  const launcher = Buffer.from('fake macOS helper launcher');
  const launcherSha256 = createHash('sha256').update(launcher).digest('hex');
  const workspace = {
    platform: 'darwin', root: '/tmp/bw-agent-bridge-disposable-test', nonce: 'a'.repeat(64),
    homedir: '/tmp/bw-agent-bridge-disposable-test/home', env: {},
  };
  const manifest = buildApplyManifest({
    platform: workspace.platform, homedir: workspace.homedir, env: workspace.env,
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
  return { launcherSha256, launcherByteLength: launcher.byteLength, workspace, manifest, request };
}

function authorizationContext(fixture, peerEvidence) {
  return {
    workspace: fixture.workspace,
    manifest: fixture.manifest,
    launcherSha256: fixture.launcherSha256,
    launcherByteLength: fixture.launcherByteLength,
    peerEvidence,
  };
}

describe('macOS helper peer-evidence evaluator', () => {
  it('returns only five value-free authorization booleans for distinct effective UIDs', () => {
    const result = evaluateMacosHelperPeerEvidence(evidence());
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

  it('never treats sandbox, signing, hardened runtime, or audit session as a different principal', () => {
    const result = evaluateMacosHelperPeerEvidence(evidence({ helper_euid_sha256: callerDigest }));
    assert.equal(result.identity_verified, true);
    assert.equal(result.different_principal, false);
    assert.equal(JSON.stringify(result).includes(callerDigest), false);
  });

  it('keeps defense-in-depth facts separate from effective-UID identity', () => {
    const result = evaluateMacosHelperPeerEvidence(evidence({
      caller_app_sandbox_active: false,
      helper_app_sandbox_active: false,
      caller_hardened_runtime: false,
      helper_hardened_runtime: false,
      caller_code_signature_valid: false,
      caller_code_requirement_differs: false,
      caller_audit_session_differs: false,
      caller_sandbox_blocks_some_writes: false,
    }));
    assert.equal(result.identity_verified, true);
    assert.equal(result.different_principal, true);
  });

  it('fails every transport and identity proof closed independently', () => {
    for (const field of [
      'mach_service_bound', 'xpc_peer_connection_verified', 'peer_audit_token_verified',
      'peer_pid_verified', 'peer_pidversion_verified', 'helper_pid_verified', 'helper_pidversion_verified',
    ]) {
      assert.equal(evaluateMacosHelperPeerEvidence(evidence({ [field]: false })).local_transport, false);
    }
    for (const field of [
      'caller_audit_token_verified', 'helper_audit_token_verified', 'caller_euid_verified',
      'helper_euid_verified', 'audit_token_euid_matches_caller_euid',
      'audit_token_euid_matches_helper_euid',
      'helper_code_identity_verified', 'helper_code_requirement_satisfied',
    ]) {
      const result = evaluateMacosHelperPeerEvidence(evidence({ [field]: false }));
      assert.equal(result.identity_verified, false);
      assert.equal(result.different_principal, false);
    }
  });

  it('requires complete symlink-safe access checks for both write claims', () => {
    for (const field of ['target_access_checked_symlink_safe', 'access_checks_verified', 'all_targets_checked']) {
      const result = evaluateMacosHelperPeerEvidence(evidence({ [field]: false }));
      assert.equal(result.caller_write_denied, false);
      assert.equal(result.helper_write_allowed, false);
    }
    assert.equal(evaluateMacosHelperPeerEvidence(evidence({ caller_effective_write_denied: false })).caller_write_denied, false);
    assert.equal(evaluateMacosHelperPeerEvidence(evidence({ helper_required_write_allowed: false })).helper_write_allowed, false);
  });

  it('rejects missing, extra, accessor, proxy, non-boolean, raw-EUID, and wrong-transport evidence', () => {
    const missing = evidence();
    delete missing.mach_service_bound;
    const accessor = evidence();
    Object.defineProperty(accessor, 'helper_euid_verified', { get: () => true });
    for (const invalid of [
      null, missing, { ...evidence(), raw_euid: 501 }, accessor, new Proxy(evidence(), {}),
      evidence({ caller_hardened_runtime: 1 }), evidence({ caller_euid_sha256: '0' }),
      evidence({ transport_kind: 'tcp' }),
    ]) {
      assert.throws(
        () => evaluateMacosHelperPeerEvidence(invalid),
        (error) => error instanceof MacosHelperEvidenceError && error.code === 'peer_identity_unverified',
      );
    }
  });

  it('snapshots validated facts without consulting a poisoned Object.prototype', () => {
    let getterCalls = 0;
    let setterCalls = 0;
    const priorDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'helper_euid_verified');
    Object.defineProperty(Object.prototype, 'helper_euid_verified', {
      configurable: true,
      get() { getterCalls += 1; return true; },
      set() { setterCalls += 1; },
    });
    try {
      const result = evaluateMacosHelperPeerEvidence(evidence({ helper_euid_verified: false }));
      assert.equal(result.identity_verified, false);
      assert.equal(result.different_principal, false);
      assert.equal(getterCalls, 0);
      assert.equal(setterCalls, 0);
    } finally {
      if (priorDescriptor === undefined) delete Object.prototype.helper_euid_verified;
      else Object.defineProperty(Object.prototype, 'helper_euid_verified', priorDescriptor);
    }
  });

  it('feeds the helper protocol and rejects the same effective UID before apply', () => {
    const fixture = protocolFixture();
    const peerEvidence = evaluateMacosHelperPeerEvidence(evidence({ helper_euid_sha256: callerDigest }));
    assert.throws(
      () => authorizeHelperRequest(fixture.request.bytes, authorizationContext(fixture, peerEvidence)),
      (error) => error instanceof HelperProtocolError && error.code === 'same_principal_rejected',
    );
  });

  it('makes protocol authorization fail identity-first without the helper code requirement', () => {
    const fixture = protocolFixture();
    const peerEvidence = evaluateMacosHelperPeerEvidence(evidence({ helper_code_requirement_satisfied: false }));
    assert.throws(
      () => authorizeHelperRequest(fixture.request.bytes, authorizationContext(fixture, peerEvidence)),
      (error) => error instanceof HelperProtocolError && error.code === 'peer_identity_unverified',
    );
  });

  it('makes protocol authorization reject an unbound Mach-service transport', () => {
    const fixture = protocolFixture();
    const peerEvidence = evaluateMacosHelperPeerEvidence(evidence({ mach_service_bound: false }));
    assert.throws(
      () => authorizeHelperRequest(fixture.request.bytes, authorizationContext(fixture, peerEvidence)),
      (error) => error instanceof HelperProtocolError && error.code === 'peer_identity_unverified',
    );
  });
});
