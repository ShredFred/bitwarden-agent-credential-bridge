import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildWindowsServiceBoundaryPlan,
  WindowsServiceBoundaryPlanError,
} from '../src/windows-service-boundary-plan.mjs';

function valid(overrides = {}) {
  return { platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096, ...overrides };
}

describe('Windows passwordless service boundary plan', () => {
  it('pins a demand-start LocalService helper without credential or network access', () => {
    const plan = buildWindowsServiceBoundaryPlan(valid());
    assert.deepEqual(plan.service, {
      name: 'BitwardenAgentCredentialBridgeHelper',
      account: 'NT AUTHORITY\\LocalService',
      password_required: false,
      sid_type: 'unrestricted',
      start_type: 'demand',
      network_access_required: false,
      vault_access_required: false,
      token_user_must_be_local_service: true,
      service_sid_token_group_required: true,
      caller_change_config_denied_required: true,
    });
    assert.equal(plan.ipc.remote_clients_rejected, true);
    assert.equal(plan.ipc.server_pid_token_binding_required, true);
    assert.equal(plan.ipc.server_service_sid_group_required, true);
    assert.equal(plan.target_acl.caller_write_denied_required, true);
    assert.equal(plan.target_acl.trusted_or_expected_service_sid_owned_root_required, true);
    assert.equal(plan.target_acl.shared_local_service_token_user_owner_forbidden, true);
    assert.equal(plan.target_acl.caller_owner_forbidden, true);
    assert.equal(plan.target_acl.caller_write_dac_denied_required, true);
    assert.equal(plan.target_acl.caller_write_owner_denied_required, true);
    assert.equal(plan.target_acl.caller_delete_denied_required, true);
    assert.equal(plan.target_acl.ancestor_delete_child_denied_required, true);
    assert.equal(plan.target_acl.ordinary_user_profile_root_forbidden, true);
    assert.equal(plan.target_acl.service_sid_write_allowed_required, true);
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(JSON.stringify(plan).toLowerCase().includes('password_value'), false);
    assert.equal(JSON.stringify(plan).toLowerCase().includes('command'), false);
  });

  it('binds the reviewed binary and every mutable security gate', () => {
    const plan = buildWindowsServiceBoundaryPlan(valid());
    assert.deepEqual(plan.binary, {
      sha256: 'a'.repeat(64),
      byte_length: 4096,
      signature_policy: 'pinned_digest_and_operator_review',
      installed_digest_reverified_required: true,
      caller_write_denied_required: true,
      parent_chain_reparse_free_required: true,
    });
    assert.deepEqual(plan.approval_gates, [
      'operator_reviewed_binary',
      'operator_approved_elevation',
      'service_configuration_reverified',
      'service_object_dacl_reverified',
      'binary_path_acl_reverified',
      'target_ownership_and_control_rights_reverified',
      'pipe_acl_reverified',
      'pipe_server_identity_reverified',
      'different_token_user_reverified',
      'disposable_apply_rollback_verified',
      'cleanup_verified',
    ]);
  });

  it('rejects other platforms, unknown fields, accessors, and invalid binary bindings', () => {
    const accessor = valid();
    Object.defineProperty(accessor, 'binarySha256', { get: () => 'a'.repeat(64), enumerable: true });
    for (const input of [
      valid({ platform: 'linux' }),
      { ...valid(), account: 'caller-selected' },
      accessor,
      valid({ binarySha256: 'A'.repeat(64) }),
      valid({ binarySha256: { toString: () => 'a'.repeat(64) } }),
      valid({ platform: { toString: () => 'win32' } }),
      valid({ binaryByteLength: 0 }),
      valid({ binaryByteLength: 64 * 1024 * 1024 + 1 }),
    ]) {
      assert.throws(
        () => buildWindowsServiceBoundaryPlan(input),
        (error) => error instanceof WindowsServiceBoundaryPlanError,
      );
    }
  });
});
