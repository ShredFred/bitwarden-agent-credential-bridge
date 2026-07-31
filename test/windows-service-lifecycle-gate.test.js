import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import {
  buildWindowsServiceLifecycleGate,
  isWindowsServiceLifecycleGate,
  WindowsServiceLifecycleGateError,
} from '../src/windows-service-lifecycle-gate.mjs';

function boundaryPlan() {
  return buildWindowsServiceBoundaryPlan({
    platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
  });
}

describe('Windows disposable service lifecycle approval gate', () => {
  it('binds one reviewed binary to a denial-only install/start/remove sequence', () => {
    const gate = buildWindowsServiceLifecycleGate(boundaryPlan());
    assert.deepEqual(gate.binary_binding, { sha256: 'a'.repeat(64), byte_length: 4096 });
    assert.deepEqual(gate.pre_mutation_steps, [
      'reverify_boundary_plan_and_reviewed_binary_binding',
      'prove_fixed_service_and_fixed_pipe_absent',
      'select_fresh_disposable_admin_root',
      'prove_disposable_root_and_binary_absent',
    ]);
    assert.deepEqual(gate.mutation_steps, [
      'stage_reviewed_binary_and_retain_root_binary_handles',
      'reverify_staged_root_and_binary_handle_identity_digest_and_acl',
      'create_fixed_demand_start_local_service_and_retain_handle',
      'reverify_created_service_identity_and_config_via_retained_handle',
      'set_unrestricted_fixed_service_sid_via_retained_handle',
      'reverify_service_sid_via_retained_handle',
      'lock_service_object_acl_via_retained_handle',
      'reverify_service_object_acl_via_retained_handle',
      'lock_binary_chain_via_retained_file_handles',
      'reverify_binary_chain_via_retained_file_handles',
      'start_fixed_service_via_retained_handle',
      'reverify_running_service_and_server_identity',
      'exercise_value_free_different_principal_denial',
    ]);
    assert.deepEqual(gate.always_cleanup_steps, [
      'stop_run_owned_service_via_retained_handle_if_started',
      'reverify_run_owned_service_stopped_via_retained_handle',
      'delete_run_owned_service_via_retained_handle_if_identity_matches',
      'reverify_run_owned_service_delete_pending_or_absent_via_retained_handle',
      'remove_run_owned_binary_via_retained_handle_if_identity_matches',
      'reverify_run_owned_binary_absent_via_retained_parent_handle',
      'remove_run_owned_root_via_retained_handle_if_identity_matches',
      'reverify_run_owned_root_absent_via_retained_parent_handle',
      'reverify_service_binary_root_and_pipe_absent',
    ]);
    assert.equal(gate.scope.manifest_executor_forbidden, true);
    assert.equal(gate.scope.vault_access_forbidden, true);
    assert.equal(gate.scope.normal_user_roots_forbidden, true);
    assert.equal(Object.isFrozen(gate), true);
    assert.equal(Object.isFrozen(gate.mutation_steps), true);
    assert.equal(gate.control_flow.no_mutation_before_preflight_complete, true);
    assert.equal(gate.control_flow.cleanup_finally_after_first_run_owned_object_created, true);
    assert.equal(gate.control_flow.cleanup_continues_after_individual_cleanup_failure, true);
    assert.equal(gate.control_flow.destructive_cleanup_requires_run_owned_retained_handle, true);
    assert.equal(gate.control_flow.failed_create_never_reacquires_destructive_target_by_name_or_path, true);
  });

  it('cannot encode approval or authorize mutation', () => {
    const gate = buildWindowsServiceLifecycleGate(boundaryPlan());
    assert.deepEqual(gate.approval, {
      explicit_operator_approval_required: true,
      elevation_scope_must_name_this_test: true,
      approval_must_be_current: true,
      approval_accepted_by_api: false,
    });
    assert.equal(gate.mutation_authorized, false);
    assert.equal(gate.live_test_executed, false);
    assert.equal(gate.install_gate_eligible, false);
    assert.equal(isWindowsServiceLifecycleGate(gate), true);
    assert.equal(isWindowsServiceLifecycleGate(structuredClone(gate)), false);
    const serialized = JSON.stringify(gate).toLowerCase();
    for (const forbidden of ['password_value', '"command"', 'powershell', 'sc.exe', 'sid_value', 'path_value']) {
      assert.equal(serialized.includes(forbidden), false, forbidden);
    }
  });

  it('encodes cleanup as a finally path after every partial activation outcome', () => {
    const gate = buildWindowsServiceLifecycleGate(boundaryPlan());
    for (const failurePoint of [
      'stage_reviewed_binary_and_retain_root_binary_handles',
      'create_fixed_demand_start_local_service_and_retain_handle',
      'start_fixed_service_via_retained_handle',
      'reverify_running_service_and_server_identity',
      'exercise_value_free_different_principal_denial',
    ]) {
      assert.ok(gate.mutation_steps.includes(failurePoint));
      assert.equal(gate.control_flow.cleanup_finally_after_first_run_owned_object_created, true);
      assert.equal(gate.always_cleanup_steps.at(-1), 'reverify_service_binary_root_and_pipe_absent');
    }
  });

  it('never cleans up colliding service or root objects that this run did not create', () => {
    const gate = buildWindowsServiceLifecycleGate(boundaryPlan());
    assert.equal(gate.control_flow.destructive_cleanup_requires_run_owned_retained_handle, true);
    assert.equal(gate.control_flow.failed_create_never_reacquires_destructive_target_by_name_or_path, true);
    for (const step of gate.always_cleanup_steps.slice(0, -1)) {
      assert.match(step, /run_owned|retained_handle|retained_parent_handle/);
    }
  });

  it('places native re-verification after each service and ACL mutation', () => {
    const gate = buildWindowsServiceLifecycleGate(boundaryPlan());
    const pairs = [
      ['stage_reviewed_binary_and_retain_root_binary_handles',
        'reverify_staged_root_and_binary_handle_identity_digest_and_acl'],
      ['create_fixed_demand_start_local_service_and_retain_handle',
        'reverify_created_service_identity_and_config_via_retained_handle'],
      ['set_unrestricted_fixed_service_sid_via_retained_handle',
        'reverify_service_sid_via_retained_handle'],
      ['lock_service_object_acl_via_retained_handle',
        'reverify_service_object_acl_via_retained_handle'],
      ['lock_binary_chain_via_retained_file_handles',
        'reverify_binary_chain_via_retained_file_handles'],
    ];
    for (const [mutation, verification] of pairs) {
      const index = gate.mutation_steps.indexOf(mutation);
      assert.ok(index >= 0);
      assert.equal(gate.mutation_steps[index + 1], verification);
    }
  });

  it('places retained-handle verification after each destructive cleanup mutation', () => {
    const gate = buildWindowsServiceLifecycleGate(boundaryPlan());
    const pairs = [
      ['stop_run_owned_service_via_retained_handle_if_started',
        'reverify_run_owned_service_stopped_via_retained_handle'],
      ['delete_run_owned_service_via_retained_handle_if_identity_matches',
        'reverify_run_owned_service_delete_pending_or_absent_via_retained_handle'],
      ['remove_run_owned_binary_via_retained_handle_if_identity_matches',
        'reverify_run_owned_binary_absent_via_retained_parent_handle'],
      ['remove_run_owned_root_via_retained_handle_if_identity_matches',
        'reverify_run_owned_root_absent_via_retained_parent_handle'],
    ];
    for (const [mutation, verification] of pairs) {
      const index = gate.always_cleanup_steps.indexOf(mutation);
      assert.ok(index >= 0);
      assert.equal(gate.always_cleanup_steps[index + 1], verification);
    }
  });

  it('rejects copied, forged, extended, and accessor-backed lookalikes', () => {
    const valid = boundaryPlan();
    const accessor = {};
    Object.defineProperty(accessor, 'binary', { get: () => valid.binary, enumerable: true });
    for (const input of [structuredClone(valid), { ...valid }, { ...valid, approval: true }, accessor, null]) {
      assert.throws(
        () => buildWindowsServiceLifecycleGate(input),
        (error) => error instanceof WindowsServiceLifecycleGateError &&
          error.code === 'invalid_boundary_plan',
      );
    }
  });
});
