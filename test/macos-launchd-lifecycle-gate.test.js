import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildMacosLaunchdBoundaryPlan } from '../src/macos-launchd-boundary-plan.mjs';
import {
  buildMacosLaunchdLifecycleGate,
  isMacosLaunchdLifecycleGate,
  MacosLaunchdLifecycleGateError,
} from '../src/macos-launchd-lifecycle-gate.mjs';

function boundaryPlan() {
  return buildMacosLaunchdBoundaryPlan({
    platform: 'darwin',
    serviceManager: 'launchd-system',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
    designatedRequirementSha256: 'b'.repeat(64),
    plistSha256: 'c'.repeat(64),
  });
}

describe('macOS distinct-EUID LaunchDaemon lifecycle approval gate', () => {
  it('binds every reviewed artifact to one exact denial-only lifecycle', () => {
    const gate = buildMacosLaunchdLifecycleGate(boundaryPlan());
    assert.deepEqual(gate.reviewed_bindings, {
      binary_sha256: 'a'.repeat(64),
      binary_byte_length: 4096,
      designated_requirement_sha256: 'b'.repeat(64),
      plist_sha256: 'c'.repeat(64),
    });
    assert.deepEqual(gate.pre_mutation_steps, [
      'reverify_boundary_plan_and_reviewed_binary_plist_requirement_binding',
      'prove_fixed_account_absent_by_name_and_no_conflicting_uniqueid_or_generateduid',
      'prove_fixed_plist_absent',
      'prove_fixed_binary_absent',
      'prove_fixed_launchd_label_unloaded_and_mach_service_unbound',
      'prove_parent_dirs_exist_root_owned_symlink_free_caller_write_denied',
      'select_run_private_account_identity_material',
    ]);
    assert.deepEqual(gate.mutation_steps, [
      'create_static_helper_account_record',
      'reverify_account_record_identity_shell_home_and_distinct_euid',
      'open_retained_privilegedhelpertools_parent_fd',
      'reverify_privilegedhelpertools_parent_fd_identity_and_policy',
      'create_exclusive_helper_binary_via_retained_parent_fd',
      'reverify_exclusive_binary_identity_via_retained_fds',
      'write_reviewed_binary_fsync_via_retained_file_fd',
      'reverify_binary_digest_owner_mode_and_requirement_via_retained_fd_and_private_snapshot',
      'open_retained_launchdaemons_parent_fd',
      'reverify_launchdaemons_parent_fd_identity_and_policy',
      'create_exclusive_plist_via_retained_parent_fd',
      'reverify_exclusive_plist_identity_via_retained_fds',
      'write_reviewed_plist_fsync_via_retained_file_fd',
      'reverify_plist_digest_owner_mode_and_rules_via_retained_fd',
      'bootstrap_system_domain_job_for_fixed_label',
      'reverify_loaded_job_identity_program_user_machservices_and_domain',
      'demand_activate_denial_only_helper',
      'reverify_helper_process_euid_code_requirement_and_mach_service_bound',
      'exercise_value_free_audit_trailer_distinct_euid_denial',
    ]);
    assert.deepEqual(gate.always_cleanup_steps, [
      'stop_run_owned_helper_process_via_launchd_if_started',
      'reverify_run_owned_helper_process_absent_or_stopping',
      'bootout_run_owned_system_job_if_this_run_bootstrapped_and_identity_matches',
      'reverify_fixed_label_unloaded_and_mach_service_unbound_if_run_owned',
      'unlink_run_owned_plist_via_retained_fds_if_identity_matches',
      'reverify_plist_absent_via_retained_parent_fd',
      'unlink_run_owned_binary_via_retained_fds_if_identity_matches',
      'reverify_binary_absent_via_retained_parent_fd',
      'delete_run_owned_account_record_if_generateduid_and_uniqueid_still_match',
      'reverify_account_absent_by_name_and_recorded_ids_free',
      'reverify_account_plist_binary_label_and_mach_service_absent',
    ]);
    assert.equal(Object.isFrozen(gate), true);
    assert.equal(Object.isFrozen(gate.mutation_steps), true);
  });

  it('cannot accept approval, authorize mutation, or claim live evidence', () => {
    const gate = buildMacosLaunchdLifecycleGate(boundaryPlan());
    assert.deepEqual(gate.approval, {
      explicit_operator_approval_required: true,
      elevation_scope_must_name_this_test: true,
      approval_must_be_current: true,
      approval_accepted_by_api: false,
    });
    assert.equal(gate.mutation_authorized, false);
    assert.equal(gate.live_test_executed, false);
    assert.equal(gate.collector_trust_verified, false);
    assert.equal(gate.authorization_ready, false);
    assert.equal(gate.install_gate_eligible, false);
    assert.equal(Object.values(gate.structural_claims).every((value) => value === false), true);
    assert.equal(isMacosLaunchdLifecycleGate(gate), true);
    assert.equal(isMacosLaunchdLifecycleGate(structuredClone(gate)), false);
  });

  it('encodes macOS account and launchd soft ownership without pretending fd parity', () => {
    const gate = buildMacosLaunchdLifecycleGate(boundaryPlan());
    assert.equal(gate.evidence.account_ownership_is_soft_recorded_identity_bound, true);
    assert.equal(gate.evidence.file_ownership_is_retained_fd_bound, true);
    assert.equal(gate.evidence.launchd_ownership_is_bootstrap_epoch_bound, true);
    assert.equal(gate.control_flow.destructive_cleanup_requires_run_owned_identity, true);
    assert.equal(gate.control_flow.file_mutations_require_retained_parent_and_file_fds, true);
    assert.equal(
      gate.control_flow.account_cleanup_requires_this_run_create_success_and_recorded_identity_match,
      true,
    );
    assert.equal(
      gate.control_flow.launchd_cleanup_requires_this_run_bootstrap_success_and_loaded_identity_match,
      true,
    );
    assert.equal(gate.control_flow.ambiguous_account_or_bootstrap_outcome_forbids_destructive_cleanup, true);
    assert.equal(gate.control_flow.incomplete_cleanup_requires_manual_recovery_and_never_name_based_retry, true);
  });

  it('places immediate verification after every state-changing lifecycle step', () => {
    const gate = buildMacosLaunchdLifecycleGate(boundaryPlan());
    const pairs = [
      ['create_static_helper_account_record',
        'reverify_account_record_identity_shell_home_and_distinct_euid'],
      ['open_retained_privilegedhelpertools_parent_fd',
        'reverify_privilegedhelpertools_parent_fd_identity_and_policy'],
      ['create_exclusive_helper_binary_via_retained_parent_fd',
        'reverify_exclusive_binary_identity_via_retained_fds'],
      ['write_reviewed_binary_fsync_via_retained_file_fd',
        'reverify_binary_digest_owner_mode_and_requirement_via_retained_fd_and_private_snapshot'],
      ['open_retained_launchdaemons_parent_fd',
        'reverify_launchdaemons_parent_fd_identity_and_policy'],
      ['create_exclusive_plist_via_retained_parent_fd',
        'reverify_exclusive_plist_identity_via_retained_fds'],
      ['write_reviewed_plist_fsync_via_retained_file_fd',
        'reverify_plist_digest_owner_mode_and_rules_via_retained_fd'],
      ['bootstrap_system_domain_job_for_fixed_label',
        'reverify_loaded_job_identity_program_user_machservices_and_domain'],
      ['demand_activate_denial_only_helper',
        'reverify_helper_process_euid_code_requirement_and_mach_service_bound'],
    ];
    for (const [mutation, verification] of pairs) {
      const index = gate.mutation_steps.indexOf(mutation);
      assert.ok(index >= 0, mutation);
      assert.equal(gate.mutation_steps[index + 1], verification);
    }
  });

  it('orders cleanup process then bootout then files then account then final absence', () => {
    const gate = buildMacosLaunchdLifecycleGate(boundaryPlan());
    const cleanup = gate.always_cleanup_steps;
    assert.match(cleanup[0], /^stop_run_owned_helper_process/);
    assert.match(cleanup[2], /^bootout_run_owned_system_job/);
    assert.match(cleanup[4], /^unlink_run_owned_plist/);
    assert.match(cleanup[6], /^unlink_run_owned_binary/);
    assert.match(cleanup[8], /^delete_run_owned_account_record/);
    assert.equal(cleanup.at(-1), 'reverify_account_plist_binary_label_and_mach_service_absent');
    assert.equal(gate.control_flow.account_deletion_is_last_destructive_step, true);
    assert.equal(gate.control_flow.process_stop_before_bootout_before_file_unlink_before_account_delete, true);
    assert.equal(gate.control_flow.final_absence_check_runs_last, true);
    assert.equal(gate.control_flow.cleanup_continues_after_individual_cleanup_failure, true);
  });

  it('makes collisions non-owned and forbids destructive retry by fixed name or path', () => {
    const gate = buildMacosLaunchdLifecycleGate(boundaryPlan());
    assert.equal(
      gate.control_flow.collision_or_preexisting_object_aborts_without_destructive_cleanup_of_that_object,
      true,
    );
    assert.equal(gate.control_flow.failed_file_create_never_reacquires_destructive_target_by_path, true);
    for (const step of gate.always_cleanup_steps.filter((step) =>
      /^(stop|bootout|unlink|delete)_/.test(step))) {
      assert.match(step, /run_owned/);
    }
    assert.ok(gate.stop_conditions.includes('destructive_target_ownership_ambiguous'));
    assert.ok(gate.stop_conditions.includes('manual_recovery_required'));
  });

  it('keeps the gate value-free and forbids credentials, network, and user-home targets', () => {
    const gate = buildMacosLaunchdLifecycleGate(boundaryPlan());
    for (const field of [
      'manifest_executor_forbidden', 'vault_access_forbidden', 'keychain_access_forbidden',
      'network_access_forbidden', 'ordinary_user_home_targets_forbidden',
      'keep_alive_and_timers_forbidden',
    ]) assert.equal(gate.scope[field], true, field);
    const serialized = JSON.stringify(gate).toLowerCase();
    for (const forbidden of [
      '_bwagentbridge', '/library/', '/users/', 'launchctl', 'dscl', 'sudo',
      'password_value', 'credential_ref', 'uid_value', 'guid_value', 'audit_token_value',
    ]) assert.equal(serialized.includes(forbidden), false, forbidden);
  });

  it('rejects cloned, spread, proxied, accessor-backed, and forged plans', () => {
    const valid = boundaryPlan();
    const accessor = {};
    Object.defineProperty(accessor, 'binary', { enumerable: true, get: () => valid.binary });
    for (const input of [
      structuredClone(valid), { ...valid }, new Proxy(valid, {}),
      { ...valid, approval: true }, accessor, null,
    ]) {
      assert.throws(
        () => buildMacosLaunchdLifecycleGate(input),
        (error) => error instanceof MacosLaunchdLifecycleGateError &&
          error.code === 'invalid_boundary_plan',
      );
    }
  });
});
