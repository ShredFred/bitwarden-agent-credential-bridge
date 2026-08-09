import { isLinuxSystemdBoundaryPlan } from './linux-systemd-boundary-plan.mjs';

/**
 * Phase 12b: pure non-executable Linux disposable systemd lifecycle gate.
 */

const PRE_MUTATION_STEPS = Object.freeze([
  'reverify_boundary_plan_and_reviewed_binary_unit_binding',
  'prove_fixed_account_absent',
  'prove_fixed_service_and_socket_units_absent',
  'prove_fixed_binary_and_socket_path_absent',
  'prove_parent_dirs_exist_root_owned_symlink_free_caller_write_denied',
  'select_run_private_account_identity_material',
]);

const MUTATION_STEPS = Object.freeze([
  'create_static_system_user_record',
  'reverify_account_identity_nonlogin_and_distinct_uid',
  'create_exclusive_helper_binary_via_retained_parent_fd',
  'reverify_binary_digest_owner_mode_via_retained_fd',
  'create_exclusive_service_and_socket_units_via_retained_parent_fd',
  'reverify_unit_digests_owner_mode_via_retained_fds',
  'daemon_reload_and_reverify_loaded_fragments_without_dropins',
  'start_socket_activated_denial_only_helper',
  'reverify_helper_process_uid_initial_userns_and_unit_binding',
  'exercise_value_free_different_uid_af_unix_denial',
]);

const ALWAYS_CLEANUP_STEPS = Object.freeze([
  'stop_run_owned_helper_via_systemd_if_started',
  'reverify_run_owned_helper_process_absent_or_stopping',
  'disable_and_remove_run_owned_units_if_identity_matches',
  'reverify_units_absent_after_daemon_reload',
  'unlink_run_owned_binary_via_retained_fds_if_identity_matches',
  'reverify_binary_absent_via_retained_parent_fd',
  'unlink_run_owned_socket_path_if_identity_matches',
  'delete_run_owned_account_if_identity_matches',
  'reverify_account_units_binary_and_socket_absent',
]);

const STOP_CONDITIONS = Object.freeze([
  'approval_missing_or_scope_mismatch',
  'binary_or_unit_binding_changed',
  'unexpected_account_preexists',
  'unexpected_unit_preexists',
  'unexpected_binary_or_socket_preexists',
  'elevation_not_operator_controlled',
  'parent_directory_policy_mismatch',
  'exclusive_create_collision',
  'account_identity_mismatch_after_create',
  'loaded_unit_identity_mismatch',
  'helper_process_identity_or_uid_mismatch',
  'same_host_uid_observed_when_distinct_required',
  'non_denial_response_observed',
  'cleanup_incomplete',
  'manual_recovery_required',
]);

export class LinuxSystemdLifecycleGateError extends Error {
  constructor(code) {
    super(`Linux systemd lifecycle gate rejected: ${code}`);
    this.name = 'LinuxSystemdLifecycleGateError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();

export function buildLinuxSystemdLifecycleGate(boundaryPlan) {
  if (!isLinuxSystemdBoundaryPlan(boundaryPlan)) {
    throw new LinuxSystemdLifecycleGateError('invalid_boundary_plan');
  }
  const gate = deepFreeze({
    schema_version: 1,
    platform: 'linux',
    runtime_profile: 'systemd-system',
    reviewed_bindings: {
      binary_sha256: boundaryPlan.binary.sha256,
      binary_byte_length: boundaryPlan.binary.byte_length,
      service_unit_name_fixed: true,
      socket_unit_name_fixed: true,
    },
    scope: {
      disposable_root_scope_only: true,
      systemd_system_manager_only: true,
      static_system_user_only: true,
      dynamic_user_forbidden: true,
      denial_probe_only: true,
      manifest_executor_forbidden: true,
      vault_access_forbidden: true,
      network_access_forbidden: true,
      ordinary_user_home_forbidden: true,
      abstract_socket_forbidden: true,
    },
    pre_mutation_steps: PRE_MUTATION_STEPS,
    mutation_steps: MUTATION_STEPS,
    always_cleanup_steps: ALWAYS_CLEANUP_STEPS,
    stop_conditions: STOP_CONDITIONS,
    control_flow: {
      no_mutation_before_preflight_complete: true,
      cleanup_finally_after_first_run_owned_object_created: true,
      cleanup_continues_after_individual_cleanup_failure: true,
      final_absence_check_runs_last: true,
      destructive_cleanup_requires_run_owned_retained_handle: true,
      failed_create_never_reacquires_destructive_target_by_name_or_path: true,
    },
    mutation_authorized: false,
    live_test_executed: false,
    collector_trust_verified: false,
    install_gate_eligible: false,
    authorization_ready: false,
  });
  VALID_GATES.add(gate);
  return gate;
}

export function isLinuxSystemdLifecycleGate(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
