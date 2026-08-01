import { isMacosLaunchdBoundaryPlan } from './macos-launchd-boundary-plan.mjs';

const PRE_MUTATION_STEPS = Object.freeze([
  'reverify_boundary_plan_and_reviewed_binary_plist_requirement_binding',
  'prove_fixed_account_absent_by_name_and_no_conflicting_uniqueid_or_generateduid',
  'prove_fixed_plist_absent',
  'prove_fixed_binary_absent',
  'prove_fixed_launchd_label_unloaded_and_mach_service_unbound',
  'prove_parent_dirs_exist_root_owned_symlink_free_caller_write_denied',
  'select_run_private_account_identity_material',
]);

const MUTATION_STEPS = Object.freeze([
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

const ALWAYS_CLEANUP_STEPS = Object.freeze([
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

const STOP_CONDITIONS = Object.freeze([
  'approval_missing_or_scope_mismatch',
  'binary_plist_or_requirement_binding_changed',
  'unexpected_account_preexists_or_id_collision',
  'unexpected_plist_preexists',
  'unexpected_binary_preexists',
  'unexpected_launchd_label_or_mach_service_preexists',
  'elevation_not_operator_controlled',
  'parent_directory_policy_mismatch',
  'exclusive_create_collision',
  'account_identity_mismatch_after_create',
  'file_identity_digest_owner_or_mode_mismatch',
  'requirement_snapshot_mismatch',
  'loaded_job_identity_mismatch',
  'helper_process_identity_or_euid_mismatch',
  'non_denial_response_observed',
  'same_euid_observed_when_distinct_required',
  'destructive_target_ownership_ambiguous',
  'cleanup_incomplete',
  'manual_recovery_required',
]);

const VALID_GATES = new WeakSet();

export class MacosLaunchdLifecycleGateError extends Error {
  constructor(code) {
    super(`macOS launchd lifecycle gate rejected: ${code}`);
    this.name = 'MacosLaunchdLifecycleGateError';
    this.code = code;
  }
}

/**
 * Freeze the non-executable contract for a future operator-approved macOS
 * system-account/LaunchDaemon denial lifecycle. Approval is never API input.
 */
export function buildMacosLaunchdLifecycleGate(boundaryPlan) {
  if (!isMacosLaunchdBoundaryPlan(boundaryPlan)) {
    throw new MacosLaunchdLifecycleGateError('invalid_boundary_plan');
  }
  const gate = deepFreeze({
    schema_version: 1,
    platform: 'darwin',
    fixed_identities: {
      account_name_fixed: true,
      binary_path_fixed: true,
      plist_path_fixed: true,
      service_label_fixed: true,
      mach_service_fixed: true,
    },
    reviewed_bindings: {
      binary_sha256: boundaryPlan.binary.sha256,
      binary_byte_length: boundaryPlan.binary.byte_length,
      designated_requirement_sha256: boundaryPlan.binary.designated_requirement_sha256,
      plist_sha256: boundaryPlan.daemon.sha256,
    },
    scope: {
      system_domain_launchd_only: true,
      static_hidden_nonlogin_account_only: true,
      privileged_helper_tools_binary_only: true,
      launchdaemons_plist_only: true,
      production_mach_service_name_required: true,
      denial_probe_only: true,
      manifest_executor_forbidden: true,
      vault_access_forbidden: true,
      keychain_access_forbidden: true,
      network_access_forbidden: true,
      ordinary_user_home_targets_forbidden: true,
      keep_alive_and_timers_forbidden: true,
    },
    pre_mutation_steps: PRE_MUTATION_STEPS,
    mutation_steps: MUTATION_STEPS,
    always_cleanup_steps: ALWAYS_CLEANUP_STEPS,
    control_flow: {
      no_mutation_before_preflight_complete: true,
      cleanup_finally_after_first_run_owned_object_created: true,
      cleanup_continues_after_individual_cleanup_failure: true,
      final_absence_check_runs_last: true,
      destructive_cleanup_requires_run_owned_identity: true,
      failed_file_create_never_reacquires_destructive_target_by_path: true,
      file_mutations_require_retained_parent_and_file_fds: true,
      account_cleanup_requires_this_run_create_success_and_recorded_identity_match: true,
      launchd_cleanup_requires_this_run_bootstrap_success_and_loaded_identity_match: true,
      ambiguous_account_or_bootstrap_outcome_forbids_destructive_cleanup: true,
      account_deletion_is_last_destructive_step: true,
      process_stop_before_bootout_before_file_unlink_before_account_delete: true,
      collision_or_preexisting_object_aborts_without_destructive_cleanup_of_that_object: true,
      incomplete_cleanup_requires_manual_recovery_and_never_name_based_retry: true,
    },
    stop_conditions: STOP_CONDITIONS,
    approval: {
      explicit_operator_approval_required: true,
      elevation_scope_must_name_this_test: true,
      approval_must_be_current: true,
      approval_accepted_by_api: false,
    },
    evidence: {
      pre_state_required: true,
      every_mutation_reverified: true,
      cleanup_attempted_after_any_activation: true,
      cleanup_absence_proof_required: true,
      raw_paths_uids_guids_audit_tokens_commands_and_output_forbidden: true,
      account_ownership_is_soft_recorded_identity_bound: true,
      file_ownership_is_retained_fd_bound: true,
      launchd_ownership_is_bootstrap_epoch_bound: true,
    },
    structural_claims: {
      preflight_absence_verified: false,
      account_created_and_reverified: false,
      binary_published_and_reverified: false,
      plist_published_and_reverified: false,
      job_bootstrapped_and_loaded_identity_verified: false,
      distinct_euid_denial_verified: false,
      cleanup_sequence_attempted: false,
      final_absence_verified: false,
    },
    mutation_authorized: false,
    live_test_executed: false,
    collector_trust_verified: false,
    authorization_ready: false,
    install_gate_eligible: false,
  });
  VALID_GATES.add(gate);
  return gate;
}

export function isMacosLaunchdLifecycleGate(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
