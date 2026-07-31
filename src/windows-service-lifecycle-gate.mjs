import { isWindowsServiceBoundaryPlan } from './windows-service-boundary-plan.mjs';

const PRE_MUTATION_STEPS = Object.freeze([
  'reverify_boundary_plan_and_reviewed_binary_binding',
  'prove_fixed_service_and_fixed_pipe_absent',
  'select_fresh_disposable_admin_root',
  'prove_disposable_root_and_binary_absent',
]);

const MUTATION_STEPS = Object.freeze([
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

const ALWAYS_CLEANUP_STEPS = Object.freeze([
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

const STOP_CONDITIONS = Object.freeze([
  'approval_missing_or_scope_mismatch',
  'binary_binding_changed',
  'unexpected_service_preexists',
  'elevation_not_operator_controlled',
  'service_configuration_mismatch',
  'service_or_binary_acl_mismatch',
  'server_identity_mismatch',
  'non_denial_response_observed',
  'cleanup_incomplete',
]);

export class WindowsServiceLifecycleGateError extends Error {
  constructor(code) {
    super(`Windows service lifecycle gate rejected: ${code}`);
    this.name = 'WindowsServiceLifecycleGateError';
    this.code = code;
  }
}

const VALID_GATES = new WeakSet();

/**
 * Create the non-executable approval envelope for a future elevated disposable
 * SCM test. Approval itself is deliberately not accepted as data by this API.
 */
export function buildWindowsServiceLifecycleGate(boundaryPlan) {
  if (!isWindowsServiceBoundaryPlan(boundaryPlan)) {
    throw new WindowsServiceLifecycleGateError('invalid_boundary_plan');
  }
  const gate = deepFreeze({
    schema_version: 1,
    platform: 'win32',
    service_name_fixed: true,
    binary_binding: {
      sha256: boundaryPlan.binary.sha256,
      byte_length: boundaryPlan.binary.byte_length,
    },
    scope: {
      disposable_admin_root_only: true,
      local_service_only: true,
      demand_start_only: true,
      denial_probe_only: true,
      manifest_executor_forbidden: true,
      vault_access_forbidden: true,
      network_access_forbidden: true,
      normal_user_roots_forbidden: true,
    },
    pre_mutation_steps: PRE_MUTATION_STEPS,
    mutation_steps: MUTATION_STEPS,
    always_cleanup_steps: ALWAYS_CLEANUP_STEPS,
    control_flow: {
      no_mutation_before_preflight_complete: true,
      cleanup_finally_after_first_run_owned_object_created: true,
      cleanup_continues_after_individual_cleanup_failure: true,
      final_absence_check_runs_last: true,
      destructive_cleanup_requires_run_owned_retained_handle: true,
      failed_create_never_reacquires_destructive_target_by_name_or_path: true,
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
      raw_paths_sids_acls_commands_and_output_forbidden: true,
    },
    mutation_authorized: false,
    live_test_executed: false,
    install_gate_eligible: false,
  });
  VALID_GATES.add(gate);
  return gate;
}

export function isWindowsServiceLifecycleGate(value) {
  return value !== null && typeof value === 'object' && VALID_GATES.has(value);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
