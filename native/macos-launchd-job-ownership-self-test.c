#include "macos-launchd-job-ownership.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  bool present;
  bool process_running;
  bool drift_after_bootstrap;
  bool drift_inside_bootout;
  bool stop_fails;
  bw_job_result activation_result;
  bool bootstrap_called;
  bool stop_called;
  bool bootout_called;
  bool denial_called;
  bw_launchd_job_record record;
} fake_launchd;

static bool same(const bw_launchd_job_record *left, const bw_launchd_job_record *right) {
  return strcmp(left->label, right->label) == 0 && strcmp(left->program, right->program) == 0 &&
      strcmp(left->user_name, right->user_name) == 0 &&
      strcmp(left->mach_service, right->mach_service) == 0 &&
      strcmp(left->binary_sha256, right->binary_sha256) == 0 &&
      strcmp(left->plist_sha256, right->plist_sha256) == 0 &&
      left->demand_activation_only == right->demand_activation_only;
}

static bw_launchd_probe probe_label(void *raw, const char *label) {
  fake_launchd *state = raw;
  return state->present && strcmp(state->record.label, label) == 0
      ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_ABSENT;
}

static bw_launchd_probe probe_mach(void *raw, const char *name) {
  fake_launchd *state = raw;
  return state->present && strcmp(state->record.mach_service, name) == 0
      ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_ABSENT;
}

static bw_job_result bootstrap(void *raw, const bw_launchd_job_record *record) {
  fake_launchd *state = raw;
  state->bootstrap_called = true;
  if (state->present) return BW_JOB_NO_EFFECT;
  state->record = *record;
  state->present = true;
  if (state->drift_after_bootstrap) state->record.binary_sha256[0] = 'b';
  return BW_JOB_OK;
}

static bool read_job(void *raw, const char *label, bw_launchd_job_record *record) {
  fake_launchd *state = raw;
  if (!state->present || strcmp(state->record.label, label) != 0) return false;
  *record = state->record;
  return true;
}

static bw_job_result activate(void *raw, const bw_launchd_job_record *record) {
  fake_launchd *state = raw;
  if (!state->present || !same(&state->record, record)) return BW_JOB_AMBIGUOUS;
  if (state->activation_result == BW_JOB_OK || state->activation_result == BW_JOB_AMBIGUOUS) {
    state->process_running = true;
  }
  return state->activation_result;
}

static bool verify_process(void *raw, const bw_launchd_job_record *record) {
  fake_launchd *state = raw;
  return state->process_running && state->present && same(&state->record, record);
}

static bool exercise_denial(void *raw, const bw_launchd_job_record *record) {
  fake_launchd *state = raw;
  state->denial_called = true;
  return verify_process(raw, record);
}

static bw_job_result stop_process(void *raw, const bw_launchd_job_record *record) {
  fake_launchd *state = raw;
  state->stop_called = true;
  if (!state->present || !same(&state->record, record)) return BW_JOB_AMBIGUOUS;
  if (state->stop_fails) return BW_JOB_AMBIGUOUS;
  state->process_running = false;
  return BW_JOB_OK;
}

static bw_job_result bootout(void *raw, const bw_launchd_job_record *record) {
  fake_launchd *state = raw;
  state->bootout_called = true;
  if (state->drift_inside_bootout) state->record.plist_sha256[0] = 'c';
  if (!state->present || !same(&state->record, record)) return BW_JOB_AMBIGUOUS;
  state->present = false;
  state->process_running = false;
  return BW_JOB_OK;
}

static bw_launchd_ops ops(fake_launchd *state) {
  bw_launchd_ops value = {
    .context = state,
    .probe_label = probe_label,
    .probe_mach_service = probe_mach,
    .bootstrap = bootstrap,
    .read_job = read_job,
    .activate = activate,
    .verify_process = verify_process,
    .exercise_denial = exercise_denial,
    .stop_process = stop_process,
    .bootout = bootout,
  };
  return value;
}

static bw_launchd_job_record candidate(void) {
  bw_launchd_job_record value = {
    .label = "de.frederikstadler.bitwarden-agent-credential-bridge.helper",
    .program = "/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.helper",
    .user_name = "_bwagentbridge",
    .mach_service = "de.frederikstadler.bitwarden-agent-credential-bridge.helper",
    .binary_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    .plist_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    .demand_activation_only = true,
  };
  return value;
}

static bool prepare_bootstrap(fake_launchd *state, bw_owned_launchd_job *owned) {
  bw_launchd_ops value_ops = ops(state);
  bw_launchd_job_record value = candidate();
  bw_init_owned_launchd_job(owned);
  return bw_prepare_owned_launchd_job(&value_ops, &value, owned) == BW_JOB_OK &&
      bw_bootstrap_owned_launchd_job(&value_ops, owned) == BW_JOB_OK;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 2;
  bool clean_denial_cleanup = false;
  bool collision_no_effect = false;
  bool bootstrap_drift_not_owned = false;
  bool ambiguous_activation_cleaned = false;
  bool activation_error_cleaned = false;
  bool foreign_swap_preserved = false;
  bool bootout_race_preserved = false;
  bool cleanup_continues_after_stop_failure = false;

  fake_launchd clean = {.activation_result = BW_JOB_OK};
  bw_launchd_ops clean_ops = ops(&clean);
  bw_launchd_job_record value = candidate();
  bw_owned_launchd_job clean_owned;
  bw_init_owned_launchd_job(&clean_owned);
  clean_denial_cleanup = bw_prepare_owned_launchd_job(&clean_ops, &value, &clean_owned) == BW_JOB_OK &&
      bw_bootstrap_owned_launchd_job(&clean_ops, &clean_owned) == BW_JOB_OK &&
      bw_activate_and_verify_owned_launchd_job(&clean_ops, &clean_owned) == BW_JOB_OK &&
      bw_exercise_owned_launchd_denial(&clean_ops, &clean_owned) == BW_JOB_OK &&
      bw_cleanup_owned_launchd_job(&clean_ops, &clean_owned) == BW_JOB_OK &&
      clean.denial_called && clean.stop_called && clean.bootout_called && !clean.present;

  fake_launchd collision = {.present = true, .record = candidate()};
  bw_launchd_ops collision_ops = ops(&collision);
  bw_owned_launchd_job collision_owned;
  bw_init_owned_launchd_job(&collision_owned);
  collision_no_effect = bw_prepare_owned_launchd_job(
      &collision_ops, &value, &collision_owned) == BW_JOB_NO_EFFECT &&
      !collision.bootstrap_called && !collision.bootout_called;

  fake_launchd bootstrap_drift = {.drift_after_bootstrap = true};
  bw_launchd_ops bootstrap_drift_ops = ops(&bootstrap_drift);
  bw_owned_launchd_job bootstrap_drift_owned;
  bw_init_owned_launchd_job(&bootstrap_drift_owned);
  bootstrap_drift_not_owned = bw_prepare_owned_launchd_job(
      &bootstrap_drift_ops, &value, &bootstrap_drift_owned) == BW_JOB_OK &&
      bw_bootstrap_owned_launchd_job(&bootstrap_drift_ops, &bootstrap_drift_owned) == BW_JOB_AMBIGUOUS &&
      bw_cleanup_owned_launchd_job(&bootstrap_drift_ops, &bootstrap_drift_owned) == BW_JOB_AMBIGUOUS &&
      bootstrap_drift.present && !bootstrap_drift.bootout_called;

  fake_launchd ambiguous_activation = {.activation_result = BW_JOB_AMBIGUOUS};
  bw_launchd_ops ambiguous_ops = ops(&ambiguous_activation);
  bw_owned_launchd_job ambiguous_owned;
  if (prepare_bootstrap(&ambiguous_activation, &ambiguous_owned)) {
    ambiguous_activation_cleaned = bw_activate_and_verify_owned_launchd_job(
        &ambiguous_ops, &ambiguous_owned) == BW_JOB_AMBIGUOUS &&
        bw_cleanup_owned_launchd_job(&ambiguous_ops, &ambiguous_owned) == BW_JOB_OK &&
        ambiguous_activation.stop_called && ambiguous_activation.bootout_called &&
        !ambiguous_activation.present;
  }

  fake_launchd activation_error = {.activation_result = BW_JOB_ERROR};
  bw_launchd_ops activation_error_ops = ops(&activation_error);
  bw_owned_launchd_job activation_error_owned;
  if (prepare_bootstrap(&activation_error, &activation_error_owned)) {
    activation_error_cleaned = bw_activate_and_verify_owned_launchd_job(
        &activation_error_ops, &activation_error_owned) == BW_JOB_AMBIGUOUS &&
        bw_cleanup_owned_launchd_job(&activation_error_ops, &activation_error_owned) == BW_JOB_OK &&
        activation_error.stop_called && activation_error.bootout_called && !activation_error.present;
  }

  fake_launchd foreign_swap = {.activation_result = BW_JOB_OK};
  bw_launchd_ops foreign_ops = ops(&foreign_swap);
  bw_owned_launchd_job foreign_owned;
  if (prepare_bootstrap(&foreign_swap, &foreign_owned)) {
    foreign_swap.record.binary_sha256[0] = 'b';
    foreign_swap_preserved = bw_cleanup_owned_launchd_job(
        &foreign_ops, &foreign_owned) == BW_JOB_AMBIGUOUS &&
        foreign_swap.present && !foreign_swap.stop_called && !foreign_swap.bootout_called;
  }

  fake_launchd bootout_race = {.activation_result = BW_JOB_OK, .drift_inside_bootout = true};
  bw_launchd_ops bootout_race_ops = ops(&bootout_race);
  bw_owned_launchd_job bootout_race_owned;
  if (prepare_bootstrap(&bootout_race, &bootout_race_owned)) {
    bootout_race_preserved = bw_cleanup_owned_launchd_job(
        &bootout_race_ops, &bootout_race_owned) == BW_JOB_AMBIGUOUS &&
        bootout_race.present && bootout_race.bootout_called;
  }

  fake_launchd stop_failure = {
    .activation_result = BW_JOB_OK, .stop_fails = true,
  };
  bw_launchd_ops stop_failure_ops = ops(&stop_failure);
  bw_owned_launchd_job stop_failure_owned;
  if (prepare_bootstrap(&stop_failure, &stop_failure_owned) &&
      bw_activate_and_verify_owned_launchd_job(
          &stop_failure_ops, &stop_failure_owned) == BW_JOB_OK) {
    cleanup_continues_after_stop_failure = bw_cleanup_owned_launchd_job(
        &stop_failure_ops, &stop_failure_owned) == BW_JOB_AMBIGUOUS &&
        stop_failure.stop_called && stop_failure.bootout_called && !stop_failure.present;
  }

  if (!(clean_denial_cleanup && collision_no_effect && bootstrap_drift_not_owned &&
      ambiguous_activation_cleaned && activation_error_cleaned && foreign_swap_preserved &&
      bootout_race_preserved &&
      cleanup_continues_after_stop_failure)) return 1;
  printf("{\"schema_version\":1,\"clean_denial_cleanup\":true,"
      "\"collision_no_effect\":true,\"bootstrap_drift_not_owned\":true,"
      "\"ambiguous_activation_cleaned\":true,\"activation_error_cleaned\":true,"
      "\"foreign_swap_preserved\":true,"
      "\"bootout_race_preserved\":true,\"cleanup_continues_after_stop_failure\":true}\n");
  return 0;
}
