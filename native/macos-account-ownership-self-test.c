#include "macos-account-ownership.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  bool present;
  bool drift_after_create;
  bool drift_before_delete;
  bool delete_called;
  bw_account_record record;
} fake_directory;

static bw_directory_probe probe_name(void *raw, const char *name) {
  fake_directory *state = raw;
  return state->present && strcmp(state->record.name, name) == 0
      ? BW_DIRECTORY_PRESENT : BW_DIRECTORY_ABSENT;
}

static bw_directory_probe probe_uid(void *raw, uid_t unique_id) {
  fake_directory *state = raw;
  return state->present && state->record.unique_id == unique_id
      ? BW_DIRECTORY_PRESENT : BW_DIRECTORY_ABSENT;
}

static bw_directory_probe probe_guid(void *raw, const char *generated_uid) {
  fake_directory *state = raw;
  return state->present && strcmp(state->record.generated_uid, generated_uid) == 0
      ? BW_DIRECTORY_PRESENT : BW_DIRECTORY_ABSENT;
}

static bw_account_result create_record(void *raw, const bw_account_record *record) {
  fake_directory *state = raw;
  if (state->present) return BW_ACCOUNT_NO_EFFECT;
  state->record = *record;
  state->present = true;
  if (state->drift_after_create) state->record.unique_id += 1;
  return BW_ACCOUNT_OK;
}

static bool read_record(void *raw, const char *name, bw_account_record *record) {
  fake_directory *state = raw;
  if (!state->present || strcmp(state->record.name, name) != 0) return false;
  *record = state->record;
  return true;
}

static bw_account_result delete_record(void *raw, const bw_account_record *record) {
  fake_directory *state = raw;
  state->delete_called = true;
  if (state->drift_before_delete) state->record.generated_uid[0] = 'F';
  if (!state->present || state->record.unique_id != record->unique_id ||
      strcmp(state->record.generated_uid, record->generated_uid) != 0) return BW_ACCOUNT_AMBIGUOUS;
  state->present = false;
  return BW_ACCOUNT_OK;
}

static bw_directory_ops ops(fake_directory *state) {
  bw_directory_ops value = {
    .context = state,
    .probe_name = probe_name,
    .probe_unique_id = probe_uid,
    .probe_generated_uid = probe_guid,
    .create_record = create_record,
    .read_record = read_record,
    .delete_record = delete_record,
  };
  return value;
}

static bw_account_record candidate(void) {
  bw_account_record value = {
    .name = "_bwagentbridge",
    .unique_id = 499,
    .generated_uid = "12345678-1234-4ABC-8DEF-1234567890AB",
    .shell = "/usr/bin/false",
    .home = "/var/empty",
  };
  return value;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 2;
  bool clean_lifecycle = false;
  bool collision_no_effect = false;
  bool post_create_drift_ambiguous = false;
  bool drift_never_deleted = false;
  bool delete_race_preserved = false;

  fake_directory clean = {0};
  bw_directory_ops clean_ops = ops(&clean);
  bw_account_record clean_candidate = candidate();
  bw_owned_account clean_owned;
  bw_init_owned_account(&clean_owned);
  clean_lifecycle = bw_prepare_owned_account(&clean_ops, &clean_candidate, &clean_owned) == BW_ACCOUNT_OK &&
      bw_create_owned_account(&clean_ops, &clean_owned) == BW_ACCOUNT_OK &&
      bw_verify_owned_account(&clean_ops, &clean_owned) == BW_ACCOUNT_OK &&
      bw_delete_owned_account(&clean_ops, &clean_owned) == BW_ACCOUNT_OK &&
      bw_create_owned_account(&clean_ops, &clean_owned) == BW_ACCOUNT_ERROR &&
      !clean.present && clean.delete_called;

  fake_directory collision = {.present = true, .record = candidate()};
  bw_directory_ops collision_ops = ops(&collision);
  bw_owned_account collision_owned;
  bw_init_owned_account(&collision_owned);
  collision_no_effect = bw_prepare_owned_account(
      &collision_ops, &clean_candidate, &collision_owned) == BW_ACCOUNT_NO_EFFECT &&
      !collision.delete_called;

  fake_directory drift_create = {.drift_after_create = true};
  bw_directory_ops drift_create_ops = ops(&drift_create);
  bw_owned_account drift_create_owned;
  bw_init_owned_account(&drift_create_owned);
  post_create_drift_ambiguous = bw_prepare_owned_account(
      &drift_create_ops, &clean_candidate, &drift_create_owned) == BW_ACCOUNT_OK &&
      bw_create_owned_account(&drift_create_ops, &drift_create_owned) == BW_ACCOUNT_AMBIGUOUS &&
      bw_delete_owned_account(&drift_create_ops, &drift_create_owned) == BW_ACCOUNT_NO_EFFECT &&
      bw_prepare_owned_account(&drift_create_ops, &clean_candidate, &drift_create_owned) ==
          BW_ACCOUNT_ERROR &&
      !drift_create.delete_called;

  fake_directory drift_delete = {0};
  bw_directory_ops drift_delete_ops = ops(&drift_delete);
  bw_owned_account drift_delete_owned;
  bw_init_owned_account(&drift_delete_owned);
  if (bw_prepare_owned_account(&drift_delete_ops, &clean_candidate, &drift_delete_owned) == BW_ACCOUNT_OK &&
      bw_create_owned_account(&drift_delete_ops, &drift_delete_owned) == BW_ACCOUNT_OK) {
    drift_delete.record.generated_uid[0] = 'A';
    drift_never_deleted = bw_delete_owned_account(
        &drift_delete_ops, &drift_delete_owned) == BW_ACCOUNT_AMBIGUOUS &&
        drift_delete.present && !drift_delete.delete_called;
  }

  fake_directory delete_race = {0};
  bw_directory_ops delete_race_ops = ops(&delete_race);
  bw_owned_account delete_race_owned;
  bw_init_owned_account(&delete_race_owned);
  if (bw_prepare_owned_account(&delete_race_ops, &clean_candidate, &delete_race_owned) == BW_ACCOUNT_OK &&
      bw_create_owned_account(&delete_race_ops, &delete_race_owned) == BW_ACCOUNT_OK) {
    delete_race.drift_before_delete = true;
    delete_race_preserved = bw_delete_owned_account(
        &delete_race_ops, &delete_race_owned) == BW_ACCOUNT_AMBIGUOUS &&
        delete_race.present && delete_race.delete_called;
  }

  if (!(clean_lifecycle && collision_no_effect && post_create_drift_ambiguous &&
      drift_never_deleted && delete_race_preserved)) return 1;
  printf("{\"schema_version\":1,\"clean_lifecycle\":true,"
      "\"collision_no_effect\":true,\"post_create_drift_ambiguous\":true,"
      "\"drift_never_deleted\":true,\"delete_race_preserved\":true}\n");
  return 0;
}
