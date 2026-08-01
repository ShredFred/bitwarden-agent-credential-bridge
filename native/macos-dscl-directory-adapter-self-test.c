#include "macos-dscl-directory-adapter.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  bool present;
  bool malformed_search;
  int fail_call;
  int calls;
  int properties;
  bw_account_record record;
} fake_dscl;

static fake_dscl *ACTIVE;

static void successful_output(bw_command_output *output, const char *stdout_value) {
  memset(output, 0, sizeof(*output));
  output->exited = true;
  output->exit_code = 0;
  if (stdout_value != NULL) {
    output->stdout_length = strlen(stdout_value);
    (void)strcpy(output->stdout_bytes, stdout_value);
  }
}

static bw_command_result fake_run(
    const char *executable,
    char *const argv[],
    unsigned int timeout,
    size_t maximum,
    bw_command_output *output) {
  fake_dscl *fake = ACTIVE;
  if (fake == NULL || strcmp(executable, "/usr/bin/dscl") != 0 ||
      strcmp(argv[0], executable) != 0 || timeout != 5000 || maximum != 8192) {
    return BW_COMMAND_INVALID;
  }
  fake->calls += 1;
  if (fake->calls == fake->fail_call) return BW_COMMAND_TIMEOUT;
  successful_output(output, NULL);
  if (strcmp(argv[2], "-search") == 0) {
    if (fake->malformed_search) {
      successful_output(output, "malformed\n");
      return BW_COMMAND_OK;
    }
    if (!fake->present) return BW_COMMAND_OK;
    char line[256];
    (void)snprintf(line, sizeof(line), "%s\t\t%s\n", fake->record.name, argv[5]);
    successful_output(output, line);
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[2], "-create") == 0 && argv[4] == NULL) {
    fake->present = true;
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[2], "-create") == 0 && argv[4] != NULL && argv[5] != NULL &&
      argv[6] == NULL) {
    fake->properties += 1;
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[2], "-read") == 0 && fake->present) {
    char value[512];
    (void)snprintf(value, sizeof(value),
        "UniqueID: %u\nGeneratedUID: %s\nUserShell: %s\nNFSHomeDirectory: %s\n",
        (unsigned int)fake->record.unique_id, fake->record.generated_uid,
        fake->record.shell, fake->record.home);
    successful_output(output, value);
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[2], "-delete") == 0 && fake->present) {
    fake->present = false;
    return BW_COMMAND_OK;
  }
  return BW_COMMAND_SPAWN_FAILED;
}

static bw_account_record candidate(void) {
  return (bw_account_record){
    .name = "_bwagentbridge",
    .unique_id = 499,
    .generated_uid = "12345678-1234-4ABC-8DEF-1234567890AB",
    .shell = "/usr/bin/false",
    .home = "/var/empty",
  };
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  bw_account_record expected = candidate();
  fake_dscl clean = {.record = expected};
  ACTIVE = &clean;
  bw_dscl_directory_adapter adapter;
  bw_directory_ops ops;
  bw_owned_account owned;
  bw_init_owned_account(&owned);
  bool initialized = bw_init_dscl_directory_ops(&adapter, fake_run, &ops);
  bool clean_lifecycle = initialized &&
      bw_prepare_owned_account(&ops, &expected, &owned) == BW_ACCOUNT_OK &&
      bw_create_owned_account(&ops, &owned) == BW_ACCOUNT_OK && clean.properties == 7 &&
      bw_delete_owned_account(&ops, &owned) == BW_ACCOUNT_OK && !clean.present;

  fake_dscl malformed = {.record = expected, .malformed_search = true};
  ACTIVE = &malformed;
  bw_init_owned_account(&owned);
  bool malformed_rejected =
      bw_prepare_owned_account(&ops, &expected, &owned) == BW_ACCOUNT_ERROR &&
      !malformed.present;

  fake_dscl partial = {.record = expected, .fail_call = 5};
  ACTIVE = &partial;
  bw_init_owned_account(&owned);
  bool partial_ambiguous =
      bw_prepare_owned_account(&ops, &expected, &owned) == BW_ACCOUNT_OK &&
      bw_create_owned_account(&ops, &owned) == BW_ACCOUNT_AMBIGUOUS && partial.present;

  fake_dscl swapped = {.present = true, .record = expected};
  swapped.record.unique_id = 498;
  ACTIVE = &swapped;
  bool swapped_delete_refused =
      ops.delete_record(ops.context, &expected) == BW_ACCOUNT_AMBIGUOUS && swapped.present;

  bool all = clean_lifecycle && malformed_rejected && partial_ambiguous && swapped_delete_refused;
  (void)printf(
      "{\"schema_version\":1,\"clean_lifecycle\":%s,\"malformed_rejected\":%s,"
      "\"partial_ambiguous\":%s,\"swapped_delete_refused\":%s}\n",
      clean_lifecycle ? "true" : "false", malformed_rejected ? "true" : "false",
      partial_ambiguous ? "true" : "false", swapped_delete_refused ? "true" : "false");
  return all ? 0 : 1;
}
