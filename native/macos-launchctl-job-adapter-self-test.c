#include "macos-launchctl-job-adapter.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define LABEL "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define TARGET "system/" LABEL

typedef struct {
  bool loaded;
  bool running;
  bool malformed_print;
  bool duplicate_pid;
  bool denial;
  bool artifacts_valid;
  int mutations;
} fake_launchd;

static fake_launchd *ACTIVE;

static void output_status(bw_command_output *output, int code, const char *out, const char *err) {
  memset(output, 0, sizeof(*output));
  output->exited = true;
  output->exit_code = code;
  if (out != NULL) {
    output->stdout_length = strlen(out);
    (void)strcpy(output->stdout_bytes, out);
  }
  if (err != NULL) {
    output->stderr_length = strlen(err);
    (void)strcpy(output->stderr_bytes, err);
  }
}

static bw_command_result fake_run(
    const char *executable,
    char *const argv[],
    unsigned int timeout,
    size_t maximum,
    bw_command_output *output) {
  fake_launchd *fake = ACTIVE;
  if (fake == NULL || strcmp(executable, "/bin/launchctl") != 0 ||
      strcmp(argv[0], executable) != 0 || timeout != 10000 ||
      maximum != BW_COMMAND_OUTPUT_CAPACITY) return BW_COMMAND_INVALID;
  if (strcmp(argv[1], "print") == 0 && strcmp(argv[2], TARGET) == 0 && argv[3] == NULL) {
    if (!fake->loaded) {
      output_status(output, 113, NULL,
          "Bad request.\nCould not find service \"" LABEL "\" in domain for system\n");
      return BW_COMMAND_OK;
    }
    if (fake->malformed_print) {
      output_status(output, 0, "system/" LABEL " = {\nprogram = /foreign\n}\n", NULL);
      return BW_COMMAND_OK;
    }
    char value[1024];
    (void)snprintf(value, sizeof(value),
        "system/%s = {\n\tstate = %s\n\tprogram = /Library/PrivilegedHelperTools/%s\n"
        "\tusername = _bwagentbridge\n\tpid = %s\n%s}\n",
        LABEL, fake->running ? "running" : "not running", LABEL,
        fake->running ? "4242" : "0", fake->duplicate_pid ? "\tpid = 4343\n" : "");
    output_status(output, 0, value, NULL);
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[1], "bootstrap") == 0 && strcmp(argv[2], "system") == 0 &&
      strcmp(argv[3], "/Library/LaunchDaemons/" LABEL ".plist") == 0 && argv[4] == NULL) {
    fake->loaded = true;
    fake->mutations += 1;
    output_status(output, 0, NULL, NULL);
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[1], "kickstart") == 0 && strcmp(argv[2], TARGET) == 0 && argv[3] == NULL) {
    fake->running = true;
    fake->mutations += 1;
    output_status(output, 0, NULL, NULL);
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[1], "kill") == 0 && strcmp(argv[2], "SIGTERM") == 0 &&
      strcmp(argv[3], TARGET) == 0 && argv[4] == NULL) {
    fake->running = false;
    fake->mutations += 1;
    output_status(output, 0, NULL, NULL);
    return BW_COMMAND_OK;
  }
  if (strcmp(argv[1], "bootout") == 0 && strcmp(argv[2], TARGET) == 0 && argv[3] == NULL) {
    fake->loaded = false;
    fake->mutations += 1;
    output_status(output, 0, NULL, NULL);
    return BW_COMMAND_OK;
  }
  return BW_COMMAND_SPAWN_FAILED;
}

static bw_launchd_probe mach_presence(void *context, const char *name) {
  fake_launchd *fake = context;
  if (fake == NULL || strcmp(name, LABEL) != 0) return BW_LAUNCHD_PROBE_ERROR;
  return fake->loaded ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_ABSENT;
}

static bool denial(void *context, const bw_launchd_job_record *identity) {
  fake_launchd *fake = context;
  return fake != NULL && fake->loaded && fake->running && fake->denial &&
      strcmp(identity->label, LABEL) == 0;
}

static bool artifacts(void *context, const bw_launchd_job_record *identity) {
  fake_launchd *fake = context;
  return fake != NULL && strcmp(identity->program,
      "/Library/PrivilegedHelperTools/" LABEL) == 0 && identity->demand_activation_only &&
      fake->artifacts_valid;
}

static bw_launchd_job_record expected_record(void) {
  return (bw_launchd_job_record){
    .label = LABEL,
    .program = "/Library/PrivilegedHelperTools/" LABEL,
    .user_name = "_bwagentbridge",
    .mach_service = LABEL,
    .binary_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    .plist_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    .demand_activation_only = true,
  };
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  bw_launchd_job_record expected = expected_record();
  fake_launchd clean = {.denial = true, .artifacts_valid = true};
  ACTIVE = &clean;
  bw_launchctl_job_adapter adapter;
  bw_launchd_ops ops;
  bw_owned_launchd_job owned;
  bw_init_owned_launchd_job(&owned);
  bool initialized = bw_init_launchctl_job_ops(
      &adapter, fake_run, mach_presence, denial, artifacts, &clean, &clean, &expected, &ops);
  bool clean_lifecycle = initialized &&
      bw_prepare_owned_launchd_job(&ops, &expected, &owned) == BW_JOB_OK &&
      bw_bootstrap_owned_launchd_job(&ops, &owned) == BW_JOB_OK &&
      bw_activate_and_verify_owned_launchd_job(&ops, &owned) == BW_JOB_OK &&
      bw_exercise_owned_launchd_denial(&ops, &owned) == BW_JOB_OK &&
      bw_cleanup_owned_launchd_job(&ops, &owned) == BW_JOB_OK &&
      !clean.loaded && !clean.running && clean.mutations == 4;

  fake_launchd foreign = {.loaded = true, .malformed_print = true, .artifacts_valid = true};
  ACTIVE = &foreign;
  bw_init_owned_launchd_job(&owned);
  bool malformed_collision = bw_init_launchctl_job_ops(
      &adapter, fake_run, mach_presence, denial, artifacts, &foreign, &foreign, &expected, &ops) &&
      bw_prepare_owned_launchd_job(&ops, &expected, &owned) == BW_JOB_ERROR &&
      foreign.mutations == 0;

  fake_launchd duplicate = {
    .loaded = true, .running = true, .duplicate_pid = true, .artifacts_valid = true,
  };
  ACTIVE = &duplicate;
  bool duplicate_pid_rejected = bw_init_launchctl_job_ops(
      &adapter, fake_run, mach_presence, denial, artifacts, &duplicate, &duplicate, &expected, &ops) &&
      !ops.verify_process(ops.context, &expected) && duplicate.mutations == 0;

  fake_launchd drift = {0};
  ACTIVE = &drift;
  bool prebootstrap_drift_blocked = bw_init_launchctl_job_ops(
      &adapter, fake_run, mach_presence, denial, artifacts, &drift, &drift, &expected, &ops) &&
      ops.bootstrap(ops.context, &expected) == BW_JOB_AMBIGUOUS && drift.mutations == 0 &&
      !drift.loaded;

  bool all = clean_lifecycle && malformed_collision && duplicate_pid_rejected &&
      prebootstrap_drift_blocked;
  (void)printf(
      "{\"schema_version\":1,\"clean_lifecycle\":%s,\"malformed_collision\":%s,"
      "\"duplicate_pid_rejected\":%s,\"prebootstrap_drift_blocked\":%s}\n",
      clean_lifecycle ? "true" : "false", malformed_collision ? "true" : "false",
      duplicate_pid_rejected ? "true" : "false",
      prebootstrap_drift_blocked ? "true" : "false");
  return all ? 0 : 1;
}
