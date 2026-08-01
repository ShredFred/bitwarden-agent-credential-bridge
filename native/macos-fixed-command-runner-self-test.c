#include "macos-fixed-command-runner.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool clean_exit(const bw_command_output *output, int code) {
  return output->exited && output->exit_code == code && !output->signaled;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;

  bw_command_output output;
  char *true_argv[] = {"/usr/bin/true", NULL};
  bool true_ok = bw_run_fixed_command(
      "/usr/bin/true", true_argv, 1000, 1024, &output) == BW_COMMAND_OK &&
      clean_exit(&output, 0) && output.stdout_length == 0 && output.stderr_length == 0;

  char *printf_argv[] = {"/usr/bin/printf", "runner-ok", NULL};
  bool capture_ok = bw_run_fixed_command(
      "/usr/bin/printf", printf_argv, 1000, 1024, &output) == BW_COMMAND_OK &&
      clean_exit(&output, 0) && strcmp(output.stdout_bytes, "runner-ok") == 0 &&
      output.stderr_length == 0;

  char *false_argv[] = {"/usr/bin/false", NULL};
  bool nonzero_reported = bw_run_fixed_command(
      "/usr/bin/false", false_argv, 1000, 1024, &output) == BW_COMMAND_OK &&
      clean_exit(&output, 1);

  char *sleep_argv[] = {"/bin/sleep", "2", NULL};
  bool timeout_killed = bw_run_fixed_command(
      "/bin/sleep", sleep_argv, 25, 1024, &output) == BW_COMMAND_TIMEOUT;

  char *yes_argv[] = {"/usr/bin/yes", NULL};
  bool flood_killed = bw_run_fixed_command(
      "/usr/bin/yes", yes_argv, 1000, 128, &output) == BW_COMMAND_OUTPUT_TOO_LARGE;

  char *relative_argv[] = {"true", NULL};
  bool relative_rejected = bw_run_fixed_command(
      "true", relative_argv, 1000, 1024, &output) == BW_COMMAND_INVALID;

  bool all = true_ok && capture_ok && nonzero_reported && timeout_killed && flood_killed &&
      relative_rejected;
  (void)printf(
      "{\"schema_version\":1,\"true_ok\":%s,\"capture_ok\":%s,"
      "\"nonzero_reported\":%s,\"timeout_killed\":%s,\"flood_killed\":%s,"
      "\"relative_rejected\":%s}\n",
      true_ok ? "true" : "false", capture_ok ? "true" : "false",
      nonzero_reported ? "true" : "false", timeout_killed ? "true" : "false",
      flood_killed ? "true" : "false", relative_rejected ? "true" : "false");
  return all ? 0 : 1;
}
