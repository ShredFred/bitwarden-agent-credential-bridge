#ifndef BW_AGENT_MACOS_FIXED_COMMAND_RUNNER_H
#define BW_AGENT_MACOS_FIXED_COMMAND_RUNNER_H

#include <stdbool.h>
#include <stddef.h>

#define BW_COMMAND_OUTPUT_CAPACITY (64U * 1024U)

typedef enum {
  BW_COMMAND_OK = 0,
  BW_COMMAND_INVALID = 1,
  BW_COMMAND_SPAWN_FAILED = 2,
  BW_COMMAND_TIMEOUT = 3,
  BW_COMMAND_OUTPUT_TOO_LARGE = 4,
  BW_COMMAND_IO_FAILED = 5,
} bw_command_result;

typedef struct {
  int exit_code;
  bool exited;
  bool signaled;
  int signal_number;
  char stdout_bytes[BW_COMMAND_OUTPUT_CAPACITY + 1];
  size_t stdout_length;
  char stderr_bytes[BW_COMMAND_OUTPUT_CAPACITY + 1];
  size_t stderr_length;
} bw_command_output;

bw_command_result bw_run_fixed_command(
    const char *absolute_executable,
    char *const argv[],
    unsigned int timeout_milliseconds,
    size_t maximum_output_bytes,
    bw_command_output *output);

#endif
