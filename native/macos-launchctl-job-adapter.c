#include "macos-launchctl-job-adapter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LAUNCHCTL "/bin/launchctl"
#define LABEL "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define SERVICE_TARGET "system/" LABEL
#define PLIST_PATH "/Library/LaunchDaemons/" LABEL ".plist"
#define PROGRAM_PATH "/Library/PrivilegedHelperTools/" LABEL
#define ACCOUNT "_bwagentbridge"
#define COMMAND_TIMEOUT_MS 10000U
#define COMMAND_OUTPUT_MAX BW_COMMAND_OUTPUT_CAPACITY

static const char ABSENT_STDERR[] =
    "Bad request.\nCould not find service \"" LABEL "\" in domain for system\n";

static bool sha256_text(const char *value) {
  if (value == NULL || strlen(value) != 64) return false;
  for (size_t index = 0; index < 64; index += 1) {
    if (!((value[index] >= '0' && value[index] <= '9') ||
          (value[index] >= 'a' && value[index] <= 'f'))) return false;
  }
  return true;
}

static bool exact_record(const bw_launchd_job_record *record) {
  return record != NULL && strcmp(record->label, LABEL) == 0 &&
      strcmp(record->program, PROGRAM_PATH) == 0 && strcmp(record->user_name, ACCOUNT) == 0 &&
      strcmp(record->mach_service, LABEL) == 0 && sha256_text(record->binary_sha256) &&
      sha256_text(record->plist_sha256) && record->demand_activation_only;
}

static bool same_record(
    const bw_launchd_job_record *left, const bw_launchd_job_record *right) {
  return exact_record(left) && exact_record(right) &&
      strcmp(left->label, right->label) == 0 && strcmp(left->program, right->program) == 0 &&
      strcmp(left->user_name, right->user_name) == 0 &&
      strcmp(left->mach_service, right->mach_service) == 0 &&
      strcmp(left->binary_sha256, right->binary_sha256) == 0 &&
      strcmp(left->plist_sha256, right->plist_sha256) == 0 &&
      left->demand_activation_only == right->demand_activation_only;
}

static bool safe_output(const char *bytes, size_t length) {
  if (bytes == NULL || length == 0 || bytes[length - 1] != '\n' ||
      memchr(bytes, '\0', length) != NULL) return false;
  for (size_t index = 0; index < length; index += 1) {
    unsigned char byte = (unsigned char)bytes[index];
    if (byte != '\n' && byte != '\t' && (byte < 0x20 || byte > 0x7e)) return false;
  }
  return true;
}

static bool clean_exit(const bw_command_output *output, int code) {
  return output->exited && output->exit_code == code && !output->signaled;
}

static bw_command_result run_launchctl(
    bw_launchctl_job_adapter *adapter, char *const argv[], bw_command_output *output) {
  if (adapter == NULL || adapter->run == NULL) return BW_COMMAND_INVALID;
  return adapter->run(
      LAUNCHCTL, argv, COMMAND_TIMEOUT_MS, COMMAND_OUTPUT_MAX, output);
}

static size_t exact_trimmed_line_count(const char *bytes, size_t length, const char *expected) {
  size_t expected_length = strlen(expected);
  size_t matches = 0;
  size_t start = 0;
  while (start < length) {
    size_t end = start;
    while (end < length && bytes[end] != '\n') end += 1;
    size_t left = start;
    while (left < end && (bytes[left] == ' ' || bytes[left] == '\t')) left += 1;
    size_t right = end;
    while (right > left && (bytes[right - 1] == ' ' || bytes[right - 1] == '\t')) right -= 1;
    if (right - left == expected_length && memcmp(bytes + left, expected, expected_length) == 0) {
      matches += 1;
    }
    start = end + 1;
  }
  return matches;
}

static bool unique_key_line(
    const char *bytes, size_t length, const char *key, const char *expected) {
  size_t key_length = strlen(key);
  size_t expected_length = strlen(expected);
  size_t key_count = 0;
  size_t expected_count = 0;
  size_t start = 0;
  while (start < length) {
    size_t end = start;
    while (end < length && bytes[end] != '\n') end += 1;
    size_t left = start;
    while (left < end && (bytes[left] == ' ' || bytes[left] == '\t')) left += 1;
    size_t right = end;
    while (right > left && (bytes[right - 1] == ' ' || bytes[right - 1] == '\t')) right -= 1;
    if (right - left >= key_length && memcmp(bytes + left, key, key_length) == 0) {
      key_count += 1;
      if (right - left == expected_length &&
          memcmp(bytes + left, expected, expected_length) == 0) expected_count += 1;
    }
    start = end + 1;
  }
  return key_count == 1 && expected_count == 1;
}

static bool unique_pid_line(const char *bytes, size_t length) {
  static const char key[] = "pid = ";
  size_t found_count = 0;
  unsigned long found_pid = 0;
  size_t start = 0;
  while (start < length) {
    size_t end = start;
    while (end < length && bytes[end] != '\n') end += 1;
    size_t left = start;
    while (left < end && (bytes[left] == ' ' || bytes[left] == '\t')) left += 1;
    size_t right = end;
    while (right > left && (bytes[right - 1] == ' ' || bytes[right - 1] == '\t')) right -= 1;
    if (right - left >= sizeof(key) - 1 && memcmp(bytes + left, key, sizeof(key) - 1) == 0) {
      found_count += 1;
      size_t digits = right - left - (sizeof(key) - 1);
      if (digits == 0 || digits > 8) return false;
      char value[9];
      memcpy(value, bytes + left + sizeof(key) - 1, digits);
      value[digits] = '\0';
      errno = 0;
      char *parsed_end = NULL;
      found_pid = strtoul(value, &parsed_end, 10);
      if (errno != 0 || parsed_end == value || *parsed_end != '\0') return false;
    }
    start = end + 1;
  }
  return found_count == 1 && found_pid > 1 && found_pid <= 99999999UL;
}

static bool parsed_loaded_job(
    const bw_command_output *output,
    const bw_launchd_job_record *expected,
    bool require_running) {
  if (!clean_exit(output, 0) || output->stderr_length != 0 ||
      !safe_output(output->stdout_bytes, output->stdout_length)) return false;
  char header[192];
  char program[384];
  char username[128];
  int h = snprintf(header, sizeof(header), "system/%s = {", expected->label);
  int p = snprintf(program, sizeof(program), "program = %s", expected->program);
  int u = snprintf(username, sizeof(username), "username = %s", expected->user_name);
  if (h < 1 || p < 1 || u < 1 || (size_t)h >= sizeof(header) ||
      (size_t)p >= sizeof(program) || (size_t)u >= sizeof(username) ||
      exact_trimmed_line_count(output->stdout_bytes, output->stdout_length, header) != 1 ||
      !unique_key_line(output->stdout_bytes, output->stdout_length, "program = ", program) ||
      !unique_key_line(output->stdout_bytes, output->stdout_length, "username = ", username)) {
    return false;
  }
  if (!require_running) return true;
  if (!unique_key_line(
          output->stdout_bytes, output->stdout_length, "state = ", "state = running")) {
    return false;
  }
  return unique_pid_line(output->stdout_bytes, output->stdout_length);
}

static bool print_job(
    bw_launchctl_job_adapter *adapter,
    const bw_launchd_job_record *expected,
    bool require_running) {
  char *args[] = {LAUNCHCTL, "print", SERVICE_TARGET, NULL};
  bw_command_output output;
  return adapter->artifacts != NULL &&
      adapter->artifacts(adapter->artifact_context, expected) &&
      run_launchctl(adapter, args, &output) == BW_COMMAND_OK &&
      parsed_loaded_job(&output, expected, require_running);
}

static bw_launchd_probe probe_label(void *context, const char *label) {
  bw_launchctl_job_adapter *adapter = context;
  if (adapter == NULL || label == NULL || strcmp(label, LABEL) != 0) {
    return BW_LAUNCHD_PROBE_ERROR;
  }
  char *args[] = {LAUNCHCTL, "print", SERVICE_TARGET, NULL};
  bw_command_output output;
  if (run_launchctl(adapter, args, &output) != BW_COMMAND_OK) return BW_LAUNCHD_PROBE_ERROR;
  if (clean_exit(&output, 113) && output.stdout_length == 0 &&
      output.stderr_length == strlen(ABSENT_STDERR) &&
      memcmp(output.stderr_bytes, ABSENT_STDERR, output.stderr_length) == 0) {
    return BW_LAUNCHD_ABSENT;
  }
  return parsed_loaded_job(&output, &adapter->expected, false)
      ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_PROBE_ERROR;
}

static bw_launchd_probe probe_mach_service(void *context, const char *name) {
  bw_launchctl_job_adapter *adapter = context;
  if (adapter == NULL || name == NULL || strcmp(name, LABEL) != 0 ||
      adapter->mach_presence == NULL) return BW_LAUNCHD_PROBE_ERROR;
  return adapter->mach_presence(adapter->probe_context, name);
}

static bw_job_result bootstrap(void *context, const bw_launchd_job_record *record) {
  bw_launchctl_job_adapter *adapter = context;
  if (adapter == NULL || !same_record(record, &adapter->expected)) return BW_JOB_ERROR;
  if (adapter->artifacts == NULL ||
      !adapter->artifacts(adapter->artifact_context, record)) return BW_JOB_AMBIGUOUS;
  char *args[] = {LAUNCHCTL, "bootstrap", "system", PLIST_PATH, NULL};
  bw_command_output output;
  if (run_launchctl(adapter, args, &output) != BW_COMMAND_OK || !clean_exit(&output, 0) ||
      output.stdout_length != 0 || output.stderr_length != 0) return BW_JOB_AMBIGUOUS;
  return BW_JOB_OK;
}

static bool read_job(void *context, const char *label, bw_launchd_job_record *record) {
  bw_launchctl_job_adapter *adapter = context;
  if (adapter == NULL || label == NULL || strcmp(label, LABEL) != 0 || record == NULL ||
      !print_job(adapter, &adapter->expected, false)) return false;
  *record = adapter->expected;
  return true;
}

static bw_job_result activate(void *context, const bw_launchd_job_record *record) {
  bw_launchctl_job_adapter *adapter = context;
  if (adapter == NULL || !same_record(record, &adapter->expected)) return BW_JOB_ERROR;
  if (adapter->artifacts == NULL ||
      !adapter->artifacts(adapter->artifact_context, record)) return BW_JOB_AMBIGUOUS;
  char *args[] = {LAUNCHCTL, "kickstart", SERVICE_TARGET, NULL};
  bw_command_output output;
  if (run_launchctl(adapter, args, &output) != BW_COMMAND_OK || !clean_exit(&output, 0) ||
      output.stdout_length != 0 || output.stderr_length != 0) return BW_JOB_AMBIGUOUS;
  return BW_JOB_OK;
}

static bool verify_process(void *context, const bw_launchd_job_record *record) {
  bw_launchctl_job_adapter *adapter = context;
  return adapter != NULL && same_record(record, &adapter->expected) &&
      print_job(adapter, &adapter->expected, true);
}

static bool exercise_denial(void *context, const bw_launchd_job_record *record) {
  bw_launchctl_job_adapter *adapter = context;
  return adapter != NULL && same_record(record, &adapter->expected) && adapter->denial != NULL &&
      adapter->denial(adapter->probe_context, record);
}

static bw_job_result stop_process(void *context, const bw_launchd_job_record *record) {
  bw_launchctl_job_adapter *adapter = context;
  if (adapter == NULL || !same_record(record, &adapter->expected)) return BW_JOB_ERROR;
  if (!print_job(adapter, &adapter->expected, false)) return BW_JOB_AMBIGUOUS;
  char *args[] = {LAUNCHCTL, "kill", "SIGTERM", SERVICE_TARGET, NULL};
  bw_command_output output;
  if (run_launchctl(adapter, args, &output) != BW_COMMAND_OK || !clean_exit(&output, 0) ||
      output.stdout_length != 0 || output.stderr_length != 0) return BW_JOB_AMBIGUOUS;
  return BW_JOB_OK;
}

static bw_job_result bootout(void *context, const bw_launchd_job_record *record) {
  bw_launchctl_job_adapter *adapter = context;
  if (adapter == NULL || !same_record(record, &adapter->expected)) return BW_JOB_ERROR;
  if (!print_job(adapter, &adapter->expected, false)) return BW_JOB_AMBIGUOUS;
  char *args[] = {LAUNCHCTL, "bootout", SERVICE_TARGET, NULL};
  bw_command_output output;
  if (run_launchctl(adapter, args, &output) != BW_COMMAND_OK || !clean_exit(&output, 0) ||
      output.stdout_length != 0 || output.stderr_length != 0) return BW_JOB_AMBIGUOUS;
  return BW_JOB_OK;
}

bool bw_init_launchctl_job_ops(
    bw_launchctl_job_adapter *adapter,
    bw_fixed_command_runner runner,
    bw_mach_presence_probe mach_presence,
    bw_mach_denial_probe denial,
    bw_job_artifact_probe artifacts,
    void *probe_context,
    void *artifact_context,
    const bw_launchd_job_record *expected,
    bw_launchd_ops *ops) {
  if (adapter == NULL || runner == NULL || mach_presence == NULL || denial == NULL ||
      artifacts == NULL || artifact_context == NULL ||
      !exact_record(expected) || ops == NULL) return false;
  *adapter = (bw_launchctl_job_adapter){
    .run = runner, .mach_presence = mach_presence, .denial = denial, .artifacts = artifacts,
    .probe_context = probe_context, .artifact_context = artifact_context, .expected = *expected,
  };
  *ops = (bw_launchd_ops){
    .context = adapter, .probe_label = probe_label, .probe_mach_service = probe_mach_service,
    .bootstrap = bootstrap, .read_job = read_job, .activate = activate,
    .verify_process = verify_process, .exercise_denial = exercise_denial,
    .stop_process = stop_process, .bootout = bootout,
  };
  return true;
}
