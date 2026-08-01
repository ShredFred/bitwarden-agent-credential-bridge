#include "macos-dscl-directory-adapter.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DSCL "/usr/bin/dscl"
#define ACCOUNT "_bwagentbridge"
#define ACCOUNT_PATH "/Users/_bwagentbridge"
#define COMMAND_TIMEOUT_MS 5000U
#define COMMAND_OUTPUT_MAX 8192U

static bool exact_candidate(const bw_account_record *record) {
  if (record == NULL || strcmp(record->name, ACCOUNT) != 0 || record->unique_id < 1 ||
      record->unique_id > 499 || strcmp(record->shell, "/usr/bin/false") != 0 ||
      strcmp(record->home, "/var/empty") != 0 || strlen(record->generated_uid) != 36) return false;
  for (size_t index = 0; index < 36; index += 1) {
    char byte = record->generated_uid[index];
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (byte != '-') return false;
    } else if (!((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'F'))) {
      return false;
    }
  }
  return record->generated_uid[14] == '4' && strchr("89AB", record->generated_uid[19]) != NULL;
}

static bool clean_exit(const bw_command_output *output, int code) {
  return output->exited && output->exit_code == code && !output->signaled &&
      output->stderr_length == 0;
}

static bool run_clean(
    bw_dscl_directory_adapter *adapter, char *const argv[], bw_command_output *output) {
  return adapter != NULL && adapter->run != NULL &&
      adapter->run(DSCL, argv, COMMAND_TIMEOUT_MS, COMMAND_OUTPUT_MAX, output) == BW_COMMAND_OK &&
      clean_exit(output, 0);
}

static bool safe_search_output(const char *bytes, size_t length) {
  if (length == 0) return true;
  if (bytes == NULL || bytes[length - 1] != '\n') return false;
  size_t fields = 0;
  bool in_field = false;
  for (size_t index = 0; index < length; index += 1) {
    unsigned char byte = (unsigned char)bytes[index];
    if (byte == '\n') {
      if (fields != 1 || !in_field) return false;
      fields = 0;
      in_field = false;
    } else if (byte == ' ' || byte == '\t') {
      if (in_field) {
        fields += 1;
        in_field = false;
      }
    } else if (byte < 0x21 || byte > 0x7e) {
      return false;
    } else {
      in_field = true;
    }
  }
  return fields == 0 && !in_field;
}

static bw_directory_probe search(
    bw_dscl_directory_adapter *adapter, const char *attribute, const char *value) {
  if (adapter == NULL || adapter->run == NULL || attribute == NULL || value == NULL) {
    return BW_DIRECTORY_PROBE_ERROR;
  }
  char *args[] = {DSCL, ".", "-search", "/Users", (char *)attribute, (char *)value, NULL};
  bw_command_output output;
  if (!run_clean(adapter, args, &output) ||
      !safe_search_output(output.stdout_bytes, output.stdout_length)) return BW_DIRECTORY_PROBE_ERROR;
  return output.stdout_length == 0 ? BW_DIRECTORY_ABSENT : BW_DIRECTORY_PRESENT;
}

static bw_directory_probe probe_name(void *context, const char *name) {
  if (name == NULL || strcmp(name, ACCOUNT) != 0) return BW_DIRECTORY_PROBE_ERROR;
  return search(context, "RecordName", name);
}

static bw_directory_probe probe_unique_id(void *context, uid_t unique_id) {
  if (unique_id < 1 || unique_id > 499) return BW_DIRECTORY_PROBE_ERROR;
  char value[16];
  int count = snprintf(value, sizeof(value), "%u", (unsigned int)unique_id);
  if (count < 1 || (size_t)count >= sizeof(value)) return BW_DIRECTORY_PROBE_ERROR;
  return search(context, "UniqueID", value);
}

static bw_directory_probe probe_generated_uid(void *context, const char *generated_uid) {
  bw_account_record candidate = {
    .name = ACCOUNT, .unique_id = 1, .shell = "/usr/bin/false", .home = "/var/empty",
  };
  if (generated_uid == NULL || strlen(generated_uid) >= sizeof(candidate.generated_uid)) {
    return BW_DIRECTORY_PROBE_ERROR;
  }
  (void)strcpy(candidate.generated_uid, generated_uid);
  if (!exact_candidate(&candidate)) return BW_DIRECTORY_PROBE_ERROR;
  return search(context, "GeneratedUID", generated_uid);
}

static bool create_property(
    bw_dscl_directory_adapter *adapter, const char *property, const char *value) {
  char *args[] = {DSCL, ".", "-create", ACCOUNT_PATH, (char *)property, (char *)value, NULL};
  bw_command_output output;
  return run_clean(adapter, args, &output) && output.stdout_length == 0;
}

static bw_account_result create_record(void *context, const bw_account_record *record) {
  bw_dscl_directory_adapter *adapter = context;
  if (!exact_candidate(record)) return BW_ACCOUNT_ERROR;
  char *create_args[] = {DSCL, ".", "-create", ACCOUNT_PATH, NULL};
  bw_command_output output;
  if (!run_clean(adapter, create_args, &output) || output.stdout_length != 0) {
    return BW_ACCOUNT_AMBIGUOUS;
  }
  char unique_id[16];
  int count = snprintf(unique_id, sizeof(unique_id), "%u", (unsigned int)record->unique_id);
  if (count < 1 || (size_t)count >= sizeof(unique_id)) return BW_ACCOUNT_AMBIGUOUS;
  const char *properties[][2] = {
    {"UniqueID", unique_id}, {"GeneratedUID", record->generated_uid},
    {"UserShell", record->shell}, {"NFSHomeDirectory", record->home},
    {"PrimaryGroupID", "20"}, {"IsHidden", "1"},
    {"RealName", "Bitwarden Agent Bridge"},
  };
  for (size_t index = 0; index < sizeof(properties) / sizeof(properties[0]); index += 1) {
    if (!create_property(adapter, properties[index][0], properties[index][1])) {
      return BW_ACCOUNT_AMBIGUOUS;
    }
  }
  return BW_ACCOUNT_OK;
}

static bool parse_record(const bw_command_output *output, bw_account_record *record) {
  char copy[COMMAND_OUTPUT_MAX + 1];
  if (output == NULL || record == NULL || output->stdout_length == 0 ||
      output->stdout_length >= sizeof(copy) ||
      output->stdout_bytes[output->stdout_length - 1] != '\n' ||
      memchr(output->stdout_bytes, '\0', output->stdout_length) != NULL) return false;
  memcpy(copy, output->stdout_bytes, output->stdout_length + 1);
  bool saw_uid = false, saw_guid = false, saw_shell = false, saw_home = false;
  for (char *line = strtok(copy, "\n"); line != NULL; line = strtok(NULL, "\n")) {
    char *separator = strstr(line, ": ");
    if (separator == NULL || separator[2] == '\0') return false;
    *separator = '\0';
    const char *value = separator + 2;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; cursor += 1) {
      if (isspace(*cursor)) return false;
    }
    if (strcmp(line, "UniqueID") == 0 && !saw_uid) {
      errno = 0;
      char *end = NULL;
      unsigned long parsed = strtoul(value, &end, 10);
      if (errno != 0 || end == value || *end != '\0' || parsed < 1 || parsed > 499) return false;
      record->unique_id = (uid_t)parsed;
      saw_uid = true;
    } else if (strcmp(line, "GeneratedUID") == 0 && !saw_guid &&
        strlen(value) < sizeof(record->generated_uid)) {
      (void)strcpy(record->generated_uid, value);
      saw_guid = true;
    } else if (strcmp(line, "UserShell") == 0 && !saw_shell &&
        strlen(value) < sizeof(record->shell)) {
      (void)strcpy(record->shell, value);
      saw_shell = true;
    } else if (strcmp(line, "NFSHomeDirectory") == 0 && !saw_home &&
        strlen(value) < sizeof(record->home)) {
      (void)strcpy(record->home, value);
      saw_home = true;
    } else {
      return false;
    }
  }
  (void)strcpy(record->name, ACCOUNT);
  return saw_uid && saw_guid && saw_shell && saw_home && exact_candidate(record);
}

static bool read_record(void *context, const char *name, bw_account_record *record) {
  bw_dscl_directory_adapter *adapter = context;
  if (name == NULL || strcmp(name, ACCOUNT) != 0 || record == NULL) return false;
  char *args[] = {
    DSCL, ".", "-read", ACCOUNT_PATH, "UniqueID", "GeneratedUID", "UserShell",
    "NFSHomeDirectory", NULL,
  };
  bw_command_output output;
  memset(record, 0, sizeof(*record));
  return run_clean(adapter, args, &output) && parse_record(&output, record);
}

static bw_account_result delete_record(void *context, const bw_account_record *record) {
  bw_dscl_directory_adapter *adapter = context;
  if (!exact_candidate(record)) return BW_ACCOUNT_ERROR;
  bw_account_record current;
  if (!read_record(context, ACCOUNT, &current) ||
      strcmp(current.name, record->name) != 0 || current.unique_id != record->unique_id ||
      strcmp(current.generated_uid, record->generated_uid) != 0 ||
      strcmp(current.shell, record->shell) != 0 || strcmp(current.home, record->home) != 0) {
    return BW_ACCOUNT_AMBIGUOUS;
  }
  char *args[] = {DSCL, ".", "-delete", ACCOUNT_PATH, NULL};
  bw_command_output output;
  if (!run_clean(adapter, args, &output) || output.stdout_length != 0) {
    return BW_ACCOUNT_AMBIGUOUS;
  }
  return BW_ACCOUNT_OK;
}

bool bw_init_dscl_directory_ops(
    bw_dscl_directory_adapter *adapter,
    bw_fixed_command_runner runner,
    bw_directory_ops *ops) {
  if (adapter == NULL || runner == NULL || ops == NULL) return false;
  adapter->run = runner;
  *ops = (bw_directory_ops){
    .context = adapter,
    .probe_name = probe_name,
    .probe_unique_id = probe_unique_id,
    .probe_generated_uid = probe_generated_uid,
    .create_record = create_record,
    .read_record = read_record,
    .delete_record = delete_record,
  };
  return true;
}
