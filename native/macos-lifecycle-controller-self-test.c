#include "macos-lifecycle-controller.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  bool account_present;
  bool account_drift_after_create;
  bool account_create_ambiguous;
  bool account_create_called;
  bool account_delete_called;
  bw_account_record account;
  bool job_present;
  bool process_running;
  bool job_bootstrap_called;
  bool job_stop_called;
  bool job_bootout_called;
  bw_job_result activation_result;
  bool replace_plist_on_denial;
  int plist_parent_fd;
  bw_launchd_job_record job;
} fake_host;

static bw_directory_probe account_name(void *raw, const char *name) {
  fake_host *host = raw;
  return host->account_present && strcmp(host->account.name, name) == 0
      ? BW_DIRECTORY_PRESENT : BW_DIRECTORY_ABSENT;
}
static bw_directory_probe account_uid(void *raw, uid_t uid) {
  fake_host *host = raw;
  return host->account_present && host->account.unique_id == uid
      ? BW_DIRECTORY_PRESENT : BW_DIRECTORY_ABSENT;
}
static bw_directory_probe account_guid(void *raw, const char *guid) {
  fake_host *host = raw;
  return host->account_present && strcmp(host->account.generated_uid, guid) == 0
      ? BW_DIRECTORY_PRESENT : BW_DIRECTORY_ABSENT;
}
static bw_account_result account_create(void *raw, const bw_account_record *record) {
  fake_host *host = raw;
  host->account_create_called = true;
  if (host->account_present) return BW_ACCOUNT_NO_EFFECT;
  host->account = *record;
  host->account_present = true;
  if (host->account_create_ambiguous) return BW_ACCOUNT_AMBIGUOUS;
  if (host->account_drift_after_create) host->account.unique_id -= 1;
  return BW_ACCOUNT_OK;
}
static bool account_read(void *raw, const char *name, bw_account_record *record) {
  fake_host *host = raw;
  if (!host->account_present || strcmp(host->account.name, name) != 0) return false;
  *record = host->account;
  return true;
}
static bw_account_result account_delete(void *raw, const bw_account_record *record) {
  fake_host *host = raw;
  host->account_delete_called = true;
  if (!host->account_present || host->account.unique_id != record->unique_id ||
      strcmp(host->account.generated_uid, record->generated_uid) != 0) return BW_ACCOUNT_AMBIGUOUS;
  host->account_present = false;
  return BW_ACCOUNT_OK;
}

static bool same_job(const bw_launchd_job_record *left, const bw_launchd_job_record *right) {
  return strcmp(left->label, right->label) == 0 && strcmp(left->program, right->program) == 0 &&
      strcmp(left->user_name, right->user_name) == 0 &&
      strcmp(left->mach_service, right->mach_service) == 0 &&
      strcmp(left->binary_sha256, right->binary_sha256) == 0 &&
      strcmp(left->plist_sha256, right->plist_sha256) == 0 &&
      left->demand_activation_only == right->demand_activation_only;
}
static bw_launchd_probe job_label(void *raw, const char *label) {
  fake_host *host = raw;
  return host->job_present && strcmp(host->job.label, label) == 0
      ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_ABSENT;
}
static bw_launchd_probe job_mach(void *raw, const char *name) {
  fake_host *host = raw;
  return host->job_present && strcmp(host->job.mach_service, name) == 0
      ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_ABSENT;
}
static bw_job_result job_bootstrap(void *raw, const bw_launchd_job_record *record) {
  fake_host *host = raw;
  host->job_bootstrap_called = true;
  if (host->job_present) return BW_JOB_NO_EFFECT;
  host->job = *record;
  host->job_present = true;
  return BW_JOB_OK;
}
static bool job_read(void *raw, const char *label, bw_launchd_job_record *record) {
  fake_host *host = raw;
  if (!host->job_present || strcmp(host->job.label, label) != 0) return false;
  *record = host->job;
  return true;
}
static bw_job_result job_activate(void *raw, const bw_launchd_job_record *record) {
  fake_host *host = raw;
  if (!host->job_present || !same_job(&host->job, record)) return BW_JOB_AMBIGUOUS;
  if (host->activation_result != BW_JOB_NO_EFFECT) host->process_running = true;
  return host->activation_result;
}
static bool process_verify(void *raw, const bw_launchd_job_record *record) {
  fake_host *host = raw;
  return host->process_running && host->job_present && same_job(&host->job, record);
}
static bool denial(void *raw, const bw_launchd_job_record *record) {
  fake_host *host = raw;
  if (!process_verify(raw, record)) return false;
  if (host->replace_plist_on_denial) {
    const char *name = "de.frederikstadler.bitwarden-agent-credential-bridge.helper.plist";
    if (unlinkat(host->plist_parent_fd, name, 0) != 0) return false;
    int fd = openat(host->plist_parent_fd, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    static const unsigned char foreign[] = "foreign";
    bool ok = write(fd, foreign, sizeof(foreign)) == (ssize_t)sizeof(foreign) && close(fd) == 0;
    if (!ok) return false;
  }
  return true;
}
static bw_job_result process_stop(void *raw, const bw_launchd_job_record *record) {
  fake_host *host = raw;
  host->job_stop_called = true;
  if (!host->job_present || !same_job(&host->job, record)) return BW_JOB_AMBIGUOUS;
  host->process_running = false;
  return BW_JOB_OK;
}
static bw_job_result job_bootout(void *raw, const bw_launchd_job_record *record) {
  fake_host *host = raw;
  host->job_bootout_called = true;
  if (!host->job_present || !same_job(&host->job, record)) return BW_JOB_AMBIGUOUS;
  host->job_present = false;
  host->process_running = false;
  return BW_JOB_OK;
}

static bw_account_record account_candidate(void) {
  bw_account_record value = {
    .name = "_bwagentbridge", .unique_id = 499,
    .generated_uid = "12345678-1234-4ABC-8DEF-1234567890AB",
    .shell = "/usr/bin/false", .home = "/var/empty",
  };
  return value;
}
static bw_launchd_job_record job_candidate(void) {
  bw_launchd_job_record value = {
    .label = "de.frederikstadler.bitwarden-agent-credential-bridge.helper",
    .program = "/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.helper",
    .user_name = "_bwagentbridge",
    .mach_service = "de.frederikstadler.bitwarden-agent-credential-bridge.helper",
    .binary_sha256 = "e072091af0e8a40cb74dcba6563687af03648839b91787fc20dbb8af0f4d571c",
    .plist_sha256 = "56b162b6263c4ceec673d49b3d91e826a05ab88cdd8c1ce03756b13d46ef6858",
    .demand_activation_only = true,
  };
  return value;
}

static bw_lifecycle_request request(fake_host *host, int binary_parent, int plist_parent) {
  static const unsigned char binary[] = "binary-bytes";
  static const unsigned char plist[] = "plist-bytes";
  bw_lifecycle_request value = {
    .binary_parent_fd = binary_parent, .plist_parent_fd = plist_parent,
    .binary_bytes = binary, .binary_length = sizeof(binary),
    .plist_bytes = plist, .plist_length = sizeof(plist),
    .file_owner = getuid(), .file_group = getgid(),
    .directory_ops = {
      .context = host, .probe_name = account_name, .probe_unique_id = account_uid,
      .probe_generated_uid = account_guid, .create_record = account_create,
      .read_record = account_read, .delete_record = account_delete,
    },
    .account_candidate = account_candidate(),
    .launchd_ops = {
      .context = host, .probe_label = job_label, .probe_mach_service = job_mach,
      .bootstrap = job_bootstrap, .read_job = job_read, .activate = job_activate,
      .verify_process = process_verify, .exercise_denial = denial,
      .stop_process = process_stop, .bootout = job_bootout,
    },
    .job_candidate = job_candidate(),
  };
  host->plist_parent_fd = plist_parent;
  return value;
}

static bool path_absent(int parent_fd, const char *name) {
  struct stat value;
  return fstatat(parent_fd, name, &value, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 2;
  char root[] = "/tmp/bw-lifecycle-controller.XXXXXX";
  if (mkdtemp(root) == NULL) return 1;
  int binary_parent = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int plist_parent = dup(binary_parent);
  if (binary_parent < 0 || plist_parent < 0) return 1;
  const char *binary_name = "de.frederikstadler.bitwarden-agent-credential-bridge.helper";
  const char *plist_name = "de.frederikstadler.bitwarden-agent-credential-bridge.helper.plist";

  fake_host clean = {.activation_result = BW_JOB_OK};
  bw_lifecycle_request clean_request = request(&clean, binary_parent, plist_parent);
  bw_lifecycle_report clean_report = bw_run_lifecycle(&clean_request);
  bool clean_complete = clean_report.preflight_complete && clean_report.mutation_complete &&
      clean_report.denial_verified && clean_report.cleanup_complete &&
      !clean_report.manual_recovery_required && path_absent(binary_parent, binary_name) &&
      path_absent(plist_parent, plist_name) && !clean.account_present && !clean.job_present;

  int collision_fd = openat(binary_parent, binary_name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  if (collision_fd < 0 || close(collision_fd) != 0) return 1;
  fake_host collision = {.activation_result = BW_JOB_OK};
  bw_lifecycle_request collision_request = request(&collision, binary_parent, plist_parent);
  bw_lifecycle_report collision_report = bw_run_lifecycle(&collision_request);
  bool collision_no_mutation = !collision_report.preflight_complete &&
      !collision.account_create_called && !collision.job_bootstrap_called;
  (void)unlinkat(binary_parent, binary_name, 0);

  fake_host account_drift = {.activation_result = BW_JOB_OK, .account_drift_after_create = true};
  bw_lifecycle_request drift_request = request(&account_drift, binary_parent, plist_parent);
  bw_lifecycle_report drift_report = bw_run_lifecycle(&drift_request);
  bool account_ambiguity_preserved = drift_report.preflight_complete &&
      drift_report.manual_recovery_required && account_drift.account_present &&
      !account_drift.account_delete_called && !account_drift.job_bootstrap_called;
  account_drift.account_present = false;

  fake_host create_ambiguous = {
    .activation_result = BW_JOB_OK, .account_create_ambiguous = true,
  };
  bw_lifecycle_request create_ambiguous_request = request(
      &create_ambiguous, binary_parent, plist_parent);
  bw_lifecycle_report create_ambiguous_report = bw_run_lifecycle(&create_ambiguous_request);
  bool ambiguous_create_reported = create_ambiguous_report.cleanup_attempted &&
      create_ambiguous_report.manual_recovery_required && create_ambiguous.account_present &&
      !create_ambiguous.account_delete_called;
  create_ambiguous.account_present = false;

  fake_host activation_ambiguous = {.activation_result = BW_JOB_AMBIGUOUS};
  bw_lifecycle_request ambiguous_request = request(&activation_ambiguous, binary_parent, plist_parent);
  bw_lifecycle_report ambiguous_report = bw_run_lifecycle(&ambiguous_request);
  bool ambiguous_activation_cleaned = !ambiguous_report.mutation_complete &&
      ambiguous_report.cleanup_complete && activation_ambiguous.job_stop_called &&
      activation_ambiguous.job_bootout_called && !activation_ambiguous.account_present &&
      path_absent(binary_parent, binary_name) && path_absent(plist_parent, plist_name);

  fake_host replacement = {
    .activation_result = BW_JOB_OK, .replace_plist_on_denial = true,
  };
  bw_lifecycle_request replacement_request = request(&replacement, binary_parent, plist_parent);
  bw_lifecycle_report replacement_report = bw_run_lifecycle(&replacement_request);
  struct stat foreign;
  bool foreign_plist_preserved = replacement_report.denial_verified &&
      replacement_report.manual_recovery_required &&
      fstatat(plist_parent, plist_name, &foreign, AT_SYMLINK_NOFOLLOW) == 0 &&
      foreign.st_size == 8 && path_absent(binary_parent, binary_name) &&
      !replacement.account_present && !replacement.job_present;
  (void)unlinkat(plist_parent, plist_name, 0);

  bool fixture_cleanup = close(plist_parent) == 0 && close(binary_parent) == 0 && rmdir(root) == 0;
  if (!(clean_complete && collision_no_mutation && account_ambiguity_preserved &&
      ambiguous_create_reported &&
      ambiguous_activation_cleaned && foreign_plist_preserved && fixture_cleanup)) return 1;
  printf("{\"schema_version\":1,\"clean_complete\":true,"
      "\"collision_no_mutation\":true,\"account_ambiguity_preserved\":true,"
      "\"ambiguous_create_reported\":true,"
      "\"ambiguous_activation_cleaned\":true,\"foreign_plist_preserved\":true,"
      "\"fixture_cleanup\":true}\n");
  return 0;
}
