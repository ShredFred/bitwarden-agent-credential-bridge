#include "macos-lifecycle-controller.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define FIXED_BINARY_NAME "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define FIXED_PLIST_NAME FIXED_BINARY_NAME ".plist"
#define MAX_ARTIFACT_BYTES (64U * 1024U * 1024U)

static bool child_absent(int parent_fd, const char *name) {
  struct stat value;
  if (fstatat(parent_fd, name, &value, AT_SYMLINK_NOFOLLOW) == 0) return false;
  return errno == ENOENT;
}

static bool parent_directory(int fd, uid_t expected_owner) {
  struct stat value;
  return fd >= 0 && fstat(fd, &value) == 0 && S_ISDIR(value.st_mode) &&
      value.st_uid == expected_owner && (value.st_mode & 0022U) == 0;
}

static bool digest_matches(const unsigned char *bytes, size_t length, const char *expected) {
  if (bytes == NULL || length == 0 || length > MAX_ARTIFACT_BYTES || expected == NULL ||
      strlen(expected) != 64) return false;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  if (CC_SHA256(bytes, (CC_LONG)length, digest) == NULL) return false;
  char hex[65];
  for (size_t index = 0; index < sizeof(digest); index += 1) {
    (void)snprintf(hex + (index * 2), 3, "%02x", digest[index]);
  }
  hex[64] = '\0';
  return strcmp(hex, expected) == 0;
}

static bool valid_request(const bw_lifecycle_request *request) {
  return request != NULL && parent_directory(request->binary_parent_fd, request->file_owner) &&
      parent_directory(request->plist_parent_fd, request->file_owner) &&
      request->binary_bytes != NULL &&
      request->plist_bytes != NULL && request->binary_length > 0 && request->plist_length > 0 &&
      request->binary_length <= MAX_ARTIFACT_BYTES && request->plist_length <= MAX_ARTIFACT_BYTES &&
      digest_matches(request->binary_bytes, request->binary_length,
          request->job_candidate.binary_sha256) &&
      digest_matches(request->plist_bytes, request->plist_length,
          request->job_candidate.plist_sha256);
}

static bool file_cleanup(bw_owned_file *owned) {
  if (!owned->created) {
    bw_close_owned_file(owned);
    return true;
  }
  bool complete = bw_unlink_owned_file(owned) == BW_FILE_OK;
  bw_close_owned_file(owned);
  return complete;
}

bw_lifecycle_report bw_run_lifecycle(const bw_lifecycle_request *request) {
  bw_lifecycle_report report = {0};
  if (!valid_request(request)) return report;

  bw_owned_account account;
  bw_owned_launchd_job job;
  bw_owned_file binary = {.parent_fd = -1, .file_fd = -1};
  bw_owned_file plist = {.parent_fd = -1, .file_fd = -1};
  bw_init_owned_account(&account);
  bw_init_owned_launchd_job(&job);

  if (!child_absent(request->binary_parent_fd, FIXED_BINARY_NAME) ||
      !child_absent(request->plist_parent_fd, FIXED_PLIST_NAME) ||
      bw_prepare_owned_account(&request->directory_ops, &request->account_candidate, &account) !=
          BW_ACCOUNT_OK ||
      bw_prepare_owned_launchd_job(&request->launchd_ops, &request->job_candidate, &job) != BW_JOB_OK) {
    return report;
  }
  report.preflight_complete = true;

  bool mutation_attempted = true;
  bw_account_result account_result = bw_create_owned_account(&request->directory_ops, &account);
  report.account_created_and_verified = account_result == BW_ACCOUNT_OK;
  if (!report.account_created_and_verified) goto cleanup;

  bw_file_result binary_result = bw_publish_owned_file(
      request->binary_parent_fd, FIXED_BINARY_NAME, request->binary_bytes,
      request->binary_length, 0555, request->file_owner, request->file_group, &binary);
  report.binary_published_and_verified = binary_result == BW_FILE_OK;
  if (!report.binary_published_and_verified) goto cleanup;

  bw_file_result plist_result = bw_publish_owned_file(
      request->plist_parent_fd, FIXED_PLIST_NAME, request->plist_bytes,
      request->plist_length, 0644, request->file_owner, request->file_group, &plist);
  report.plist_published_and_verified = plist_result == BW_FILE_OK;
  if (!report.plist_published_and_verified) goto cleanup;

  bw_job_result bootstrap_result = bw_bootstrap_owned_launchd_job(&request->launchd_ops, &job);
  report.job_bootstrapped_and_verified = bootstrap_result == BW_JOB_OK;
  if (!report.job_bootstrapped_and_verified) goto cleanup;

  bw_job_result activation_result =
      bw_activate_and_verify_owned_launchd_job(&request->launchd_ops, &job);
  report.process_activated_and_verified = activation_result == BW_JOB_OK;
  if (!report.process_activated_and_verified) goto cleanup;

  report.denial_verified =
      bw_exercise_owned_launchd_denial(&request->launchd_ops, &job) == BW_JOB_OK;
  report.mutation_complete = report.denial_verified;

cleanup:
  report.cleanup_attempted = mutation_attempted;

  bw_job_result job_cleanup = bw_cleanup_owned_launchd_job(&request->launchd_ops, &job);
  report.job_cleanup_complete = job_cleanup == BW_JOB_OK ||
      (job_cleanup == BW_JOB_NO_EFFECT && !job.bootstrap_attempted);
  report.plist_cleanup_complete = file_cleanup(&plist);
  report.binary_cleanup_complete = file_cleanup(&binary);

  bw_account_result account_cleanup =
      bw_delete_owned_account(&request->directory_ops, &account);
  report.account_cleanup_complete = account_cleanup == BW_ACCOUNT_OK ||
      (account_cleanup == BW_ACCOUNT_NO_EFFECT && !account.created);
  report.final_absence_complete =
      child_absent(request->binary_parent_fd, FIXED_BINARY_NAME) &&
      child_absent(request->plist_parent_fd, FIXED_PLIST_NAME) &&
      request->directory_ops.probe_name(
          request->directory_ops.context, request->account_candidate.name) == BW_DIRECTORY_ABSENT &&
      request->directory_ops.probe_unique_id(
          request->directory_ops.context, request->account_candidate.unique_id) == BW_DIRECTORY_ABSENT &&
      request->directory_ops.probe_generated_uid(
          request->directory_ops.context, request->account_candidate.generated_uid) ==
          BW_DIRECTORY_ABSENT &&
      request->launchd_ops.probe_label(
          request->launchd_ops.context, request->job_candidate.label) == BW_LAUNCHD_ABSENT &&
      request->launchd_ops.probe_mach_service(
          request->launchd_ops.context, request->job_candidate.mach_service) == BW_LAUNCHD_ABSENT;
  report.cleanup_complete = report.job_cleanup_complete && report.plist_cleanup_complete &&
      report.binary_cleanup_complete && report.account_cleanup_complete &&
      report.final_absence_complete;
  report.manual_recovery_required = report.cleanup_attempted && !report.cleanup_complete;
  return report;
}
