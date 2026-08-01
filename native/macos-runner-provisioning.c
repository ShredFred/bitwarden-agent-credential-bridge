#include "macos-runner-provisioning.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RUNNER_NAME "de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-runner"
#define MAX_RUNNER_BYTES (8U * 1024U * 1024U)
#define RUNNER_TIMEOUT_MS UINT64_C(120000)

#if !defined(BW_RUNNER_PROVISIONING_TESTING)
static uint64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return 0;
  return (uint64_t)now.tv_sec * UINT64_C(1000) +
      (uint64_t)now.tv_nsec / UINT64_C(1000000);
}
#endif

static bool absent(int parent_fd) {
  struct stat value;
  return fstatat(parent_fd, RUNNER_NAME, &value, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}

static bool no_extended_acl(int parent_fd) {
  errno = 0;
  acl_t acl = acl_get_fd_np(parent_fd, ACL_TYPE_EXTENDED);
  if (acl == NULL) return errno == ENOENT;
  acl_entry_t entry;
  int found = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  (void)acl_free(acl);
  return found == 0;
}

static bool valid_request(const bw_runner_provisioning_request *request) {
  if (request == NULL || request->parent_fd < 0 || request->runner_bytes == NULL ||
      request->runner_length == 0 || request->runner_length > MAX_RUNNER_BYTES) return false;
#if defined(BW_RUNNER_PROVISIONING_TESTING)
  if (request->test_execute_retained_fd == NULL ||
      request->test_execution_context == NULL) return false;
#endif
  struct stat parent;
  return fstat(request->parent_fd, &parent) == 0 && S_ISDIR(parent.st_mode) &&
      parent.st_uid == request->owner && (parent.st_mode & 0022U) == 0 &&
      no_extended_acl(request->parent_fd);
}

static bool execute_retained_fd(const bw_runner_provisioning_request *request, int runner_fd) {
#if defined(BW_RUNNER_PROVISIONING_TESTING)
  return request->test_execute_retained_fd(request->test_execution_context, runner_fd);
#else
  (void)request;
  long maximum_fd = sysconf(_SC_OPEN_MAX);
  if (maximum_fd < 4 || maximum_fd > 1048576) return false;
  pid_t child = fork();
  if (child < 0) return false;
  if (child == 0) {
    const int execution_fd = 3;
    if ((runner_fd != execution_fd && dup2(runner_fd, execution_fd) < 0) ||
        fcntl(execution_fd, F_SETFD, FD_CLOEXEC) != 0) _exit(126);
    for (long descriptor = execution_fd + 1; descriptor < maximum_fd; descriptor += 1)
      (void)close((int)descriptor);
    char descriptor_path[32];
    int path_length = snprintf(
        descriptor_path, sizeof(descriptor_path), "/dev/fd/%d", execution_fd);
    char *const arguments[] = {(char *)RUNNER_NAME, "--approved-denial-lifecycle", NULL};
    char *const environment[] = {
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", NULL,
    };
    if (path_length > 0 && (size_t)path_length < sizeof(descriptor_path))
      execve(descriptor_path, arguments, environment);
    _exit(126);
  }
  int status = 0;
  uint64_t started = monotonic_ms();
  bool reaped = false;
  while (started != 0 && monotonic_ms() - started < RUNNER_TIMEOUT_MS) {
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) { reaped = true; break; }
    if (waited < 0 && errno != EINTR) break;
    (void)usleep(10000);
  }
  if (!reaped) {
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) return false;
    while (waitpid(child, &status, 0) < 0) {
      if (errno != EINTR) return false;
    }
    return false;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

bw_runner_provisioning_report bw_provision_run_cleanup_runner(
    const bw_runner_provisioning_request *request) {
  bw_runner_provisioning_report report = {0};
  if (!valid_request(request)) return report;
  if (!absent(request->parent_fd)) {
    report.collision_preserved = true;
    return report;
  }
  bw_owned_file runner = {.parent_fd = -1, .file_fd = -1};
  bw_file_result published = bw_publish_owned_file(
      request->parent_fd, RUNNER_NAME, request->runner_bytes, request->runner_length,
      0555, request->owner, request->group, &runner);
  if (published == BW_FILE_NO_EFFECT) report.collision_preserved = true;
  report.preflight_absent = published == BW_FILE_OK;
  bool verified = published == BW_FILE_OK &&
      bw_verify_owned_file(&runner, request->runner_bytes, request->runner_length,
          0555, request->owner, request->group) == BW_FILE_OK;
  report.runner_published_and_verified = verified;
  if (verified) {
    report.execution_attempted = true;
    report.execution_succeeded = execute_retained_fd(request, runner.file_fd);
  }

  report.cleanup_attempted = runner.created;
  if (runner.created) report.cleanup_complete = bw_unlink_owned_file(&runner) == BW_FILE_OK;
  else report.cleanup_complete = true;
  bw_close_owned_file(&runner);
  report.final_absence_complete = absent(request->parent_fd);
  report.cleanup_complete = report.cleanup_complete && report.final_absence_complete;
  report.manual_recovery_required = report.cleanup_attempted && !report.cleanup_complete;
  return report;
}
