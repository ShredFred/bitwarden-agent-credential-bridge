#include "macos-runner-provisioning.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RUNNER_NAME "de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-runner"

typedef struct {
  int parent_fd;
  bool replace;
  bool succeed;
  int calls;
} fake_executor;

static bool execute(void *raw, int runner_fd) {
  fake_executor *fake = raw;
  struct stat retained;
  if (fake == NULL || runner_fd < 0 || fstat(runner_fd, &retained) != 0 ||
      !S_ISREG(retained.st_mode)) return false;
  fake->calls += 1;
  if (fake->replace) {
    if (unlinkat(fake->parent_fd, RUNNER_NAME, 0) != 0) return false;
    int replacement = openat(fake->parent_fd, RUNNER_NAME,
        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    static const char foreign[] = "foreign";
    bool written = replacement >= 0 &&
        write(replacement, foreign, sizeof(foreign)) == (ssize_t)sizeof(foreign);
    if (replacement >= 0 && close(replacement) != 0) written = false;
    if (!written) return false;
  }
  return fake->succeed;
}

static bw_runner_provisioning_request request(int parent, fake_executor *fake) {
  static const unsigned char bytes[] = "signed-runner-bytes";
  return (bw_runner_provisioning_request){
    .parent_fd = parent, .runner_bytes = bytes, .runner_length = sizeof(bytes),
    .owner = getuid(), .group = getgid(), .test_execute_retained_fd = execute,
    .test_execution_context = fake,
  };
}

static bool path_absent(int parent) {
  struct stat value;
  return fstatat(parent, RUNNER_NAME, &value, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  char root[] = "/tmp/bw-runner-provision.XXXXXX";
  if (mkdtemp(root) == NULL) return 1;
  int parent = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent < 0) return 1;

  fake_executor success = {.parent_fd = parent, .succeed = true};
  bw_runner_provisioning_request success_request = request(parent, &success);
  bw_runner_provisioning_report clean = bw_provision_run_cleanup_runner(&success_request);
  bool clean_complete = clean.preflight_absent && clean.runner_published_and_verified &&
      clean.execution_attempted && clean.execution_succeeded && clean.cleanup_attempted &&
      clean.cleanup_complete && clean.final_absence_complete && !clean.collision_preserved &&
      !clean.manual_recovery_required && success.calls == 1 && path_absent(parent);

  int collision_fd = openat(parent, RUNNER_NAME,
      O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  static const char collision_bytes[] = "collision";
  bool collision_created = collision_fd >= 0 &&
      write(collision_fd, collision_bytes, sizeof(collision_bytes)) ==
          (ssize_t)sizeof(collision_bytes) && close(collision_fd) == 0;
  fake_executor collision_fake = {.parent_fd = parent, .succeed = true};
  bw_runner_provisioning_request collision_request = request(parent, &collision_fake);
  bw_runner_provisioning_report collision = bw_provision_run_cleanup_runner(&collision_request);
  struct stat collision_stat;
  bool collision_preserved = collision_created && collision.collision_preserved &&
      !collision.preflight_absent && !collision.runner_published_and_verified &&
      !collision.execution_attempted && !collision.cleanup_attempted &&
      !collision.manual_recovery_required && collision_fake.calls == 0 &&
      fstatat(parent, RUNNER_NAME, &collision_stat, AT_SYMLINK_NOFOLLOW) == 0 &&
      collision_stat.st_size == (off_t)sizeof(collision_bytes) &&
      unlinkat(parent, RUNNER_NAME, 0) == 0;

  fake_executor replacement = {.parent_fd = parent, .replace = true, .succeed = true};
  bw_runner_provisioning_request replacement_request = request(parent, &replacement);
  bw_runner_provisioning_report replaced = bw_provision_run_cleanup_runner(&replacement_request);
  struct stat replacement_stat;
  bool replacement_preserved = replaced.runner_published_and_verified &&
      replaced.execution_attempted && replaced.execution_succeeded && replaced.cleanup_attempted &&
      !replaced.cleanup_complete && !replaced.final_absence_complete &&
      replaced.manual_recovery_required && replacement.calls == 1 &&
      fstatat(parent, RUNNER_NAME, &replacement_stat, AT_SYMLINK_NOFOLLOW) == 0 &&
      replacement_stat.st_size == 8 && unlinkat(parent, RUNNER_NAME, 0) == 0;

  bool fixture_cleanup = close(parent) == 0 && rmdir(root) == 0;
  bool all = clean_complete && collision_preserved && replacement_preserved && fixture_cleanup;
  (void)printf(
      "{\"schema_version\":1,\"clean_complete\":%s,\"collision_preserved\":%s,"
      "\"replacement_preserved\":%s,\"fixture_cleanup\":%s}\n",
      clean_complete ? "true" : "false", collision_preserved ? "true" : "false",
      replacement_preserved ? "true" : "false", fixture_cleanup ? "true" : "false");
  return all ? 0 : 1;
}
