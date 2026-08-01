#include "macos-elevation-identity.h"
#include "macos-runner-provisioning.h"

#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(BW_PROVISIONER_RUNNER_HEADER)
#error "BW_PROVISIONER_RUNNER_HEADER must name the generated packaged-runner header"
#endif
#include BW_PROVISIONER_RUNNER_HEADER

#define MODE "--provision-run-cleanup-approved-denial-lifecycle"
#define RUNNER_PARENT "/Library/PrivilegedHelperTools"

static bool exact_runner_contract(void) {
  if (BW_PROVISIONER_RUNNER_LENGTH < 1 || BW_PROVISIONER_RUNNER_LENGTH > 8U * 1024U * 1024U)
    return false;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  bool valid = CC_SHA256(BW_PROVISIONER_RUNNER_BYTES,
      (CC_LONG)BW_PROVISIONER_RUNNER_LENGTH, digest) != NULL &&
      memcmp(digest, BW_PROVISIONER_RUNNER_SHA256, sizeof(digest)) == 0;
  memset(digest, 0, sizeof(digest));
  return valid;
}

static bool canonical_parent(int parent_fd) {
  char resolved[PATH_MAX];
  memset(resolved, 0, sizeof(resolved));
  return parent_fd >= 0 && fcntl(parent_fd, F_GETPATH, resolved) == 0 &&
      strcmp(resolved, RUNNER_PARENT) == 0;
}

int main(int argc, char **argv) {
  if (argc != 2 || argv == NULL || argv[0] == NULL || argv[1] == NULL ||
      strcmp(argv[1], MODE) != 0) return 64;
  if (getuid() == 0 || geteuid() != 0 || !bw_stable_direct_sudo_parent() ||
      !exact_runner_contract()) return 77;
  (void)umask(077);
  int parent = open(RUNNER_PARENT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent < 0 || !canonical_parent(parent) || !bw_stable_direct_sudo_parent()) {
    if (parent >= 0) (void)close(parent);
    return 78;
  }
  bw_runner_provisioning_request request = {
    .parent_fd = parent,
    .runner_bytes = BW_PROVISIONER_RUNNER_BYTES,
    .runner_length = BW_PROVISIONER_RUNNER_LENGTH,
    .owner = 0,
    .group = 0,
  };
  bw_runner_provisioning_report report = bw_provision_run_cleanup_runner(&request);
  bool parent_closed = close(parent) == 0;
  if (!parent_closed || !report.preflight_absent ||
      !report.runner_published_and_verified || !report.execution_attempted ||
      !report.execution_succeeded || !report.cleanup_attempted ||
      !report.cleanup_complete || !report.final_absence_complete ||
      report.collision_preserved || report.manual_recovery_required) return 1;
  return 0;
}
