#include "macos-sudo-lifecycle-launcher.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define MODE "--run-approved-denial-lifecycle"

static const char SUCCESS[] =
    "{\"schema_version\":1,\"mutation_complete\":true,\"denial_verified\":true,"
    "\"cleanup_complete\":true,\"manual_recovery_required\":false}\n";

static bool write_success(void) {
  size_t offset = 0;
  while (offset < sizeof(SUCCESS) - 1) {
    ssize_t count = write(STDOUT_FILENO, SUCCESS + offset, sizeof(SUCCESS) - 1 - offset);
    if (count > 0) { offset += (size_t)count; continue; }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

int main(int argc, char **argv) {
  if (argc != 2 || argv == NULL || argv[0] == NULL || argv[1] == NULL ||
      strcmp(argv[1], MODE) != 0) return 64;
  bw_sudo_lifecycle_result result = bw_run_fixed_sudo_lifecycle();
  if (!result.child_started || !result.challenge_answered || !result.child_exited_cleanly ||
      !result.child_reported_denial || !result.child_reported_cleanup ||
      !result.provisioner_selected || result.runner_collision_detected ||
      result.provisioner_unavailable || result.runner_state_unknown) return 1;
  return write_success() ? 0 : 1;
}
