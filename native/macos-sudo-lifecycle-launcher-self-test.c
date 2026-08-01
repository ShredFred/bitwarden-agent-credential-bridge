#include "macos-sudo-lifecycle-launcher.h"

#include <mach-o/dyld.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char SUCCESS_OUTPUT[] =
    "{\"schema_version\":1,\"mutation_complete\":true,\"denial_verified\":true,"
    "\"cleanup_complete\":true,\"manual_recovery_required\":false}\n";

int main(int argc, char **argv) {
  bw_lifecycle_approval_bindings bindings;
  memset(&bindings, 0x44, sizeof(bindings));
  if (argc == 2 && strcmp(argv[1], "--fixture-runner") == 0) {
    int descriptor_flags = fcntl(STDIN_FILENO, F_GETFD);
    bool stdin_survived_exec = descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) == 0;
    bool approved = stdin_survived_exec &&
        bw_receive_and_consume_lifecycle_approval(STDIN_FILENO, &bindings);
    if (approved) (void)write(STDOUT_FILENO, SUCCESS_OUTPUT, sizeof(SUCCESS_OUTPUT) - 1);
    return approved ? 0 : 1;
  }
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  char self[4096];
  uint32_t length = sizeof(self);
  if (_NSGetExecutablePath(self, &length) != 0) return 1;
  bw_set_lifecycle_approval_nonce_for_test(0xC1);
  bw_sudo_lifecycle_result result = bw_run_sudo_lifecycle_fixture(self, &bindings);
  bool all = result.child_started && result.challenge_answered && result.child_exited_cleanly &&
      result.child_reported_denial && result.child_reported_cleanup &&
      bw_lifecycle_launcher_branch_fixture(true, true, true) == 1 &&
      bw_lifecycle_launcher_branch_fixture(false, true, true) == 2 &&
      bw_lifecycle_launcher_branch_fixture(true, true, false) == 3 &&
      bw_lifecycle_launcher_branch_fixture(false, false, false) == 4;
  (void)printf(
      "{\"schema_version\":1,\"child_started\":%s,\"challenge_answered\":%s,"
      "\"child_exited_cleanly\":%s,\"denial_verified\":%s,\"cleanup_complete\":%s,"
      "\"branch_selection_verified\":%s}\n",
      result.child_started ? "true" : "false", result.challenge_answered ? "true" : "false",
      result.child_exited_cleanly ? "true" : "false",
      result.child_reported_denial ? "true" : "false",
      result.child_reported_cleanup ? "true" : "false",
      all ? "true" : "false");
  return all ? 0 : 1;
}
