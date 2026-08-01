#ifndef BW_AGENT_MACOS_SUDO_LIFECYCLE_LAUNCHER_H
#define BW_AGENT_MACOS_SUDO_LIFECYCLE_LAUNCHER_H

#include "macos-lifecycle-approval.h"

#include <stdbool.h>

typedef struct {
  bool child_started;
  bool challenge_answered;
  bool child_exited_cleanly;
  bool child_reported_denial;
  bool child_reported_cleanup;
  bool provisioner_selected;
  bool runner_collision_detected;
  bool provisioner_unavailable;
  bool runner_state_unknown;
} bw_sudo_lifecycle_result;

/*
 * Run only the fixed root-owned lifecycle runner through /usr/bin/sudo -k.
 * There is no executable, argv, environment, command, or output configuration.
 */
bw_sudo_lifecycle_result bw_run_fixed_sudo_lifecycle(void);

#if defined(BW_SUDO_LAUNCHER_TESTING)
int bw_lifecycle_launcher_branch_fixture(
    bool runner_absent, bool runner_state_known, bool provisioner_ready);
bw_sudo_lifecycle_result bw_run_sudo_lifecycle_fixture(
    const char *fixture_executable,
    const bw_lifecycle_approval_bindings *approved);
#endif

#endif
