#ifndef BW_AGENT_MACOS_RUNNER_PROVISIONING_H
#define BW_AGENT_MACOS_RUNNER_PROVISIONING_H

#include "macos-retained-file-ops.h"

#include <stdbool.h>
#include <stddef.h>

#if defined(BW_RUNNER_PROVISIONING_TESTING)
typedef bool (*bw_retained_fd_runner_executor)(void *context, int runner_fd);
#endif

typedef struct {
  int parent_fd;
  const unsigned char *runner_bytes;
  size_t runner_length;
  uid_t owner;
  gid_t group;
#if defined(BW_RUNNER_PROVISIONING_TESTING)
  bw_retained_fd_runner_executor test_execute_retained_fd;
  void *test_execution_context;
#endif
} bw_runner_provisioning_request;

typedef struct {
  bool preflight_absent;
  bool runner_published_and_verified;
  bool execution_attempted;
  bool execution_succeeded;
  bool cleanup_attempted;
  bool cleanup_complete;
  bool final_absence_complete;
  bool collision_preserved;
  bool manual_recovery_required;
} bw_runner_provisioning_report;

bw_runner_provisioning_report bw_provision_run_cleanup_runner(
    const bw_runner_provisioning_request *request);

#endif
