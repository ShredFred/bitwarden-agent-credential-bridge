#ifndef BW_AGENT_MACOS_MACH_SERVICE_PROBES_H
#define BW_AGENT_MACOS_MACH_SERVICE_PROBES_H

#include "macos-launchd-job-ownership.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
  uint32_t state_magic;
} bw_mach_probe_context;

void bw_init_mach_probe_context(bw_mach_probe_context *context);

bool bw_fixed_mach_denial_probe(
    void *context,
    const bw_launchd_job_record *identity,
    pid_t expected_helper_pid);

#if defined(BW_MACH_PROBE_TESTING)
bool bw_test_mach_denial_exchange(
    const char *service_name, pid_t expected_helper_pid, uid_t expected_helper_euid);
#endif

#endif
