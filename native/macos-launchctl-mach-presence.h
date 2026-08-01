#ifndef BW_AGENT_MACOS_LAUNCHCTL_MACH_PRESENCE_H
#define BW_AGENT_MACOS_LAUNCHCTL_MACH_PRESENCE_H

#include "macos-launchd-job-ownership.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t state_magic;
} bw_launchctl_presence_context;

void bw_init_launchctl_presence_context(bw_launchctl_presence_context *context);
bw_launchd_probe bw_probe_fixed_system_mach_name(void *context, const char *fixed_name);

#if defined(BW_LAUNCHCTL_PRESENCE_TESTING)
bool bw_test_snapshot_contains_name(const char *snapshot, size_t length, const char *fixed_name);
#endif

#endif
