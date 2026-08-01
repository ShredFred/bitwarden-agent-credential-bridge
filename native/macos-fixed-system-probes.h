#ifndef BW_AGENT_MACOS_FIXED_SYSTEM_PROBES_H
#define BW_AGENT_MACOS_FIXED_SYSTEM_PROBES_H

#include "macos-launchctl-mach-presence.h"
#include "macos-mach-service-probes.h"

typedef struct {
  uint32_t state_magic;
  bw_launchctl_presence_context presence;
  bw_mach_probe_context denial;
} bw_fixed_system_probes;

void bw_init_fixed_system_probes(bw_fixed_system_probes *probes);
bw_launchd_probe bw_fixed_system_presence_probe(void *context, const char *fixed_name);
bool bw_fixed_system_denial_probe(
    void *context, const bw_launchd_job_record *identity, pid_t expected_helper_pid);

#endif
