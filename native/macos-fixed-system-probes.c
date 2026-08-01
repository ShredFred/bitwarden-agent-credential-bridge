#include "macos-fixed-system-probes.h"

#include <string.h>

#define BUNDLE_MAGIC UINT32_C(0x42575350)

void bw_init_fixed_system_probes(bw_fixed_system_probes *probes) {
  if (probes == NULL) return;
  memset(probes, 0, sizeof(*probes));
  bw_init_launchctl_presence_context(&probes->presence);
  bw_init_mach_probe_context(&probes->denial);
  probes->state_magic = BUNDLE_MAGIC;
}

bw_launchd_probe bw_fixed_system_presence_probe(void *raw, const char *fixed_name) {
  bw_fixed_system_probes *probes = raw;
  if (probes == NULL || probes->state_magic != BUNDLE_MAGIC) return BW_LAUNCHD_PROBE_ERROR;
  return bw_probe_fixed_system_mach_name(&probes->presence, fixed_name);
}

bool bw_fixed_system_denial_probe(
    void *raw, const bw_launchd_job_record *identity, pid_t expected_helper_pid) {
  bw_fixed_system_probes *probes = raw;
  return probes != NULL && probes->state_magic == BUNDLE_MAGIC &&
      bw_fixed_mach_denial_probe(&probes->denial, identity, expected_helper_pid);
}
