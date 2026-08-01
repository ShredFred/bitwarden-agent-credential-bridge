#ifndef BW_AGENT_MACOS_LAUNCHCTL_JOB_ADAPTER_H
#define BW_AGENT_MACOS_LAUNCHCTL_JOB_ADAPTER_H

#include "macos-fixed-command-runner.h"
#include "macos-launchd-job-ownership.h"

#include <sys/types.h>

typedef bw_launchd_probe (*bw_mach_presence_probe)(void *context, const char *fixed_name);
typedef bool (*bw_mach_denial_probe)(
    void *context, const bw_launchd_job_record *identity, pid_t expected_helper_pid);
typedef bool (*bw_job_artifact_probe)(void *context, const bw_launchd_job_record *identity);

typedef struct {
  bw_fixed_command_runner run;
  bw_mach_presence_probe mach_presence;
  bw_mach_denial_probe denial;
  bw_job_artifact_probe artifacts;
  void *probe_context;
  void *artifact_context;
  bw_launchd_job_record expected;
  pid_t verified_pid;
} bw_launchctl_job_adapter;

bool bw_init_launchctl_job_ops(
    bw_launchctl_job_adapter *adapter,
    bw_fixed_command_runner runner,
    bw_mach_presence_probe mach_presence,
    bw_mach_denial_probe denial,
    bw_job_artifact_probe artifacts,
    void *probe_context,
    void *artifact_context,
    const bw_launchd_job_record *expected,
    bw_launchd_ops *ops);

#endif
