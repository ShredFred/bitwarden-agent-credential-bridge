#ifndef BW_AGENT_MACOS_NATIVE_LIFECYCLE_WIRING_H
#define BW_AGENT_MACOS_NATIVE_LIFECYCLE_WIRING_H

#include "macos-dscl-directory-adapter.h"
#include "macos-launchctl-job-adapter.h"
#include "macos-lifecycle-controller.h"

typedef struct {
  const bw_owned_file *binary;
  const bw_owned_file *plist;
  const unsigned char *binary_bytes;
  size_t binary_length;
  const unsigned char *plist_bytes;
  size_t plist_length;
  uid_t owner;
  gid_t group;
  bool bound;
  int binary_parent_fd;
  int plist_parent_fd;
  bool fixture_paths;
} bw_native_artifact_binding;

typedef struct {
  bw_dscl_directory_adapter directory_adapter;
  bw_launchctl_job_adapter launchctl_adapter;
  bw_native_artifact_binding artifact_binding;
  bw_lifecycle_request request;
} bw_native_lifecycle_wiring;

/* Do not copy or move an initialized wiring object; its callbacks retain interior pointers. */

bool bw_init_native_lifecycle_wiring(
    bw_native_lifecycle_wiring *wiring,
    bw_fixed_command_runner runner,
    bw_mach_presence_probe mach_presence,
    bw_mach_denial_probe denial,
    void *mach_context,
    int binary_parent_fd,
    int plist_parent_fd,
    const unsigned char *binary_bytes,
    size_t binary_length,
    const unsigned char *plist_bytes,
    size_t plist_length,
    uid_t owner,
    gid_t group,
    const bw_account_record *account,
    const bw_launchd_job_record *job);

bw_lifecycle_report bw_run_native_lifecycle(bw_native_lifecycle_wiring *wiring);

/* Artifact buffers must remain immutable and valid until bw_run_native_lifecycle returns. */

#if defined(BW_NATIVE_WIRING_TESTING)
bool bw_init_native_lifecycle_wiring_for_test(
    bw_native_lifecycle_wiring *wiring,
    bw_fixed_command_runner runner,
    bw_mach_presence_probe mach_presence,
    bw_mach_denial_probe denial,
    void *mach_context,
    int binary_parent_fd,
    int plist_parent_fd,
    const unsigned char *binary_bytes,
    size_t binary_length,
    const unsigned char *plist_bytes,
    size_t plist_length,
    uid_t owner,
    gid_t group,
    const bw_account_record *account,
    const bw_launchd_job_record *job);
#endif

#endif
