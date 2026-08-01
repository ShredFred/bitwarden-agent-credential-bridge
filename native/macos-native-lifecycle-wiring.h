#ifndef BW_AGENT_MACOS_NATIVE_LIFECYCLE_WIRING_H
#define BW_AGENT_MACOS_NATIVE_LIFECYCLE_WIRING_H

#include "macos-dscl-directory-adapter.h"
#include "macos-launchctl-job-adapter.h"
#include "macos-lifecycle-controller.h"
#include "macos-lifecycle-approval.h"

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
  bw_lifecycle_approval_bindings approval_bindings;
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
    const unsigned char requirement_sha256[BW_APPROVAL_DIGEST_BYTES],
    uid_t owner,
    gid_t group,
    const bw_account_record *account,
    const bw_launchd_job_record *job);

bw_lifecycle_report bw_run_authorized_native_lifecycle(
    bw_native_lifecycle_wiring *wiring,
    int approval_socket_fd);

/* Artifact buffers must remain valid until the authorized lifecycle call returns. */

#if defined(BW_NATIVE_WIRING_TESTING)
/* Fixture-only compatibility entry point; production must supply approval. */
bw_lifecycle_report bw_run_native_lifecycle_for_test(bw_native_lifecycle_wiring *wiring);

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
    const unsigned char requirement_sha256[BW_APPROVAL_DIGEST_BYTES],
    uid_t owner,
    gid_t group,
    const bw_account_record *account,
    const bw_launchd_job_record *job);
#endif

#endif
