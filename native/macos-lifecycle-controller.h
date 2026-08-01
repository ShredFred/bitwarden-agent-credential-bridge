#ifndef BW_AGENT_MACOS_LIFECYCLE_CONTROLLER_H
#define BW_AGENT_MACOS_LIFECYCLE_CONTROLLER_H

#include "macos-account-ownership.h"
#include "macos-launchd-job-ownership.h"
#include "macos-retained-file-ops.h"

#include <stdbool.h>
#include <stddef.h>

typedef bool (*bw_owned_artifact_binder)(
    void *context,
    const bw_owned_file *binary,
    const bw_owned_file *plist);

typedef struct {
  int binary_parent_fd;
  int plist_parent_fd;
  const unsigned char *binary_bytes;
  size_t binary_length;
  const unsigned char *plist_bytes;
  size_t plist_length;
  uid_t file_owner;
  gid_t file_group;
  bw_directory_ops directory_ops;
  bw_account_record account_candidate;
  bw_launchd_ops launchd_ops;
  bw_launchd_job_record job_candidate;
  bw_owned_artifact_binder bind_owned_artifacts;
  void *artifact_binding_context;
} bw_lifecycle_request;

typedef struct {
  bool preflight_complete;
  bool account_created_and_verified;
  bool binary_published_and_verified;
  bool plist_published_and_verified;
  bool job_bootstrapped_and_verified;
  bool process_activated_and_verified;
  bool denial_verified;
  bool cleanup_attempted;
  bool job_cleanup_complete;
  bool plist_cleanup_complete;
  bool binary_cleanup_complete;
  bool account_cleanup_complete;
  bool final_absence_complete;
  bool mutation_complete;
  bool cleanup_complete;
  bool manual_recovery_required;
} bw_lifecycle_report;

bw_lifecycle_report bw_run_lifecycle(const bw_lifecycle_request *request);

#endif
