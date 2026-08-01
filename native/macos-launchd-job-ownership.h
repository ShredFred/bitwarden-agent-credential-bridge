#ifndef BW_AGENT_MACOS_LAUNCHD_JOB_OWNERSHIP_H
#define BW_AGENT_MACOS_LAUNCHD_JOB_OWNERSHIP_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
  BW_LAUNCHD_ABSENT = 0,
  BW_LAUNCHD_PRESENT = 1,
  BW_LAUNCHD_PROBE_ERROR = 2,
} bw_launchd_probe;

typedef enum {
  BW_JOB_OK = 0,
  BW_JOB_NO_EFFECT = 1,
  BW_JOB_AMBIGUOUS = 2,
  BW_JOB_ERROR = 3,
} bw_job_result;

typedef struct {
  char label[128];
  char program[256];
  char user_name[64];
  char mach_service[128];
  char binary_sha256[65];
  char plist_sha256[65];
  bool demand_activation_only;
} bw_launchd_job_record;

typedef struct {
  void *context;
  bw_launchd_probe (*probe_label)(void *context, const char *label);
  bw_launchd_probe (*probe_mach_service)(void *context, const char *mach_service);
  bw_job_result (*bootstrap)(void *context, const bw_launchd_job_record *record);
  bool (*read_job)(void *context, const char *label, bw_launchd_job_record *record);
  bw_job_result (*activate)(void *context, const bw_launchd_job_record *record);
  bool (*verify_process)(void *context, const bw_launchd_job_record *record);
  bool (*exercise_denial)(void *context, const bw_launchd_job_record *record);
  bw_job_result (*stop_process)(void *context, const bw_launchd_job_record *record);
  bw_job_result (*bootout)(void *context, const bw_launchd_job_record *record);
} bw_launchd_ops;

typedef struct {
  uint32_t state_magic;
  bw_launchd_job_record identity;
  bool prepared;
  bool bootstrap_attempted;
  bool bootstrapped;
  bool verified;
  bool activation_attempted;
  bool process_verified;
  bool denial_verified;
} bw_owned_launchd_job;

void bw_init_owned_launchd_job(bw_owned_launchd_job *owned);
bw_job_result bw_prepare_owned_launchd_job(
    const bw_launchd_ops *ops,
    const bw_launchd_job_record *candidate,
    bw_owned_launchd_job *owned);
bw_job_result bw_bootstrap_owned_launchd_job(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned);
bw_job_result bw_verify_owned_launchd_job(
    const bw_launchd_ops *ops,
    const bw_owned_launchd_job *owned);
bw_job_result bw_activate_and_verify_owned_launchd_job(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned);
bw_job_result bw_exercise_owned_launchd_denial(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned);
bw_job_result bw_cleanup_owned_launchd_job(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned);

#endif
