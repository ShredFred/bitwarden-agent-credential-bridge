#include "macos-launchd-job-ownership.h"

#include <stddef.h>
#include <string.h>

#define BW_JOB_STATE_MAGIC UINT32_C(0x42574A4F)
#define FIXED_LABEL "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define FIXED_PROGRAM "/Library/PrivilegedHelperTools/" FIXED_LABEL
#define FIXED_USER "_bwagentbridge"

static bool exact_text(const char *value, size_t maximum) {
  if (value == NULL) return false;
  size_t length = strnlen(value, maximum);
  if (length == 0 || length >= maximum) return false;
  for (size_t index = 0; index < length; index += 1) {
    unsigned char byte = (unsigned char)value[index];
    if (byte < 0x21 || byte > 0x7e) return false;
  }
  return true;
}

static bool sha256_text(const char *value) {
  if (!exact_text(value, 65) || strlen(value) != 64) return false;
  for (size_t index = 0; index < 64; index += 1) {
    if (!((value[index] >= '0' && value[index] <= '9') ||
          (value[index] >= 'a' && value[index] <= 'f'))) return false;
  }
  return true;
}

static bool valid_record(const bw_launchd_job_record *record) {
  return record != NULL && strcmp(record->label, FIXED_LABEL) == 0 &&
      strcmp(record->program, FIXED_PROGRAM) == 0 && strcmp(record->user_name, FIXED_USER) == 0 &&
      strcmp(record->mach_service, FIXED_LABEL) == 0 && sha256_text(record->binary_sha256) &&
      sha256_text(record->plist_sha256) && record->demand_activation_only;
}

static bool same_record(const bw_launchd_job_record *left, const bw_launchd_job_record *right) {
  return strcmp(left->label, right->label) == 0 && strcmp(left->program, right->program) == 0 &&
      strcmp(left->user_name, right->user_name) == 0 &&
      strcmp(left->mach_service, right->mach_service) == 0 &&
      strcmp(left->binary_sha256, right->binary_sha256) == 0 &&
      strcmp(left->plist_sha256, right->plist_sha256) == 0 &&
      left->demand_activation_only == right->demand_activation_only;
}

static bool valid_ops(const bw_launchd_ops *ops) {
  return ops != NULL && ops->probe_label != NULL && ops->probe_mach_service != NULL &&
      ops->bootstrap != NULL && ops->read_job != NULL && ops->activate != NULL &&
      ops->verify_process != NULL && ops->exercise_denial != NULL &&
      ops->stop_process != NULL && ops->bootout != NULL;
}

static bool job_absent(const bw_launchd_ops *ops, const bw_launchd_job_record *identity) {
  return ops->probe_label(ops->context, identity->label) == BW_LAUNCHD_ABSENT &&
      ops->probe_mach_service(ops->context, identity->mach_service) == BW_LAUNCHD_ABSENT;
}

static void clear_owned_job(bw_owned_launchd_job *owned) {
  owned->prepared = false;
  owned->bootstrap_attempted = false;
  owned->bootstrapped = false;
  owned->verified = false;
  owned->activation_attempted = false;
  owned->process_verified = false;
  owned->denial_verified = false;
  memset(&owned->identity, 0, sizeof(owned->identity));
}

void bw_init_owned_launchd_job(bw_owned_launchd_job *owned) {
  if (owned == NULL) return;
  memset(owned, 0, sizeof(*owned));
  owned->state_magic = BW_JOB_STATE_MAGIC;
}

bw_job_result bw_prepare_owned_launchd_job(
    const bw_launchd_ops *ops,
    const bw_launchd_job_record *candidate,
    bw_owned_launchd_job *owned) {
  if (!valid_ops(ops) || !valid_record(candidate) || owned == NULL ||
      owned->state_magic != BW_JOB_STATE_MAGIC || owned->prepared || owned->bootstrapped ||
      owned->bootstrap_attempted || owned->verified || owned->activation_attempted) return BW_JOB_ERROR;
  bw_launchd_probe label = ops->probe_label(ops->context, candidate->label);
  bw_launchd_probe mach = ops->probe_mach_service(ops->context, candidate->mach_service);
  if (label == BW_LAUNCHD_PROBE_ERROR || mach == BW_LAUNCHD_PROBE_ERROR) return BW_JOB_ERROR;
  if (label != BW_LAUNCHD_ABSENT || mach != BW_LAUNCHD_ABSENT) return BW_JOB_NO_EFFECT;
  owned->identity = *candidate;
  owned->prepared = true;
  return BW_JOB_OK;
}

bw_job_result bw_verify_owned_launchd_job(
    const bw_launchd_ops *ops,
    const bw_owned_launchd_job *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_JOB_STATE_MAGIC ||
      !owned->prepared || !owned->bootstrapped || !owned->verified ||
      !valid_record(&owned->identity)) return BW_JOB_ERROR;
  bw_launchd_job_record observed;
  memset(&observed, 0, sizeof(observed));
  if (!ops->read_job(ops->context, owned->identity.label, &observed) ||
      !valid_record(&observed) || !same_record(&owned->identity, &observed) ||
      ops->probe_label(ops->context, owned->identity.label) != BW_LAUNCHD_PRESENT ||
      ops->probe_mach_service(ops->context, owned->identity.mach_service) != BW_LAUNCHD_PRESENT) {
    return BW_JOB_AMBIGUOUS;
  }
  return BW_JOB_OK;
}

bw_job_result bw_bootstrap_owned_launchd_job(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_JOB_STATE_MAGIC ||
      !owned->prepared || owned->bootstrapped || !valid_record(&owned->identity)) return BW_JOB_ERROR;
  bw_job_result result = ops->bootstrap(ops->context, &owned->identity);
  if (result == BW_JOB_NO_EFFECT) return BW_JOB_NO_EFFECT;
  owned->bootstrap_attempted = true;
  if (result != BW_JOB_OK) return BW_JOB_AMBIGUOUS;
  owned->bootstrapped = true;
  bw_launchd_job_record observed;
  memset(&observed, 0, sizeof(observed));
  if (!ops->read_job(ops->context, owned->identity.label, &observed) ||
      !valid_record(&observed) || !same_record(&owned->identity, &observed) ||
      ops->probe_label(ops->context, owned->identity.label) != BW_LAUNCHD_PRESENT ||
      ops->probe_mach_service(ops->context, owned->identity.mach_service) != BW_LAUNCHD_PRESENT) {
    return BW_JOB_AMBIGUOUS;
  }
  owned->verified = true;
  return BW_JOB_OK;
}

bw_job_result bw_activate_and_verify_owned_launchd_job(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_JOB_STATE_MAGIC ||
      !owned->verified || owned->activation_attempted || owned->process_verified) return BW_JOB_ERROR;
  if (bw_verify_owned_launchd_job(ops, owned) != BW_JOB_OK) {
    owned->verified = false;
    return BW_JOB_AMBIGUOUS;
  }
  bw_job_result result = ops->activate(ops->context, &owned->identity);
  if (result == BW_JOB_NO_EFFECT) return BW_JOB_NO_EFFECT;
  owned->activation_attempted = true;
  if (result != BW_JOB_OK) return BW_JOB_AMBIGUOUS;
  if (!ops->verify_process(ops->context, &owned->identity)) return BW_JOB_AMBIGUOUS;
  owned->process_verified = true;
  return BW_JOB_OK;
}

bw_job_result bw_exercise_owned_launchd_denial(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_JOB_STATE_MAGIC ||
      !owned->verified || !owned->activation_attempted || !owned->process_verified ||
      owned->denial_verified) return BW_JOB_ERROR;
  if (bw_verify_owned_launchd_job(ops, owned) != BW_JOB_OK) {
    owned->verified = false;
    return BW_JOB_AMBIGUOUS;
  }
  if (!ops->verify_process(ops->context, &owned->identity)) {
    owned->process_verified = false;
    return BW_JOB_AMBIGUOUS;
  }
  if (!ops->exercise_denial(ops->context, &owned->identity)) return BW_JOB_AMBIGUOUS;
  owned->denial_verified = true;
  return BW_JOB_OK;
}

bw_job_result bw_cleanup_owned_launchd_job(
    const bw_launchd_ops *ops,
    bw_owned_launchd_job *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_JOB_STATE_MAGIC) {
    return BW_JOB_ERROR;
  }
  if (!owned->bootstrap_attempted) return BW_JOB_NO_EFFECT;
  if (!owned->bootstrapped || !owned->verified) {
    if (!job_absent(ops, &owned->identity)) return BW_JOB_AMBIGUOUS;
    clear_owned_job(owned);
    return BW_JOB_OK;
  }
  if (bw_verify_owned_launchd_job(ops, owned) != BW_JOB_OK) {
    owned->verified = false;
    return BW_JOB_AMBIGUOUS;
  }
  bool cleanup_failed = false;
  if (owned->activation_attempted) {
    bw_job_result stopped = ops->stop_process(ops->context, &owned->identity);
    if (stopped != BW_JOB_OK && stopped != BW_JOB_NO_EFFECT) cleanup_failed = true;
  }
  if (bw_verify_owned_launchd_job(ops, owned) != BW_JOB_OK) {
    owned->verified = false;
    return BW_JOB_AMBIGUOUS;
  }
  if (ops->bootout(ops->context, &owned->identity) != BW_JOB_OK) return BW_JOB_AMBIGUOUS;
  if (ops->probe_label(ops->context, owned->identity.label) != BW_LAUNCHD_ABSENT ||
      ops->probe_mach_service(ops->context, owned->identity.mach_service) != BW_LAUNCHD_ABSENT) {
    return BW_JOB_AMBIGUOUS;
  }
  clear_owned_job(owned);
  return cleanup_failed ? BW_JOB_AMBIGUOUS : BW_JOB_OK;
}
