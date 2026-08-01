#include "macos-account-ownership.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

#define BW_ACCOUNT_STATE_MAGIC UINT32_C(0x42574143)

static bool fixed_text(const char *value, size_t maximum) {
  if (value == NULL) return false;
  size_t length = strnlen(value, maximum);
  if (length == 0 || length >= maximum) return false;
  for (size_t index = 0; index < length; index += 1) {
    unsigned char byte = (unsigned char)value[index];
    if (byte < 0x21 || byte > 0x7e) return false;
  }
  return true;
}

static bool canonical_uuid(const char *value) {
  if (!fixed_text(value, 37) || strlen(value) != 36) return false;
  for (size_t index = 0; index < 36; index += 1) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (value[index] != '-') return false;
    } else if (!isxdigit((unsigned char)value[index]) || islower((unsigned char)value[index])) {
      return false;
    }
  }
  return value[14] == '4' &&
      (value[19] == '8' || value[19] == '9' || value[19] == 'A' || value[19] == 'B');
}

static bool valid_record(const bw_account_record *record) {
  return record != NULL && fixed_text(record->name, sizeof(record->name)) &&
      strcmp(record->name, "_bwagentbridge") == 0 &&
      record->unique_id > 0 && record->unique_id < 500 &&
      canonical_uuid(record->generated_uid) &&
      (strcmp(record->shell, "/usr/bin/false") == 0 ||
       strcmp(record->shell, "/usr/bin/nologin") == 0) &&
      strcmp(record->home, "/var/empty") == 0;
}

static bool same_record(const bw_account_record *left, const bw_account_record *right) {
  return left->unique_id == right->unique_id && strcmp(left->name, right->name) == 0 &&
      strcmp(left->generated_uid, right->generated_uid) == 0 &&
      strcmp(left->shell, right->shell) == 0 && strcmp(left->home, right->home) == 0;
}

static bool valid_ops(const bw_directory_ops *ops) {
  return ops != NULL && ops->probe_name != NULL && ops->probe_unique_id != NULL &&
      ops->probe_generated_uid != NULL && ops->create_record != NULL &&
      ops->read_record != NULL && ops->delete_record != NULL;
}

void bw_init_owned_account(bw_owned_account *owned) {
  if (owned == NULL) return;
  memset(owned, 0, sizeof(*owned));
  owned->state_magic = BW_ACCOUNT_STATE_MAGIC;
}

bw_account_result bw_prepare_owned_account(
    const bw_directory_ops *ops,
    const bw_account_record *candidate,
    bw_owned_account *owned) {
  if (!valid_ops(ops) || !valid_record(candidate) || owned == NULL ||
      owned->state_magic != BW_ACCOUNT_STATE_MAGIC || owned->prepared || owned->created ||
      owned->verified) return BW_ACCOUNT_ERROR;
  bw_directory_probe name = ops->probe_name(ops->context, candidate->name);
  bw_directory_probe unique_id = ops->probe_unique_id(ops->context, candidate->unique_id);
  bw_directory_probe generated_uid = ops->probe_generated_uid(ops->context, candidate->generated_uid);
  if (name == BW_DIRECTORY_PROBE_ERROR || unique_id == BW_DIRECTORY_PROBE_ERROR ||
      generated_uid == BW_DIRECTORY_PROBE_ERROR) return BW_ACCOUNT_ERROR;
  if (name != BW_DIRECTORY_ABSENT || unique_id != BW_DIRECTORY_ABSENT ||
      generated_uid != BW_DIRECTORY_ABSENT) return BW_ACCOUNT_NO_EFFECT;
  owned->identity = *candidate;
  owned->prepared = true;
  return BW_ACCOUNT_OK;
}

bw_account_result bw_create_owned_account(
    const bw_directory_ops *ops,
    bw_owned_account *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_ACCOUNT_STATE_MAGIC ||
      !owned->prepared || owned->created ||
      !valid_record(&owned->identity)) return BW_ACCOUNT_ERROR;
  bw_account_result created = ops->create_record(ops->context, &owned->identity);
  if (created != BW_ACCOUNT_OK) return created;
  owned->created = true;
  bw_account_record observed;
  memset(&observed, 0, sizeof(observed));
  if (!ops->read_record(ops->context, owned->identity.name, &observed) ||
      !valid_record(&observed) || !same_record(&owned->identity, &observed) ||
      ops->probe_name(ops->context, owned->identity.name) != BW_DIRECTORY_PRESENT ||
      ops->probe_unique_id(ops->context, owned->identity.unique_id) != BW_DIRECTORY_PRESENT ||
      ops->probe_generated_uid(ops->context, owned->identity.generated_uid) != BW_DIRECTORY_PRESENT) {
    return BW_ACCOUNT_AMBIGUOUS;
  }
  owned->verified = true;
  return BW_ACCOUNT_OK;
}

bw_account_result bw_verify_owned_account(
    const bw_directory_ops *ops,
    const bw_owned_account *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_ACCOUNT_STATE_MAGIC ||
      !owned->prepared || !owned->created ||
      !owned->verified || !valid_record(&owned->identity)) return BW_ACCOUNT_ERROR;
  bw_account_record observed;
  memset(&observed, 0, sizeof(observed));
  if (!ops->read_record(ops->context, owned->identity.name, &observed) ||
      !valid_record(&observed) || !same_record(&owned->identity, &observed)) {
    return BW_ACCOUNT_AMBIGUOUS;
  }
  return BW_ACCOUNT_OK;
}

bw_account_result bw_delete_owned_account(
    const bw_directory_ops *ops,
    bw_owned_account *owned) {
  if (!valid_ops(ops) || owned == NULL || owned->state_magic != BW_ACCOUNT_STATE_MAGIC) {
    return BW_ACCOUNT_ERROR;
  }
  if (!owned->prepared || !owned->created || !owned->verified) return BW_ACCOUNT_NO_EFFECT;
  if (bw_verify_owned_account(ops, owned) != BW_ACCOUNT_OK) return BW_ACCOUNT_AMBIGUOUS;
  if (ops->delete_record(ops->context, &owned->identity) != BW_ACCOUNT_OK) {
    return BW_ACCOUNT_AMBIGUOUS;
  }
  bw_directory_probe name = ops->probe_name(ops->context, owned->identity.name);
  bw_directory_probe unique_id = ops->probe_unique_id(ops->context, owned->identity.unique_id);
  bw_directory_probe generated_uid =
      ops->probe_generated_uid(ops->context, owned->identity.generated_uid);
  if (name != BW_DIRECTORY_ABSENT || unique_id != BW_DIRECTORY_ABSENT ||
      generated_uid != BW_DIRECTORY_ABSENT) return BW_ACCOUNT_AMBIGUOUS;
  owned->created = false;
  owned->verified = false;
  owned->prepared = false;
  memset(&owned->identity, 0, sizeof(owned->identity));
  return BW_ACCOUNT_OK;
}
