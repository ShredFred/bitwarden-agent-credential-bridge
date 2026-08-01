#ifndef BW_AGENT_MACOS_ACCOUNT_OWNERSHIP_H
#define BW_AGENT_MACOS_ACCOUNT_OWNERSHIP_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
  BW_DIRECTORY_ABSENT = 0,
  BW_DIRECTORY_PRESENT = 1,
  BW_DIRECTORY_PROBE_ERROR = 2,
} bw_directory_probe;

typedef enum {
  BW_ACCOUNT_OK = 0,
  BW_ACCOUNT_NO_EFFECT = 1,
  BW_ACCOUNT_AMBIGUOUS = 2,
  BW_ACCOUNT_ERROR = 3,
} bw_account_result;

typedef struct {
  char name[64];
  uid_t unique_id;
  char generated_uid[37];
  char shell[64];
  char home[64];
} bw_account_record;

typedef struct {
  void *context;
  bw_directory_probe (*probe_name)(void *context, const char *name);
  bw_directory_probe (*probe_unique_id)(void *context, uid_t unique_id);
  bw_directory_probe (*probe_generated_uid)(void *context, const char *generated_uid);
  bw_account_result (*create_record)(void *context, const bw_account_record *record);
  bool (*read_record)(void *context, const char *name, bw_account_record *record);
  bw_account_result (*delete_record)(void *context, const bw_account_record *record);
} bw_directory_ops;

typedef struct {
  uint32_t state_magic;
  bw_account_record identity;
  bool prepared;
  bool created;
  bool verified;
} bw_owned_account;

void bw_init_owned_account(bw_owned_account *owned);

bw_account_result bw_prepare_owned_account(
    const bw_directory_ops *ops,
    const bw_account_record *candidate,
    bw_owned_account *owned);

bw_account_result bw_create_owned_account(
    const bw_directory_ops *ops,
    bw_owned_account *owned);

bw_account_result bw_verify_owned_account(
    const bw_directory_ops *ops,
    const bw_owned_account *owned);

bw_account_result bw_delete_owned_account(
    const bw_directory_ops *ops,
    bw_owned_account *owned);

#endif
