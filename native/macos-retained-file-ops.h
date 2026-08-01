#ifndef BW_AGENT_MACOS_RETAINED_FILE_OPS_H
#define BW_AGENT_MACOS_RETAINED_FILE_OPS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct {
  int parent_fd;
  int file_fd;
  dev_t parent_device;
  ino_t parent_inode;
  dev_t device;
  ino_t inode;
  char name[256];
  bool created;
} bw_owned_file;

typedef enum {
  BW_FILE_OK = 0,
  BW_FILE_NO_EFFECT = 1,
  BW_FILE_AMBIGUOUS = 2,
  BW_FILE_ERROR = 3,
} bw_file_result;

bw_file_result bw_publish_owned_file(
    int parent_fd,
    const char *fixed_name,
    const unsigned char *bytes,
    size_t length,
    mode_t mode,
    uid_t owner,
    gid_t group,
    bw_owned_file *owned);

bw_file_result bw_verify_owned_file(
    const bw_owned_file *owned,
    const unsigned char *expected,
    size_t expected_length,
    mode_t expected_mode,
    uid_t expected_owner,
    gid_t expected_group);

bw_file_result bw_unlink_owned_file(bw_owned_file *owned);
void bw_close_owned_file(bw_owned_file *owned);

#endif
