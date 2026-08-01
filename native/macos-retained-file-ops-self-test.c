#include "macos-retained-file-ops.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const FILE_NAME = "owned-fixture";
static const unsigned char CONTENT[] = "reviewed-bytes";
static const unsigned char FOREIGN[] = "foreign-bytes";

static bool write_foreign(int parent_fd) {
  int fd = openat(parent_fd, FILE_NAME, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  bool ok = write(fd, FOREIGN, sizeof(FOREIGN)) == (ssize_t)sizeof(FOREIGN) && fsync(fd) == 0;
  if (close(fd) != 0) ok = false;
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 2;
  char root[] = "/tmp/bw-retained-file-ops.XXXXXX";
  if (mkdtemp(root) == NULL) return 1;
  int parent_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent_fd < 0) return 1;
  bool exclusive_create_verified = false;
  bool collision_preserved = false;
  bool normal_cleanup_verified = false;
  bool replacement_refused = false;
  bool replacement_preserved = false;
  bool name_snapshot_verified = false;

  bw_owned_file first;
  if (bw_publish_owned_file(parent_fd, FILE_NAME, CONTENT, sizeof(CONTENT), 0400,
      getuid(), getgid(), &first) == BW_FILE_OK) {
    exclusive_create_verified = true;
    bw_owned_file collision;
    collision_preserved = bw_publish_owned_file(parent_fd, FILE_NAME, FOREIGN, sizeof(FOREIGN),
        0400, getuid(), getgid(), &collision) == BW_FILE_NO_EFFECT &&
        bw_verify_owned_file(&first, CONTENT, sizeof(CONTENT), 0400, getuid(), getgid()) == BW_FILE_OK;
    normal_cleanup_verified = bw_unlink_owned_file(&first) == BW_FILE_OK;
    bw_close_owned_file(&first);
  }

  bw_owned_file replaced;
  if (bw_publish_owned_file(parent_fd, FILE_NAME, CONTENT, sizeof(CONTENT), 0400,
      getuid(), getgid(), &replaced) == BW_FILE_OK) {
    if (unlinkat(parent_fd, FILE_NAME, 0) == 0 && write_foreign(parent_fd)) {
      replacement_refused = bw_unlink_owned_file(&replaced) == BW_FILE_AMBIGUOUS;
      struct stat foreign_stat;
      replacement_preserved = fstatat(parent_fd, FILE_NAME, &foreign_stat, AT_SYMLINK_NOFOLLOW) == 0;
    }
    bw_close_owned_file(&replaced);
  }

  (void)unlinkat(parent_fd, FILE_NAME, 0);
  char mutable_name[32];
  (void)strlcpy(mutable_name, FILE_NAME, sizeof(mutable_name));
  bw_owned_file snapshotted;
  if (bw_publish_owned_file(parent_fd, mutable_name, CONTENT, sizeof(CONTENT), 0400,
      getuid(), getgid(), &snapshotted) == BW_FILE_OK) {
    mutable_name[0] = 'x';
    name_snapshot_verified = strcmp(snapshotted.name, FILE_NAME) == 0 &&
        bw_unlink_owned_file(&snapshotted) == BW_FILE_OK;
    bw_close_owned_file(&snapshotted);
  }

  (void)unlinkat(parent_fd, FILE_NAME, 0);
  bool cleanup_verified = close(parent_fd) == 0 && rmdir(root) == 0;
  if (!(exclusive_create_verified && collision_preserved && normal_cleanup_verified &&
      replacement_refused && replacement_preserved && name_snapshot_verified && cleanup_verified)) return 1;
  printf("{\"schema_version\":1,\"exclusive_create_verified\":true,"
      "\"collision_preserved\":true,\"normal_cleanup_verified\":true,"
      "\"replacement_refused\":true,\"replacement_preserved\":true,"
      "\"name_snapshot_verified\":true,"
      "\"cleanup_verified\":true}\n");
  return 0;
}
