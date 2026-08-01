#include "macos-retained-file-ops.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool valid_name(const char *name) {
  if (name == NULL || name[0] == '\0' || name[0] == '.' || strchr(name, '/') != NULL) return false;
  size_t length = strnlen(name, 256);
  return length > 0 && length < 256;
}

static bool same_identity(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
      left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
      left->st_gid == right->st_gid && left->st_size == right->st_size;
}

static bool write_all(int fd, const unsigned char *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = write(fd, bytes + offset, length - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += (size_t)count;
  }
  return true;
}

static bool read_matches(int fd, const unsigned char *expected, size_t length) {
  unsigned char buffer[4096];
  size_t offset = 0;
  while (offset < length) {
    size_t wanted = length - offset;
    if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
    ssize_t count = pread(fd, buffer, wanted, (off_t)offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0 || (size_t)count > wanted ||
        memcmp(buffer, expected + offset, (size_t)count) != 0) return false;
    offset += (size_t)count;
  }
  return true;
}

static void reset_owned(bw_owned_file *owned) {
  owned->parent_fd = -1;
  owned->file_fd = -1;
  owned->parent_device = 0;
  owned->parent_inode = 0;
  owned->device = 0;
  owned->inode = 0;
  owned->name[0] = '\0';
  owned->created = false;
}

bw_file_result bw_publish_owned_file(
    int parent_fd,
    const char *fixed_name,
    const unsigned char *bytes,
    size_t length,
    mode_t mode,
    uid_t owner,
    gid_t group,
    bw_owned_file *owned) {
  if (parent_fd < 0 || !valid_name(fixed_name) || bytes == NULL || length == 0 ||
      length > 64U * 1024U * 1024U || owned == NULL || (mode & ~0777U) != 0) return BW_FILE_ERROR;
  reset_owned(owned);
  struct stat parent;
  if (fstat(parent_fd, &parent) != 0 || !S_ISDIR(parent.st_mode)) return BW_FILE_ERROR;
  int fd = openat(parent_fd, fixed_name, O_CREAT | O_EXCL | O_NOFOLLOW | O_RDWR | O_CLOEXEC, 0000);
  if (fd < 0) return errno == EEXIST ? BW_FILE_NO_EFFECT : BW_FILE_ERROR;
  owned->parent_fd = parent_fd;
  owned->file_fd = fd;
  owned->parent_device = parent.st_dev;
  owned->parent_inode = parent.st_ino;
  size_t name_length = strlen(fixed_name);
  memcpy(owned->name, fixed_name, name_length + 1);
  owned->created = true;

  struct stat initial;
  if (fstat(fd, &initial) != 0 || !S_ISREG(initial.st_mode) || initial.st_nlink != 1) {
    return BW_FILE_AMBIGUOUS;
  }
  owned->device = initial.st_dev;
  owned->inode = initial.st_ino;
  if (!write_all(fd, bytes, length) || fchown(fd, owner, group) != 0 ||
      fchmod(fd, mode) != 0 || fsync(fd) != 0 || fsync(parent_fd) != 0) {
    return BW_FILE_AMBIGUOUS;
  }
  return bw_verify_owned_file(owned, bytes, length, mode, owner, group);
}

bw_file_result bw_verify_owned_file(
    const bw_owned_file *owned,
    const unsigned char *expected,
    size_t expected_length,
    mode_t expected_mode,
    uid_t expected_owner,
    gid_t expected_group) {
  if (owned == NULL || !owned->created || owned->file_fd < 0 || owned->parent_fd < 0 ||
      !valid_name(owned->name) || expected == NULL || expected_length == 0) return BW_FILE_ERROR;
  struct stat retained;
  struct stat path;
  struct stat parent;
  if (fstat(owned->parent_fd, &parent) != 0 || !S_ISDIR(parent.st_mode) ||
      parent.st_dev != owned->parent_device || parent.st_ino != owned->parent_inode ||
      fstat(owned->file_fd, &retained) != 0 ||
      fstatat(owned->parent_fd, owned->name, &path, AT_SYMLINK_NOFOLLOW) != 0) {
    return BW_FILE_AMBIGUOUS;
  }
  if (!S_ISREG(retained.st_mode) || retained.st_nlink != 1 ||
      retained.st_dev != owned->device || retained.st_ino != owned->inode ||
      !same_identity(&retained, &path) || retained.st_size != (off_t)expected_length ||
      (retained.st_mode & 0777U) != expected_mode || retained.st_uid != expected_owner ||
      retained.st_gid != expected_group || !read_matches(owned->file_fd, expected, expected_length)) {
    return BW_FILE_AMBIGUOUS;
  }
  return BW_FILE_OK;
}

bw_file_result bw_unlink_owned_file(bw_owned_file *owned) {
  if (owned == NULL || !owned->created || owned->parent_fd < 0 || owned->file_fd < 0 ||
      !valid_name(owned->name)) return BW_FILE_NO_EFFECT;
  struct stat retained;
  struct stat path;
  struct stat parent;
  if (fstat(owned->parent_fd, &parent) != 0 || !S_ISDIR(parent.st_mode) ||
      parent.st_dev != owned->parent_device || parent.st_ino != owned->parent_inode ||
      fstat(owned->file_fd, &retained) != 0 ||
      fstatat(owned->parent_fd, owned->name, &path, AT_SYMLINK_NOFOLLOW) != 0 ||
      retained.st_dev != owned->device || retained.st_ino != owned->inode || retained.st_nlink != 1 ||
      !same_identity(&retained, &path)) return BW_FILE_AMBIGUOUS;
  if (unlinkat(owned->parent_fd, owned->name, 0) != 0 || fsync(owned->parent_fd) != 0) {
    return BW_FILE_AMBIGUOUS;
  }
  struct stat absent;
  if (fstatat(owned->parent_fd, owned->name, &absent, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
    return BW_FILE_AMBIGUOUS;
  }
  owned->created = false;
  return BW_FILE_OK;
}

void bw_close_owned_file(bw_owned_file *owned) {
  if (owned == NULL) return;
  if (owned->file_fd >= 0) (void)close(owned->file_fd);
  reset_owned(owned);
}
