#include "macos-elevation-identity.h"

#include <libproc.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/proc_info.h>
#include <unistd.h>

#define SUDO_PATH "/usr/bin/sudo"
#define PROVISIONER_PATH "/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-provisioner"

static bool valid_chain(bool direct_sudo, bool parent_provisioner, bool grandparent_sudo) {
  return direct_sudo || (parent_provisioner && grandparent_sudo);
}

static bool stable_root_process(pid_t pid, const char *expected_path, pid_t *parent_pid) {
  if (pid <= 1 || expected_path == NULL || parent_pid == NULL) return false;
  struct proc_bsdinfo before;
  struct proc_bsdinfo after;
  struct stat path_before;
  struct stat path_after;
  char path[PROC_PIDPATHINFO_MAXSIZE];
  memset(&before, 0, sizeof(before));
  memset(&after, 0, sizeof(after));
  memset(path, 0, sizeof(path));
  if (lstat(expected_path, &path_before) != 0 || S_ISLNK(path_before.st_mode) ||
      !S_ISREG(path_before.st_mode) || path_before.st_uid != 0 ||
      (path_before.st_mode & (S_IWGRP | S_IWOTH)) != 0) return false;
  int first = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, sizeof(before));
  int path_length = proc_pidpath(pid, path, sizeof(path));
  int second = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after));
  if (lstat(expected_path, &path_after) != 0 ||
      path_before.st_dev != path_after.st_dev || path_before.st_ino != path_after.st_ino ||
      path_before.st_mode != path_after.st_mode || path_before.st_uid != path_after.st_uid ||
      path_before.st_gid != path_after.st_gid) return false;
  size_t expected_length = strlen(expected_path);
  if (first != (int)sizeof(before) || second != (int)sizeof(after) ||
      path_length != (int)expected_length || memcmp(path, expected_path, expected_length) != 0 ||
      before.pbi_uid != 0 || before.pbi_pid != after.pbi_pid ||
      before.pbi_ppid != after.pbi_ppid ||
      before.pbi_start_tvsec != after.pbi_start_tvsec ||
      before.pbi_start_tvusec != after.pbi_start_tvusec) return false;
  *parent_pid = before.pbi_ppid;
  return true;
}

bool bw_stable_direct_sudo_parent(void) {
  pid_t ignored = 0;
  return stable_root_process(getppid(), SUDO_PATH, &ignored);
}

bool bw_stable_sudo_or_provisioner_parent(void) {
  pid_t parent = getppid();
  pid_t grandparent = 0;
  bool direct_sudo = stable_root_process(parent, SUDO_PATH, &grandparent);
  if (direct_sudo) return valid_chain(true, false, false);
  bool parent_provisioner = stable_root_process(parent, PROVISIONER_PATH, &grandparent);
  if (!parent_provisioner) return false;
  pid_t ignored = 0;
  bool grandparent_sudo = stable_root_process(grandparent, SUDO_PATH, &ignored);
  return valid_chain(false, true, grandparent_sudo);
}

#if defined(BW_ELEVATION_IDENTITY_TESTING)
bool bw_elevation_chain_fixture(
    bool direct_sudo, bool parent_provisioner, bool grandparent_sudo) {
  return valid_chain(direct_sudo, parent_provisioner, grandparent_sudo);
}
#endif
