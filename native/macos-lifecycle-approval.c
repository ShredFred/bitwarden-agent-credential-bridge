#include "macos-lifecycle-approval.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <os/lock.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define RECEIPT_MAGIC UINT64_C(0x4257415050523031)
#define RECEIPT_VERSION 1U
#define SUDO_PATH "/usr/bin/sudo"
#define RECEIPT_IO_TIMEOUT_MS 5000
#define NONCE_CACHE_CAPACITY 64

typedef struct {
  uint64_t magic;
  uint32_t version;
  uint32_t byte_length;
  uint64_t expires_monotonic_ns;
  uint32_t approver_uid;
  int32_t runner_pid;
  unsigned char nonce[BW_APPROVAL_NONCE_BYTES];
  bw_lifecycle_approval_bindings bindings;
} approval_receipt;

_Static_assert(sizeof(approval_receipt) == 160, "approval receipt ABI changed");
_Static_assert(offsetof(approval_receipt, bindings) == 64, "approval receipt layout changed");

static os_unfair_lock NONCE_LOCK = OS_UNFAIR_LOCK_INIT;
static unsigned char CONSUMED_NONCES[NONCE_CACHE_CAPACITY][BW_APPROVAL_NONCE_BYTES];
static size_t CONSUMED_NONCE_COUNT;

static bool monotonic_now(uint64_t *value) {
  struct timespec now;
  if (value == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return false;
  *value = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
  return true;
}

static bool equal_bytes(const void *left, const void *right, size_t length) {
  const unsigned char *a = left;
  const unsigned char *b = right;
  unsigned char different = 0;
  for (size_t index = 0; index < length; index += 1) different |= a[index] ^ b[index];
  return different == 0;
}

static bool equal_bindings(
    const bw_lifecycle_approval_bindings *left,
    const bw_lifecycle_approval_bindings *right) {
  return left != NULL && right != NULL &&
      equal_bytes(left, right, sizeof(*left));
}

static bool connected_unix_socket(int fd, uid_t expected_peer) {
  struct stat value;
  int type = 0;
  socklen_t type_length = sizeof(type);
  struct sockaddr_storage local;
  struct sockaddr_storage peer;
  socklen_t local_length = sizeof(local);
  socklen_t peer_length = sizeof(peer);
  uid_t peer_uid = (uid_t)-1;
  gid_t peer_gid = (gid_t)-1;
  return fd >= 0 && fstat(fd, &value) == 0 && S_ISSOCK(value.st_mode) &&
      getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 &&
      getsockname(fd, (struct sockaddr *)&local, &local_length) == 0 &&
      getpeername(fd, (struct sockaddr *)&peer, &peer_length) == 0 &&
      type == SOCK_STREAM && local.ss_family == AF_UNIX && peer.ss_family == AF_UNIX &&
      getpeereid(fd, &peer_uid, &peer_gid) == 0 &&
      peer_uid == expected_peer;
}

#if !defined(BW_LIFECYCLE_APPROVAL_TESTING)
static bool stable_sudo_parent(void) {
  pid_t parent = getppid();
  struct proc_bsdinfo before;
  struct proc_bsdinfo after;
  char path[PROC_PIDPATHINFO_MAXSIZE];
  memset(&before, 0, sizeof(before));
  memset(&after, 0, sizeof(after));
  memset(path, 0, sizeof(path));
  int first = proc_pidinfo(parent, PROC_PIDTBSDINFO, 0, &before, sizeof(before));
  int path_length = proc_pidpath(parent, path, sizeof(path));
  int second = proc_pidinfo(parent, PROC_PIDTBSDINFO, 0, &after, sizeof(after));
  return parent > 1 && first == (int)sizeof(before) && second == (int)sizeof(after) &&
      path_length == (int)strlen(SUDO_PATH) && memcmp(path, SUDO_PATH, strlen(SUDO_PATH)) == 0 &&
      before.pbi_uid == 0 && before.pbi_start_tvsec == after.pbi_start_tvsec &&
      before.pbi_start_tvusec == after.pbi_start_tvusec && before.pbi_pid == after.pbi_pid;
}
#endif

static bool wait_readable(int fd, uint64_t deadline_ns) {
  for (;;) {
    uint64_t now;
    if (!monotonic_now(&now) || now >= deadline_ns) return false;
    uint64_t remaining_ms = (deadline_ns - now + UINT64_C(999999)) / UINT64_C(1000000);
    int timeout = remaining_ms > INT32_MAX ? INT32_MAX : (int)remaining_ms;
    struct pollfd descriptor = {.fd = fd, .events = POLLIN};
    int result = poll(&descriptor, 1, timeout);
    if (result > 0) return (descriptor.revents & (POLLIN | POLLHUP)) != 0;
    if (result < 0 && errno == EINTR) continue;
    return false;
  }
}

static bool exact_read_then_eof(int fd, void *buffer, size_t length) {
  uint64_t now;
  if (!monotonic_now(&now)) return false;
  uint64_t deadline = now + (uint64_t)RECEIPT_IO_TIMEOUT_MS * UINT64_C(1000000);
  unsigned char *bytes = buffer;
  size_t offset = 0;
  while (offset < length) {
    if (!wait_readable(fd, deadline)) return false;
    ssize_t count = read(fd, bytes + offset, length - offset);
    if (count > 0) { offset += (size_t)count; continue; }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  unsigned char extra;
  for (;;) {
    if (!wait_readable(fd, deadline)) return false;
    ssize_t count = read(fd, &extra, 1);
    if (count == 0) return true;
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
}

static bool nonce_nonzero(const unsigned char nonce[BW_APPROVAL_NONCE_BYTES]) {
  unsigned char any = 0;
  for (size_t index = 0; index < BW_APPROVAL_NONCE_BYTES; index += 1) any |= nonce[index];
  return any != 0;
}

static bool consume_nonce_once(const unsigned char nonce[BW_APPROVAL_NONCE_BYTES]) {
  bool accepted = false;
  os_unfair_lock_lock(&NONCE_LOCK);
  for (size_t index = 0; index < CONSUMED_NONCE_COUNT; index += 1) {
    if (equal_bytes(CONSUMED_NONCES[index], nonce, BW_APPROVAL_NONCE_BYTES)) goto done;
  }
  if (CONSUMED_NONCE_COUNT >= NONCE_CACHE_CAPACITY) goto done;
  memcpy(CONSUMED_NONCES[CONSUMED_NONCE_COUNT], nonce, BW_APPROVAL_NONCE_BYTES);
  CONSUMED_NONCE_COUNT += 1;
  accepted = true;
done:
  os_unfair_lock_unlock(&NONCE_LOCK);
  return accepted;
}

bool bw_receive_and_consume_lifecycle_approval(
    int connected_socket_fd,
    const bw_lifecycle_approval_bindings *expected) {
  if (expected == NULL) return false;
#if !defined(BW_LIFECYCLE_APPROVAL_TESTING)
  if (getuid() == 0 || geteuid() != 0 || !stable_sudo_parent()) return false;
#endif
  uid_t real_uid = getuid();
  if (!connected_unix_socket(connected_socket_fd, real_uid)) return false;
  approval_receipt receipt;
  memset(&receipt, 0, sizeof(receipt));
  if (!exact_read_then_eof(connected_socket_fd, &receipt, sizeof(receipt))) return false;
  uint64_t now;
  const uint64_t maximum =
      (uint64_t)BW_APPROVAL_MAX_LIFETIME_SECONDS * UINT64_C(1000000000);
  if (!monotonic_now(&now) || receipt.magic != RECEIPT_MAGIC ||
      receipt.version != RECEIPT_VERSION || receipt.byte_length != sizeof(receipt) ||
      receipt.approver_uid != (uint32_t)real_uid || receipt.runner_pid != getpid() ||
      receipt.expires_monotonic_ns <= now || receipt.expires_monotonic_ns - now > maximum ||
      !nonce_nonzero(receipt.nonce) || !equal_bindings(&receipt.bindings, expected) ||
      !consume_nonce_once(receipt.nonce)) return false;
  memset(&receipt, 0, sizeof(receipt));
  return true;
}

#if defined(BW_LIFECYCLE_APPROVAL_TESTING)
bool bw_write_lifecycle_approval_for_test(
    int connected_socket_fd,
    const bw_lifecycle_approval_bindings *bindings,
    unsigned char nonce_value) {
  uint64_t now;
  if (connected_socket_fd < 0 || bindings == NULL || nonce_value == 0 ||
      !monotonic_now(&now)) return false;
  approval_receipt receipt = {
    .magic = RECEIPT_MAGIC, .version = RECEIPT_VERSION,
    .byte_length = sizeof(approval_receipt),
    .expires_monotonic_ns = now + UINT64_C(30000000000),
    .approver_uid = (uint32_t)getuid(), .runner_pid = getpid(), .bindings = *bindings,
  };
  memset(receipt.nonce, nonce_value, sizeof(receipt.nonce));
  const unsigned char *bytes = (const unsigned char *)&receipt;
  size_t offset = 0;
  while (offset < sizeof(receipt)) {
    ssize_t count = write(connected_socket_fd, bytes + offset, sizeof(receipt) - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += (size_t)count;
  }
  return shutdown(connected_socket_fd, SHUT_WR) == 0;
}
#endif
