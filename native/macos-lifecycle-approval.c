#include "macos-lifecycle-approval.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <os/lock.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
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
#define CHALLENGE_WAIT_TIMEOUT_MS 120000
#define NONCE_CACHE_CAPACITY 64
#define CHALLENGE_MAGIC UINT64_C(0x42574348414c3031)
#define CHALLENGE_VERSION 1U

typedef struct {
  uint64_t magic;
  uint32_t version;
  uint32_t byte_length;
  int32_t runner_pid;
  uint32_t reserved;
  unsigned char nonce[BW_APPROVAL_NONCE_BYTES];
} approval_challenge;

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
_Static_assert(sizeof(approval_challenge) == 56, "approval challenge ABI changed");
_Static_assert(offsetof(approval_challenge, nonce) == 24, "approval challenge layout changed");

#if defined(BW_LIFECYCLE_APPROVAL_TESTING)
static unsigned char FIXED_TEST_NONCE;
#endif
static os_unfair_lock NONCE_LOCK = OS_UNFAIR_LOCK_INIT;
static unsigned char RECENT_NONCES[NONCE_CACHE_CAPACITY][BW_APPROVAL_NONCE_BYTES];
static size_t RECENT_NONCE_COUNT;
static size_t RECENT_NONCE_NEXT;

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

static bool read_exact(int fd, void *buffer, size_t length, uint64_t deadline) {
  unsigned char *bytes = buffer;
  size_t offset = 0;
  while (offset < length) {
    if (!wait_readable(fd, deadline)) return false;
    ssize_t count = read(fd, bytes + offset, length - offset);
    if (count > 0) { offset += (size_t)count; continue; }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

static bool write_exact(int fd, const void *buffer, size_t length, uint64_t deadline) {
  const unsigned char *bytes = buffer;
  size_t offset = 0;
  while (offset < length) {
    uint64_t now;
    if (!monotonic_now(&now) || now >= deadline) return false;
    uint64_t remaining_ms = (deadline - now + UINT64_C(999999)) / UINT64_C(1000000);
    int timeout = remaining_ms > INT32_MAX ? INT32_MAX : (int)remaining_ms;
    struct pollfd descriptor = {.fd = fd, .events = POLLOUT};
    int result = poll(&descriptor, 1, timeout);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0 || (descriptor.revents & POLLOUT) == 0) return false;
    ssize_t count = send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);
    if (count > 0) { offset += (size_t)count; continue; }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

static bool exact_read_then_eof(int fd, void *buffer, size_t length, uint64_t deadline) {
  if (!read_exact(fd, buffer, length, deadline)) return false;
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

static bool remember_nonce_once(const unsigned char nonce[BW_APPROVAL_NONCE_BYTES]) {
  bool accepted = true;
  os_unfair_lock_lock(&NONCE_LOCK);
  for (size_t index = 0; index < RECENT_NONCE_COUNT; index += 1) {
    if (equal_bytes(RECENT_NONCES[index], nonce, BW_APPROVAL_NONCE_BYTES)) {
      accepted = false;
      break;
    }
  }
  if (accepted) {
    memcpy(RECENT_NONCES[RECENT_NONCE_NEXT], nonce, BW_APPROVAL_NONCE_BYTES);
    RECENT_NONCE_NEXT = (RECENT_NONCE_NEXT + 1) % NONCE_CACHE_CAPACITY;
    if (RECENT_NONCE_COUNT < NONCE_CACHE_CAPACITY) RECENT_NONCE_COUNT += 1;
  }
  os_unfair_lock_unlock(&NONCE_LOCK);
  return accepted;
}

static bool fill_nonce(unsigned char nonce[BW_APPROVAL_NONCE_BYTES]) {
#if defined(BW_LIFECYCLE_APPROVAL_TESTING)
  if (FIXED_TEST_NONCE != 0) {
    memset(nonce, FIXED_TEST_NONCE, BW_APPROVAL_NONCE_BYTES);
    return true;
  }
#endif
  arc4random_buf(nonce, BW_APPROVAL_NONCE_BYTES);
  return nonce_nonzero(nonce);
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
  uint64_t started;
  if (!monotonic_now(&started)) return false;
  uint64_t io_deadline =
      started + (uint64_t)RECEIPT_IO_TIMEOUT_MS * UINT64_C(1000000);
  approval_challenge challenge = {
    .magic = CHALLENGE_MAGIC, .version = CHALLENGE_VERSION,
    .byte_length = sizeof(approval_challenge), .runner_pid = getpid(), .reserved = 0,
  };
  if (!fill_nonce(challenge.nonce) ||
      !write_exact(connected_socket_fd, &challenge, sizeof(challenge), io_deadline)) return false;
  approval_receipt receipt;
  memset(&receipt, 0, sizeof(receipt));
  if (!exact_read_then_eof(connected_socket_fd, &receipt, sizeof(receipt), io_deadline)) return false;
  uint64_t now;
  const uint64_t maximum =
      (uint64_t)BW_APPROVAL_MAX_LIFETIME_SECONDS * UINT64_C(1000000000);
  if (!monotonic_now(&now) || receipt.magic != RECEIPT_MAGIC ||
      receipt.version != RECEIPT_VERSION || receipt.byte_length != sizeof(receipt) ||
      receipt.approver_uid != (uint32_t)real_uid || receipt.runner_pid != getpid() ||
      receipt.expires_monotonic_ns <= now || receipt.expires_monotonic_ns - now > maximum ||
      !equal_bytes(receipt.nonce, challenge.nonce, BW_APPROVAL_NONCE_BYTES) ||
      !nonce_nonzero(receipt.nonce) || !equal_bindings(&receipt.bindings, expected) ||
      !remember_nonce_once(receipt.nonce)
#if !defined(BW_LIFECYCLE_APPROVAL_TESTING)
      || !stable_sudo_parent()
#endif
      ) return false;
  memset(&challenge, 0, sizeof(challenge));
  memset(&receipt, 0, sizeof(receipt));
  return true;
}

bool bw_answer_lifecycle_approval_challenge(
    int connected_socket_fd,
    const bw_lifecycle_approval_bindings *bindings,
    pid_t *approved_runner_pid) {
  uint64_t now;
  if (approved_runner_pid != NULL) *approved_runner_pid = 0;
  if (connected_socket_fd < 0 || bindings == NULL || getuid() == 0 || geteuid() != getuid() ||
      !monotonic_now(&now)) {
#if !defined(BW_LIFECYCLE_APPROVAL_TESTING)
    return false;
#else
    if (connected_socket_fd < 0 || bindings == NULL || !monotonic_now(&now)) return false;
#endif
  }
  if (!connected_unix_socket(connected_socket_fd, getuid())) return false;
  uint64_t challenge_deadline =
      now + (uint64_t)CHALLENGE_WAIT_TIMEOUT_MS * UINT64_C(1000000);
  approval_challenge challenge;
  memset(&challenge, 0, sizeof(challenge));
  if (!read_exact(connected_socket_fd, &challenge, sizeof(challenge), challenge_deadline) ||
      challenge.magic != CHALLENGE_MAGIC || challenge.version != CHALLENGE_VERSION ||
      challenge.byte_length != sizeof(challenge) || challenge.runner_pid <= 1 ||
      challenge.reserved != 0 || !nonce_nonzero(challenge.nonce)) return false;
  if (!monotonic_now(&now)) return false;
  uint64_t io_deadline = now + (uint64_t)RECEIPT_IO_TIMEOUT_MS * UINT64_C(1000000);
  approval_receipt receipt = {
    .magic = RECEIPT_MAGIC, .version = RECEIPT_VERSION,
    .byte_length = sizeof(approval_receipt),
    .expires_monotonic_ns = now + UINT64_C(30000000000),
    .approver_uid = (uint32_t)getuid(), .runner_pid = challenge.runner_pid, .bindings = *bindings,
  };
  memcpy(receipt.nonce, challenge.nonce, sizeof(receipt.nonce));
  bool written = write_exact(connected_socket_fd, &receipt, sizeof(receipt), io_deadline) &&
      shutdown(connected_socket_fd, SHUT_WR) == 0;
  pid_t runner_pid = receipt.runner_pid;
  memset(&challenge, 0, sizeof(challenge));
  memset(&receipt, 0, sizeof(receipt));
  if (written && approved_runner_pid != NULL) *approved_runner_pid = runner_pid;
  return written;
}

#if defined(BW_LIFECYCLE_APPROVAL_TESTING)
void bw_set_lifecycle_approval_nonce_for_test(unsigned char nonce_value) {
  FIXED_TEST_NONCE = nonce_value;
}
#endif
