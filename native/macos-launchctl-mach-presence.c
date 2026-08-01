#include "macos-launchctl-mach-presence.h"
#include "macos-fixed-command-runner.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CONTEXT_MAGIC UINT32_C(0x42575052)
#define LAUNCHCTL "/bin/launchctl"
#define FIXED_NAME "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define SNAPSHOT_LIMIT (8U * 1024U * 1024U)
#define TIMEOUT_MS 10000U

static char *const FIXED_ENV[] = {
  "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", NULL,
};

typedef struct {
  const char *needle;
  size_t needle_length;
  char line[8192];
  size_t line_length;
  bool found;
} name_scanner;

static bool valid_fixed_name(const char *name) {
  return name != NULL && strcmp(name, FIXED_NAME) == 0;
}

static void finish_line(name_scanner *scanner) {
  if (scanner->found) {
    scanner->line_length = 0;
    return;
  }
  size_t left = 0;
  while (left < scanner->line_length &&
      (scanner->line[left] == ' ' || scanner->line[left] == '\t')) left += 1;
  size_t right = scanner->line_length;
  while (right > left &&
      (scanner->line[right - 1] == ' ' || scanner->line[right - 1] == '\t')) right -= 1;
  size_t expected_length = scanner->needle_length + 6;
  if (right - left == expected_length && scanner->line[left] == '"' &&
      memcmp(scanner->line + left + 1, scanner->needle, scanner->needle_length) == 0 &&
      memcmp(scanner->line + left + 1 + scanner->needle_length, "\" = {", 5) == 0) {
    scanner->found = true;
  }
  scanner->line_length = 0;
}

static bool scan_byte(name_scanner *scanner, unsigned char byte) {
  if (scanner == NULL || (byte != '\n' && byte != '\t' && (byte < 0x20 || byte > 0x7e))) {
    return false;
  }
  if (byte == '\n') {
    finish_line(scanner);
    return true;
  }
  if (scanner->line_length >= sizeof(scanner->line)) return false;
  scanner->line[scanner->line_length] = (char)byte;
  scanner->line_length += 1;
  return true;
}

static bool scanner_finish(name_scanner *scanner) {
  return scanner != NULL && scanner->line_length == 0 && scanner->found;
}

static uint64_t monotonic_milliseconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
  return (uint64_t)value.tv_sec * UINT64_C(1000) +
      (uint64_t)value.tv_nsec / UINT64_C(1000000);
}

static void close_fd(int *fd) {
  if (*fd >= 0) {
    (void)close(*fd);
    *fd = -1;
  }
}

static bool set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool consume_stdout(
    int fd, name_scanner *scanner, size_t *total, bool *open_pipe, bool *ended_newline) {
  unsigned char bytes[4096];
  while (true) {
    ssize_t count = read(fd, bytes, sizeof(bytes));
    if (count > 0) {
      if ((size_t)count > SNAPSHOT_LIMIT - *total) return false;
      *total += (size_t)count;
      for (ssize_t index = 0; index < count; index += 1) {
        if (!scan_byte(scanner, bytes[index])) return false;
      }
      *ended_newline = bytes[count - 1] == '\n';
      continue;
    }
    if (count == 0) {
      *open_pipe = false;
      return true;
    }
    if (errno == EINTR) continue;
    return errno == EAGAIN || errno == EWOULDBLOCK;
  }
}

static bool consume_stderr(int fd, size_t *total, bool *open_pipe) {
  unsigned char bytes[256];
  while (true) {
    ssize_t count = read(fd, bytes, sizeof(bytes));
    if (count > 0) {
      if ((size_t)count > 4096U - *total) return false;
      *total += (size_t)count;
      continue;
    }
    if (count == 0) {
      *open_pipe = false;
      return true;
    }
    if (errno == EINTR) continue;
    return errno == EAGAIN || errno == EWOULDBLOCK;
  }
}

static bw_launchd_probe collect_presence(const char *name) {
  if (!valid_fixed_name(name) || !bw_fixed_executable_is_secure(LAUNCHCTL)) {
    return BW_LAUNCHD_PROBE_ERROR;
  }
  int output_pipe[2] = {-1, -1};
  int error_pipe[2] = {-1, -1};
  int null_fd = -1;
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  bool actions_ready = false;
  bool attributes_ready = false;
  pid_t child = -1;
  bw_launchd_probe result = BW_LAUNCHD_PROBE_ERROR;
  if (pipe(output_pipe) != 0 || pipe(error_pipe) != 0) goto done;
  null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (null_fd < 0 || !set_nonblocking(output_pipe[0]) || !set_nonblocking(error_pipe[0])) goto done;
  if (posix_spawn_file_actions_init(&actions) != 0) goto done;
  actions_ready = true;
  if (posix_spawnattr_init(&attributes) != 0) goto done;
  attributes_ready = true;
  if (posix_spawnattr_setpgroup(&attributes, 0) != 0 ||
      posix_spawnattr_setflags(
          &attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP) != 0) goto done;
  if (posix_spawn_file_actions_adddup2(&actions, null_fd, STDIN_FILENO) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, error_pipe[1], STDERR_FILENO) != 0 ||
      posix_spawn_file_actions_addclose(&actions, output_pipe[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, error_pipe[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, output_pipe[1]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, error_pipe[1]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, null_fd) != 0) goto done;
  char *args[] = {LAUNCHCTL, "print", "system", NULL};
  if (posix_spawn(&child, LAUNCHCTL, &actions, &attributes, args, FIXED_ENV) != 0) goto done;
  close_fd(&output_pipe[1]);
  close_fd(&error_pipe[1]);
  close_fd(&null_fd);
  uint64_t start = monotonic_milliseconds();
  if (start == 0) goto terminate;
  name_scanner scanner = {.needle = name, .needle_length = strlen(name)};
  bool stdout_open = true, stderr_open = true, child_reaped = false, ended_newline = false;
  size_t stdout_total = 0, stderr_total = 0;
  int status = 0;
  while (!child_reaped || stdout_open || stderr_open) {
    uint64_t now = monotonic_milliseconds();
    if (now == 0 || now - start >= TIMEOUT_MS) goto terminate;
    struct pollfd polls[2] = {
      {.fd = output_pipe[0], .events = stdout_open ? (POLLIN | POLLHUP) : 0},
      {.fd = error_pipe[0], .events = stderr_open ? (POLLIN | POLLHUP) : 0},
    };
    int remaining = (int)(TIMEOUT_MS - (now - start));
    if (remaining > 20) remaining = 20;
    if (poll(polls, 2, remaining) < 0 && errno != EINTR) goto terminate;
    if (stdout_open && !consume_stdout(
        output_pipe[0], &scanner, &stdout_total, &stdout_open, &ended_newline)) goto terminate;
    if (stderr_open && !consume_stderr(error_pipe[0], &stderr_total, &stderr_open)) goto terminate;
    if (!child_reaped) {
      pid_t waited = waitpid(child, &status, WNOHANG);
      if (waited == child) child_reaped = true;
      else if (waited < 0 && errno != EINTR) goto terminate;
    }
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || stdout_total == 0 ||
      stderr_total != 0 || !ended_newline) goto done;
  result = scanner_finish(&scanner) ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_ABSENT;
  child = -1;
  goto done;

terminate:
  if (child > 0) {
    if (kill(-child, SIGKILL) != 0 && errno != ESRCH) (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    child = -1;
  }

done:
  if (attributes_ready) (void)posix_spawnattr_destroy(&attributes);
  if (actions_ready) (void)posix_spawn_file_actions_destroy(&actions);
  close_fd(&output_pipe[0]);
  close_fd(&output_pipe[1]);
  close_fd(&error_pipe[0]);
  close_fd(&error_pipe[1]);
  close_fd(&null_fd);
  return result;
}

void bw_init_launchctl_presence_context(bw_launchctl_presence_context *context) {
  if (context == NULL) return;
  context->state_magic = CONTEXT_MAGIC;
}

bw_launchd_probe bw_probe_fixed_system_mach_name(void *raw, const char *fixed_name) {
  bw_launchctl_presence_context *context = raw;
  if (context == NULL || context->state_magic != CONTEXT_MAGIC) return BW_LAUNCHD_PROBE_ERROR;
  return collect_presence(fixed_name);
}

#if defined(BW_LAUNCHCTL_PRESENCE_TESTING)
bool bw_test_snapshot_contains_name(const char *snapshot, size_t length, const char *fixed_name) {
  if (snapshot == NULL || length == 0 || snapshot[length - 1] != '\n' ||
      !valid_fixed_name(fixed_name)) return false;
  name_scanner scanner = {.needle = fixed_name, .needle_length = strlen(fixed_name)};
  for (size_t index = 0; index < length; index += 1) {
    if (!scan_byte(&scanner, (unsigned char)snapshot[index])) return false;
  }
  return scanner_finish(&scanner);
}
#endif
