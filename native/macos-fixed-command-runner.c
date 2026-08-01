#include "macos-fixed-command-runner.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char *const FIXED_ENV[] = {
  "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
  "LANG=C",
  "LC_ALL=C",
  NULL,
};

static bool valid_argument(const char *value) {
  if (value == NULL) return false;
  size_t length = strnlen(value, 4096);
  if (length == 0 || length >= 4096) return false;
  for (size_t index = 0; index < length; index += 1) {
    unsigned char byte = (unsigned char)value[index];
    if (byte == 0 || byte == '\n' || byte == '\r') return false;
  }
  return true;
}

static bool valid_invocation(const char *executable, char *const argv[]) {
  if (executable == NULL || executable[0] != '/' || !valid_argument(executable) || argv == NULL ||
      argv[0] == NULL || strcmp(argv[0], executable) != 0) return false;
  size_t count = 0;
  while (argv[count] != NULL) {
    if (count >= 32 || !valid_argument(argv[count])) return false;
    count += 1;
  }
  return count > 0;
}

static bool has_no_extended_acl(const char *path) {
  errno = 0;
  acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
  if (acl == NULL) return errno == ENOENT;
  acl_entry_t entry;
  int found = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  (void)acl_free(acl);
  return found == 0;
}

static bool acceptable_executable_stat(const struct stat *value) {
  return S_ISREG(value->st_mode) && value->st_uid == 0 &&
      (value->st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) == 0 &&
      (value->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

static bool regular_root_owned_executable(const char *path) {
  struct stat path_value;
  struct stat fd_value;
  if (lstat(path, &path_value) != 0 || S_ISLNK(path_value.st_mode) ||
      !acceptable_executable_stat(&path_value) || !has_no_extended_acl(path)) return false;
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  bool valid = fstat(fd, &fd_value) == 0 && acceptable_executable_stat(&fd_value) &&
      path_value.st_dev == fd_value.st_dev && path_value.st_ino == fd_value.st_ino &&
      path_value.st_mode == fd_value.st_mode && path_value.st_uid == fd_value.st_uid &&
      path_value.st_gid == fd_value.st_gid;
  (void)close(fd);
  return valid;
}

static uint64_t monotonic_milliseconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
  return ((uint64_t)value.tv_sec * UINT64_C(1000)) + ((uint64_t)value.tv_nsec / UINT64_C(1000000));
}

static bool set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool append_from_fd(
    int fd,
    char *buffer,
    size_t *length,
    size_t maximum,
    bool *open_pipe,
    bool *overflow) {
  char chunk[4096];
  while (true) {
    ssize_t count = read(fd, chunk, sizeof(chunk));
    if (count > 0) {
      if ((size_t)count > maximum - *length) {
        *overflow = true;
        return true;
      }
      memcpy(buffer + *length, chunk, (size_t)count);
      *length += (size_t)count;
      continue;
    }
    if (count == 0) {
      *open_pipe = false;
      return true;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
    return false;
  }
}

static void close_if_open(int *fd) {
  if (*fd >= 0) {
    (void)close(*fd);
    *fd = -1;
  }
}

bw_command_result bw_run_fixed_command(
    const char *absolute_executable,
    char *const argv[],
    unsigned int timeout_milliseconds,
    size_t maximum_output_bytes,
    bw_command_output *output) {
  if (output == NULL) return BW_COMMAND_INVALID;
  memset(output, 0, sizeof(*output));
  output->exit_code = -1;
  if (!valid_invocation(absolute_executable, argv) ||
      !regular_root_owned_executable(absolute_executable) || timeout_milliseconds < 1 ||
      timeout_milliseconds > 60000 || maximum_output_bytes < 1 ||
      maximum_output_bytes > BW_COMMAND_OUTPUT_CAPACITY) return BW_COMMAND_INVALID;

  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  int null_fd = -1;
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  bool actions_ready = false;
  bool attributes_ready = false;
  pid_t child = -1;
  bw_command_result result = BW_COMMAND_IO_FAILED;

  if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) goto done;
  null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (null_fd < 0 || !set_nonblocking(stdout_pipe[0]) || !set_nonblocking(stderr_pipe[0])) goto done;
  if (posix_spawn_file_actions_init(&actions) != 0) goto done;
  actions_ready = true;
  if (posix_spawnattr_init(&attributes) != 0) goto done;
  attributes_ready = true;
  if (posix_spawnattr_setpgroup(&attributes, 0) != 0 ||
      posix_spawnattr_setflags(
          &attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP) != 0) goto done;
  if (posix_spawn_file_actions_adddup2(&actions, null_fd, STDIN_FILENO) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, stderr_pipe[1], STDERR_FILENO) != 0 ||
      posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, stderr_pipe[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, stdout_pipe[1]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, stderr_pipe[1]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, null_fd) != 0) goto done;

  int spawn_error = posix_spawn(
      &child, absolute_executable, &actions, &attributes, argv, FIXED_ENV);
  if (spawn_error != 0) {
    result = BW_COMMAND_SPAWN_FAILED;
    goto done;
  }
  close_if_open(&stdout_pipe[1]);
  close_if_open(&stderr_pipe[1]);
  close_if_open(&null_fd);

  uint64_t start = monotonic_milliseconds();
  if (start == 0) goto terminate;
  bool stdout_open = true;
  bool stderr_open = true;
  bool child_reaped = false;
  bool overflow = false;
  int status = 0;
  while (!child_reaped || stdout_open || stderr_open) {
    uint64_t now = monotonic_milliseconds();
    if (now == 0 || now - start >= timeout_milliseconds) {
      result = BW_COMMAND_TIMEOUT;
      goto terminate;
    }
    struct pollfd polls[2] = {
      {.fd = stdout_pipe[0], .events = stdout_open ? (POLLIN | POLLHUP) : 0},
      {.fd = stderr_pipe[0], .events = stderr_open ? (POLLIN | POLLHUP) : 0},
    };
    int remaining = (int)(timeout_milliseconds - (now - start));
    if (remaining > 20) remaining = 20;
    int polled = poll(polls, 2, remaining);
    if (polled < 0 && errno != EINTR) goto terminate;
    if (stdout_open && !append_from_fd(stdout_pipe[0], output->stdout_bytes,
        &output->stdout_length, maximum_output_bytes, &stdout_open, &overflow)) goto terminate;
    if (stderr_open && !append_from_fd(stderr_pipe[0], output->stderr_bytes,
        &output->stderr_length, maximum_output_bytes, &stderr_open, &overflow)) goto terminate;
    if (overflow) {
      result = BW_COMMAND_OUTPUT_TOO_LARGE;
      goto terminate;
    }
    if (!child_reaped) {
      pid_t waited = waitpid(child, &status, WNOHANG);
      if (waited == child) child_reaped = true;
      else if (waited < 0 && errno != EINTR) goto terminate;
    }
  }
  output->stdout_bytes[output->stdout_length] = '\0';
  output->stderr_bytes[output->stderr_length] = '\0';
  if (!WIFEXITED(status) && !WIFSIGNALED(status)) {
    result = BW_COMMAND_IO_FAILED;
    goto terminate;
  }
  if (WIFEXITED(status)) {
    output->exited = true;
    output->exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    output->signaled = true;
    output->signal_number = WTERMSIG(status);
  }
  result = BW_COMMAND_OK;
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
  close_if_open(&stdout_pipe[0]);
  close_if_open(&stdout_pipe[1]);
  close_if_open(&stderr_pipe[0]);
  close_if_open(&stderr_pipe[1]);
  close_if_open(&null_fd);
  return result;
}
