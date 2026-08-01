#include "macos-sudo-lifecycle-launcher.h"

#include "macos-fixed-command-runner.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SUDO_PATH "/usr/bin/sudo"
#define RUNNER_PATH "/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-runner"
#define OUTPUT_CAPACITY 4096
#define CHILD_TIMEOUT_MS 130000
#define RUNNER_STOP_TIMEOUT_MS 5000

static const char SUCCESS_OUTPUT[] =
    "{\"schema_version\":1,\"denial_verified\":true,\"cleanup_complete\":true}\n";
static char *const FIXED_ENV[] = {
  "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", NULL,
};

static uint64_t monotonic_ms(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0) return 0;
  return (uint64_t)value.tv_sec * UINT64_C(1000) + (uint64_t)value.tv_nsec / UINT64_C(1000000);
}

static void close_fd(int *fd) {
  if (*fd >= 0) { (void)close(*fd); *fd = -1; }
}

static bool nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool close_on_exec(int fd) {
  int flags = fcntl(fd, F_GETFD);
  return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool controlling_tty_available(void) {
  int fd = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  bool valid = isatty(fd) == 1;
  (void)close(fd);
  return valid;
}

typedef struct {
  int socket_fd;
  const bw_lifecycle_approval_bindings *approved;
  bool answered;
  pid_t runner_pid;
} approval_thread_context;

static void *answer_approval(void *raw) {
  approval_thread_context *context = raw;
  context->answered = bw_answer_lifecycle_approval_challenge(
      context->socket_fd, context->approved, &context->runner_pid);
  return NULL;
}

#if !defined(BW_SUDO_LAUNCHER_TESTING)
static bool exact_runner_process(pid_t pid, struct proc_bsdinfo *snapshot) {
  if (pid <= 1 || snapshot == NULL) return false;
  struct proc_bsdinfo before;
  struct proc_bsdinfo after;
  char path[PROC_PIDPATHINFO_MAXSIZE];
  memset(&before, 0, sizeof(before));
  memset(&after, 0, sizeof(after));
  memset(path, 0, sizeof(path));
  int first = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, sizeof(before));
  int path_length = proc_pidpath(pid, path, sizeof(path));
  int second = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after));
  if (first != (int)sizeof(before) || second != (int)sizeof(after) ||
      path_length != (int)strlen(RUNNER_PATH) ||
      memcmp(path, RUNNER_PATH, strlen(RUNNER_PATH)) != 0 || before.pbi_uid != 0 ||
      before.pbi_start_tvsec != after.pbi_start_tvsec ||
      before.pbi_start_tvusec != after.pbi_start_tvusec || before.pbi_pid != after.pbi_pid) {
    return false;
  }
  *snapshot = after;
  return true;
}
#endif

static void stop_exact_runner(pid_t pid) {
#if defined(BW_SUDO_LAUNCHER_TESTING)
  (void)pid;
#else
  struct proc_bsdinfo identity;
  if (!exact_runner_process(pid, &identity)) return;
  if (kill(pid, SIGKILL) != 0 && errno != ESRCH) return;
  uint64_t started = monotonic_ms();
  if (started == 0) return;
  while (monotonic_ms() - started < RUNNER_STOP_TIMEOUT_MS) {
    struct proc_bsdinfo current;
    if (!exact_runner_process(pid, &current) ||
        current.pbi_start_tvsec != identity.pbi_start_tvsec ||
        current.pbi_start_tvusec != identity.pbi_start_tvusec) return;
    (void)usleep(10000);
  }
#endif
}

static bool drain(int fd, char *bytes, size_t *length, bool *open) {
  char chunk[512];
  for (;;) {
    ssize_t count = read(fd, chunk, sizeof(chunk));
    if (count > 0) {
      if ((size_t)count > OUTPUT_CAPACITY - *length) return false;
      memcpy(bytes + *length, chunk, (size_t)count);
      *length += (size_t)count;
      continue;
    }
    if (count == 0) { *open = false; return true; }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
    return false;
  }
}

static bool collect_child(pid_t child, int output_fd, int error_fd, bool *child_reaped) {
  if (child_reaped == NULL) return false;
  *child_reaped = false;
  if (!nonblocking(output_fd) || !nonblocking(error_fd)) return false;
  char output[OUTPUT_CAPACITY + 1];
  char errors[OUTPUT_CAPACITY + 1];
  size_t output_length = 0;
  size_t error_length = 0;
  bool output_open = true;
  bool error_open = true;
  bool reaped = false;
  int status = 0;
  uint64_t started = monotonic_ms();
  if (started == 0) return false;
  while (!reaped || output_open || error_open) {
    uint64_t now = monotonic_ms();
    if (now == 0 || now - started >= CHILD_TIMEOUT_MS) return false;
    struct pollfd descriptors[2] = {
      {.fd = output_fd, .events = output_open ? (POLLIN | POLLHUP) : 0},
      {.fd = error_fd, .events = error_open ? (POLLIN | POLLHUP) : 0},
    };
    int result = poll(descriptors, 2, 20);
    if (result < 0 && errno != EINTR) return false;
    if (output_open && !drain(output_fd, output, &output_length, &output_open)) return false;
    if (error_open && !drain(error_fd, errors, &error_length, &error_open)) return false;
    if (!reaped) {
      pid_t waited = waitpid(child, &status, WNOHANG);
      if (waited == child) { reaped = true; *child_reaped = true; }
      else if (waited < 0 && errno != EINTR) return false;
    }
  }
  output[output_length] = '\0';
  errors[error_length] = '\0';
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 && error_length == 0 &&
      output_length == sizeof(SUCCESS_OUTPUT) - 1 &&
      memcmp(output, SUCCESS_OUTPUT, sizeof(SUCCESS_OUTPUT) - 1) == 0;
}

static bw_sudo_lifecycle_result launch(
    const char *executable,
    char *const arguments[],
    bool production,
    const bw_lifecycle_approval_bindings *approved) {
  bw_sudo_lifecycle_result result = {0};
  if (approved == NULL || executable == NULL || arguments == NULL) return result;
  if (production && (!controlling_tty_available() ||
      !bw_fixed_executable_is_secure(SUDO_PATH) ||
      !bw_fixed_executable_is_secure(RUNNER_PATH))) return result;

  int approval[2] = {-1, -1};
  int output[2] = {-1, -1};
  int errors[2] = {-1, -1};
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  bool actions_ready = false;
  bool attributes_ready = false;
  pid_t child = -1;
  approval_thread_context approval_context = {
    .socket_fd = -1, .approved = approved, .answered = false, .runner_pid = 0,
  };
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, approval) != 0 ||
      pipe(output) != 0 || pipe(errors) != 0 ||
      !close_on_exec(approval[0]) || !close_on_exec(approval[1]) ||
      !close_on_exec(output[0]) || !close_on_exec(output[1]) ||
      !close_on_exec(errors[0]) || !close_on_exec(errors[1]) ||
      posix_spawn_file_actions_init(&actions) != 0) {
    goto done;
  }
  actions_ready = true;
  if (posix_spawnattr_init(&attributes) != 0) goto done;
  attributes_ready = true;
  if (posix_spawnattr_setpgroup(&attributes, 0) != 0 ||
      posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, approval[1], STDIN_FILENO) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, errors[1], STDERR_FILENO) != 0 ||
      posix_spawn_file_actions_addclose(&actions, approval[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, approval[1]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, output[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, output[1]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, errors[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, errors[1]) != 0) goto done;
  if (posix_spawn(&child, executable, &actions, &attributes, arguments, FIXED_ENV) != 0) goto done;
  result.child_started = true;
  close_fd(&approval[1]);
  close_fd(&output[1]);
  close_fd(&errors[1]);
  approval_context.socket_fd = approval[0];
  pthread_t approval_thread;
  bool approval_thread_started = pthread_create(
      &approval_thread, NULL, answer_approval, &approval_context) == 0;
  if (!approval_thread_started) goto terminate;
  bool child_reaped = false;
  result.child_exited_cleanly = collect_child(child, output[0], errors[0], &child_reaped);
  if (child_reaped) child = -1;
  if (!result.child_exited_cleanly) (void)shutdown(approval[0], SHUT_RDWR);
  bool approval_thread_joined = pthread_join(approval_thread, NULL) == 0;
  result.challenge_answered = approval_thread_joined && approval_context.answered;
  close_fd(&approval[0]);
  if (!result.child_exited_cleanly || !result.challenge_answered) goto terminate;
  result.denial_verified = true;
  result.cleanup_complete = true;
  goto done;

terminate:
  stop_exact_runner(approval_context.runner_pid);
  if (child > 0) {
    if (kill(-child, SIGKILL) != 0 && errno != ESRCH) (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    child = -1;
  }

done:
  if (attributes_ready) (void)posix_spawnattr_destroy(&attributes);
  if (actions_ready) (void)posix_spawn_file_actions_destroy(&actions);
  close_fd(&approval[0]); close_fd(&approval[1]);
  close_fd(&output[0]); close_fd(&output[1]);
  close_fd(&errors[0]); close_fd(&errors[1]);
  return result;
}

bw_sudo_lifecycle_result bw_run_fixed_sudo_lifecycle(
    const bw_lifecycle_approval_bindings *approved) {
  char *const arguments[] = {
    (char *)SUDO_PATH, "-k", "--", (char *)RUNNER_PATH,
    "--approved-denial-lifecycle", NULL,
  };
  return launch(SUDO_PATH, arguments, true, approved);
}

#if defined(BW_SUDO_LAUNCHER_TESTING)
bw_sudo_lifecycle_result bw_run_sudo_lifecycle_fixture(
    const char *fixture_executable,
    const bw_lifecycle_approval_bindings *approved) {
  char *const arguments[] = {(char *)fixture_executable, "--fixture-runner", NULL};
  return launch(fixture_executable, arguments, false, approved);
}
#endif
