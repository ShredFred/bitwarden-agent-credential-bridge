#include "macos-native-lifecycle-wiring.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define LABEL "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define TARGET "system/" LABEL

typedef struct {
  bool account_present;
  bool job_present;
  bool running;
  bool replace_plist_on_denial;
  int plist_parent_fd;
  bw_account_record account;
  int mutations;
} fake_system;

static fake_system *ACTIVE;

static void command_output(bw_command_output *output, int code, const char *out, const char *err) {
  memset(output, 0, sizeof(*output));
  output->exited = true;
  output->exit_code = code;
  if (out != NULL) {
    output->stdout_length = strlen(out);
    (void)strcpy(output->stdout_bytes, out);
  }
  if (err != NULL) {
    output->stderr_length = strlen(err);
    (void)strcpy(output->stderr_bytes, err);
  }
}

static bw_command_result fake_commands(
    const char *executable,
    char *const argv[],
    unsigned int timeout,
    size_t maximum,
    bw_command_output *output) {
  fake_system *host = ACTIVE;
  if (host == NULL || argv == NULL || strcmp(argv[0], executable) != 0) {
    return BW_COMMAND_INVALID;
  }
  if (strcmp(executable, "/usr/bin/dscl") == 0) {
    if (timeout != 5000 || maximum != 8192) return BW_COMMAND_INVALID;
    command_output(output, 0, NULL, NULL);
    if (strcmp(argv[2], "-search") == 0) {
      if (!host->account_present) return BW_COMMAND_OK;
      char value[256];
      (void)snprintf(value, sizeof(value), "%s\t\t%s\n", host->account.name, argv[5]);
      command_output(output, 0, value, NULL);
      return BW_COMMAND_OK;
    }
    if (strcmp(argv[2], "-create") == 0) {
      host->account_present = true;
      host->mutations += 1;
      return BW_COMMAND_OK;
    }
    if (strcmp(argv[2], "-read") == 0 && host->account_present) {
      char value[512];
      (void)snprintf(value, sizeof(value),
          "UniqueID: %u\nGeneratedUID: %s\nUserShell: %s\nNFSHomeDirectory: %s\n",
          (unsigned int)host->account.unique_id, host->account.generated_uid,
          host->account.shell, host->account.home);
      command_output(output, 0, value, NULL);
      return BW_COMMAND_OK;
    }
    if (strcmp(argv[2], "-delete") == 0 && host->account_present) {
      host->account_present = false;
      host->mutations += 1;
      return BW_COMMAND_OK;
    }
    return BW_COMMAND_SPAWN_FAILED;
  }
  if (strcmp(executable, "/bin/launchctl") != 0 || timeout != 10000 ||
      maximum != BW_COMMAND_OUTPUT_CAPACITY) return BW_COMMAND_INVALID;
  if (strcmp(argv[1], "print") == 0 && strcmp(argv[2], TARGET) == 0) {
    if (!host->job_present) {
      command_output(output, 113, NULL,
          "Bad request.\nCould not find service \"" LABEL "\" in domain for system\n");
      return BW_COMMAND_OK;
    }
    char value[1024];
    (void)snprintf(value, sizeof(value),
        "system/%s = {\n\tstate = %s\n\tprogram = /Library/PrivilegedHelperTools/%s\n"
        "\tusername = _bwagentbridge\n\tpid = %s\n}\n",
        LABEL, host->running ? "running" : "not running", LABEL,
        host->running ? "4242" : "0");
    command_output(output, 0, value, NULL);
    return BW_COMMAND_OK;
  }
  command_output(output, 0, NULL, NULL);
  if (strcmp(argv[1], "bootstrap") == 0) host->job_present = true;
  else if (strcmp(argv[1], "kickstart") == 0) host->running = true;
  else if (strcmp(argv[1], "kill") == 0) host->running = false;
  else if (strcmp(argv[1], "bootout") == 0) host->job_present = false;
  else return BW_COMMAND_SPAWN_FAILED;
  host->mutations += 1;
  return BW_COMMAND_OK;
}

static bw_launchd_probe mach_presence(void *raw, const char *name) {
  fake_system *host = raw;
  if (host == NULL || strcmp(name, LABEL) != 0) return BW_LAUNCHD_PROBE_ERROR;
  return host->job_present ? BW_LAUNCHD_PRESENT : BW_LAUNCHD_ABSENT;
}

static bool denial(
    void *raw, const bw_launchd_job_record *identity, pid_t expected_helper_pid) {
  fake_system *host = raw;
  if (host == NULL || !host->job_present || !host->running || expected_helper_pid != 4242 ||
      strcmp(identity->label, LABEL) != 0) {
    return false;
  }
  if (!host->replace_plist_on_denial) return true;
  const char *name = LABEL ".plist";
  if (unlinkat(host->plist_parent_fd, name, 0) != 0) return false;
  int fd = openat(host->plist_parent_fd, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  static const char foreign[] = "foreign";
  bool ok = fd >= 0 && write(fd, foreign, sizeof(foreign)) == (ssize_t)sizeof(foreign);
  if (fd >= 0 && close(fd) != 0) ok = false;
  return ok;
}

static bw_account_record account(void) {
  return (bw_account_record){
    .name = "_bwagentbridge", .unique_id = 499,
    .generated_uid = "12345678-1234-4ABC-8DEF-1234567890AB",
    .shell = "/usr/bin/false", .home = "/var/empty",
  };
}

static bw_launchd_job_record job(void) {
  return (bw_launchd_job_record){
    .label = LABEL, .program = "/Library/PrivilegedHelperTools/" LABEL,
    .user_name = "_bwagentbridge", .mach_service = LABEL,
    .binary_sha256 = "e072091af0e8a40cb74dcba6563687af03648839b91787fc20dbb8af0f4d571c",
    .plist_sha256 = "56b162b6263c4ceec673d49b3d91e826a05ab88cdd8c1ce03756b13d46ef6858",
    .demand_activation_only = true,
  };
}

static bool absent(int parent, const char *name) {
  struct stat value;
  return fstatat(parent, name, &value, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}

static bool run_case(fake_system *host, int parent, bool replacement) {
  static const unsigned char binary[] = "binary-bytes";
  static const unsigned char plist[] = "plist-bytes";
  static const unsigned char requirement[BW_APPROVAL_DIGEST_BYTES] = {0x33};
  bw_account_record account_value = account();
  bw_launchd_job_record job_value = job();
  host->account = account_value;
  host->plist_parent_fd = parent;
  host->replace_plist_on_denial = replacement;
  ACTIVE = host;
  bw_native_lifecycle_wiring wiring;
  bool production_paths_rejected = !bw_init_native_lifecycle_wiring(
      &wiring, fake_commands, mach_presence, denial, host, parent, parent,
      binary, sizeof(binary), plist, sizeof(plist), requirement, getuid(), getgid(),
      &account_value, &job_value);
  if (!production_paths_rejected) return false;
  if (!bw_init_native_lifecycle_wiring_for_test(&wiring, fake_commands, mach_presence, denial, host,
      parent, parent, binary, sizeof(binary), plist, sizeof(plist), requirement, getuid(), getgid(),
      &account_value, &job_value)) return false;
  int approval_sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, approval_sockets) != 0) return false;
  bw_set_lifecycle_approval_nonce_for_test(replacement ? 0xB2 : 0xB1);
  pid_t approval_child = fork();
  if (approval_child < 0) return false;
  if (approval_child == 0) {
    (void)close(approval_sockets[1]);
    bool answered = bw_answer_lifecycle_approval_challenge(
        approval_sockets[0], &wiring.approval_bindings, NULL);
    (void)close(approval_sockets[0]);
    _exit(answered ? 0 : 1);
  }
  (void)close(approval_sockets[0]);
  bw_lifecycle_report report = bw_run_authorized_native_lifecycle(&wiring, approval_sockets[1]);
  int approval_status = 0;
  if (close(approval_sockets[1]) != 0 ||
      waitpid(approval_child, &approval_status, 0) != approval_child ||
      !WIFEXITED(approval_status) || WEXITSTATUS(approval_status) != 0) return false;
  if (!replacement) {
    return report.mutation_complete && report.cleanup_complete &&
        !report.manual_recovery_required && !host->account_present && !host->job_present &&
        absent(parent, LABEL) && absent(parent, LABEL ".plist") &&
        !wiring.artifact_binding.bound;
  }
  struct stat value;
  bool preserved = report.denial_verified && report.manual_recovery_required &&
      host->job_present && !host->account_present && absent(parent, LABEL) &&
      fstatat(parent, LABEL ".plist", &value, AT_SYMLINK_NOFOLLOW) == 0 && value.st_size == 8 &&
      !wiring.artifact_binding.bound;
  host->job_present = false;
  host->running = false;
  (void)unlinkat(parent, LABEL ".plist", 0);
  return preserved;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  char root[] = "/tmp/bw-native-wiring.XXXXXX";
  if (mkdtemp(root) == NULL) return 1;
  int parent = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent < 0) return 1;
  fake_system clean = {0};
  bool clean_complete = run_case(&clean, parent, false);
  fake_system replacement = {0};
  bool replacement_blocked = run_case(&replacement, parent, true);
  bool fixture_cleanup = close(parent) == 0 && rmdir(root) == 0;
  bool all = clean_complete && replacement_blocked && fixture_cleanup;
  (void)printf(
      "{\"schema_version\":1,\"clean_complete\":%s,\"replacement_blocked\":%s,"
      "\"fixture_cleanup\":%s}\n",
      clean_complete ? "true" : "false", replacement_blocked ? "true" : "false",
      fixture_cleanup ? "true" : "false");
  return all ? 0 : 1;
}
