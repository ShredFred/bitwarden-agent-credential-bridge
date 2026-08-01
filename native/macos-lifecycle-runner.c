#include "macos-fixed-command-runner.h"
#include "macos-fixed-system-probes.h"
#include "macos-native-lifecycle-wiring.h"

#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>

#if !defined(BW_RUNNER_ARTIFACT_HEADER)
#error "BW_RUNNER_ARTIFACT_HEADER must name the generated reviewed artifact header"
#endif
#include BW_RUNNER_ARTIFACT_HEADER

#define MODE "--approved-denial-lifecycle"
#define BINARY_PARENT "/Library/PrivilegedHelperTools"
#define PLIST_PARENT "/Library/LaunchDaemons"
#define LABEL "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define PROGRAM BINARY_PARENT "/" LABEL
#define ACCOUNT "_bwagentbridge"

static const char SUCCESS[] =
    "{\"schema_version\":1,\"mutation_complete\":true,\"denial_verified\":true,"
    "\"cleanup_complete\":true,\"manual_recovery_required\":false}\n";

static bool write_success(void) {
  size_t offset = 0;
  while (offset < sizeof(SUCCESS) - 1) {
    ssize_t count = write(STDOUT_FILENO, SUCCESS + offset, sizeof(SUCCESS) - 1 - offset);
    if (count > 0) { offset += (size_t)count; continue; }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

static int hex_nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

static bool parse_digest(const char *hex, unsigned char output[BW_APPROVAL_DIGEST_BYTES]) {
  if (hex == NULL || strnlen(hex, 65) != 64) return false;
  for (size_t index = 0; index < BW_APPROVAL_DIGEST_BYTES; index += 1) {
    int high = hex_nibble(hex[index * 2]);
    int low = hex_nibble(hex[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    output[index] = (unsigned char)((high << 4) | low);
  }
  return true;
}

static bool exact_artifact_contract(bw_lifecycle_approval_bindings *bindings) {
  if (bindings == NULL || BW_RUNNER_HELPER_LENGTH == 0 || BW_RUNNER_PLIST_LENGTH == 0 ||
      BW_RUNNER_HELPER_LENGTH > UINT32_MAX || BW_RUNNER_PLIST_LENGTH > UINT32_MAX ||
      sizeof(BW_RUNNER_BINARY_SHA256_HEX) != 65 || sizeof(BW_RUNNER_PLIST_SHA256_HEX) != 65 ||
      sizeof(BW_RUNNER_REQUIREMENT_SHA256_HEX) != 65 ||
      sizeof(BW_RUNNER_REQUIREMENT_SHA256) != BW_APPROVAL_DIGEST_BYTES ||
      !parse_digest(BW_RUNNER_BINARY_SHA256_HEX, bindings->binary_sha256) ||
      !parse_digest(BW_RUNNER_PLIST_SHA256_HEX, bindings->plist_sha256) ||
      CC_SHA256(BW_RUNNER_HELPER_BYTES, (CC_LONG)BW_RUNNER_HELPER_LENGTH,
          bindings->binary_sha256) == NULL ||
      CC_SHA256(BW_RUNNER_PLIST_BYTES, (CC_LONG)BW_RUNNER_PLIST_LENGTH,
          bindings->plist_sha256) == NULL) return false;
  unsigned char expected_binary[BW_APPROVAL_DIGEST_BYTES];
  unsigned char expected_plist[BW_APPROVAL_DIGEST_BYTES];
  unsigned char expected_requirement[BW_APPROVAL_DIGEST_BYTES];
  if (!parse_digest(BW_RUNNER_BINARY_SHA256_HEX, expected_binary) ||
      !parse_digest(BW_RUNNER_PLIST_SHA256_HEX, expected_plist) ||
      !parse_digest(BW_RUNNER_REQUIREMENT_SHA256_HEX, expected_requirement) ||
      memcmp(bindings->binary_sha256, expected_binary, sizeof(expected_binary)) != 0 ||
      memcmp(bindings->plist_sha256, expected_plist, sizeof(expected_plist)) != 0 ||
      memcmp(BW_RUNNER_REQUIREMENT_SHA256, expected_requirement,
          sizeof(expected_requirement)) != 0) return false;
  memcpy(bindings->requirement_sha256, BW_RUNNER_REQUIREMENT_SHA256,
      BW_APPROVAL_DIGEST_BYTES);
  return true;
}

static bw_account_record run_private_account(void) {
  bw_account_record account = {
    .name = ACCOUNT, .unique_id = 499, .shell = "/usr/bin/false", .home = "/var/empty",
  };
  uuid_t generated;
  uuid_generate_random(generated);
  uuid_unparse_upper(generated, account.generated_uid);
  memset(generated, 0, sizeof(generated));
  return account;
}

static bw_launchd_job_record fixed_job(void) {
  return (bw_launchd_job_record){
    .label = LABEL, .program = PROGRAM, .user_name = ACCOUNT, .mach_service = LABEL,
    .binary_sha256 = BW_RUNNER_BINARY_SHA256_HEX,
    .plist_sha256 = BW_RUNNER_PLIST_SHA256_HEX,
    .demand_activation_only = true,
  };
}

int main(int argc, char **argv) {
  if (argc != 2 || argv == NULL || argv[0] == NULL || argv[1] == NULL ||
      strcmp(argv[1], MODE) != 0) return 64;
  if (getuid() == 0 || geteuid() != 0) return 77;
  bw_lifecycle_approval_bindings approval_bindings;
  memset(&approval_bindings, 0, sizeof(approval_bindings));
  if (!exact_artifact_contract(&approval_bindings) ||
      !bw_receive_and_consume_lifecycle_approval(STDIN_FILENO, &approval_bindings)) return 78;
  (void)umask(077);

  int binary_parent = open(BINARY_PARENT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int plist_parent = open(PLIST_PARENT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (binary_parent < 0 || plist_parent < 0) {
    if (binary_parent >= 0) (void)close(binary_parent);
    if (plist_parent >= 0) (void)close(plist_parent);
    return 78;
  }

  bw_account_record account = run_private_account();
  bw_launchd_job_record job = fixed_job();
  bw_fixed_system_probes probes;
  bw_init_fixed_system_probes(&probes);
  bw_native_lifecycle_wiring wiring;
  bool initialized = bw_init_native_lifecycle_wiring(
      &wiring, bw_run_fixed_command, bw_fixed_system_presence_probe,
      bw_fixed_system_denial_probe, &probes, binary_parent, plist_parent,
      BW_RUNNER_HELPER_BYTES, BW_RUNNER_HELPER_LENGTH,
      BW_RUNNER_PLIST_BYTES, BW_RUNNER_PLIST_LENGTH,
      BW_RUNNER_REQUIREMENT_SHA256, 0, 0, &account, &job);
  bool approval_reconciled = initialized &&
      memcmp(&approval_bindings, &wiring.approval_bindings, sizeof(approval_bindings)) == 0;
  memset(&approval_bindings, 0, sizeof(approval_bindings));
  bw_lifecycle_report report = approval_reconciled
      ? bw_run_lifecycle(&wiring.request)
      : (bw_lifecycle_report){0};
  wiring.artifact_binding.binary = NULL;
  wiring.artifact_binding.plist = NULL;
  wiring.artifact_binding.bound = false;
  memset(&wiring, 0, sizeof(wiring));
  memset(&account, 0, sizeof(account));
  bool binary_closed = close(binary_parent) == 0;
  bool plist_closed = close(plist_parent) == 0;
  bool closed = binary_closed && plist_closed;
  if (!closed || !report.preflight_complete || !report.account_created_and_verified ||
      !report.binary_published_and_verified || !report.plist_published_and_verified ||
      !report.job_bootstrapped_and_verified || !report.process_activated_and_verified ||
      !report.mutation_complete || !report.denial_verified || !report.cleanup_attempted ||
      !report.job_cleanup_complete || !report.plist_cleanup_complete ||
      !report.binary_cleanup_complete || !report.account_cleanup_complete ||
      !report.final_absence_complete || !report.cleanup_complete ||
      report.manual_recovery_required) return 1;
  return write_success() ? 0 : 1;
}
