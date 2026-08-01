#include "macos-native-lifecycle-wiring.h"

#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <sys/param.h>
#include <string.h>

#define BINARY_PARENT "/Library/PrivilegedHelperTools"
#define PLIST_PARENT "/Library/LaunchDaemons"

static bool fd_has_path(int fd, const char *expected) {
  char path[MAXPATHLEN];
  return fd >= 0 && fcntl(fd, F_GETPATH, path) == 0 && strcmp(path, expected) == 0;
}

static bool exact_parent_paths(const bw_native_artifact_binding *binding) {
  return binding != NULL && (binding->fixture_paths ||
      (fd_has_path(binding->binary_parent_fd, BINARY_PARENT) &&
       fd_has_path(binding->plist_parent_fd, PLIST_PARENT)));
}

static bool same_job(
    const bw_launchd_job_record *left, const bw_launchd_job_record *right) {
  return left != NULL && right != NULL && strcmp(left->label, right->label) == 0 &&
      strcmp(left->program, right->program) == 0 &&
      strcmp(left->user_name, right->user_name) == 0 &&
      strcmp(left->mach_service, right->mach_service) == 0 &&
      strcmp(left->binary_sha256, right->binary_sha256) == 0 &&
      strcmp(left->plist_sha256, right->plist_sha256) == 0 &&
      left->demand_activation_only == right->demand_activation_only;
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

static bool derive_approval_bindings(
    bw_lifecycle_approval_bindings *bindings,
    const unsigned char *binary_bytes,
    size_t binary_length,
    const unsigned char *plist_bytes,
    size_t plist_length,
    const unsigned char requirement_sha256[BW_APPROVAL_DIGEST_BYTES],
    const bw_launchd_job_record *job) {
  if (bindings == NULL || binary_length > UINT32_MAX || plist_length > UINT32_MAX ||
      requirement_sha256 == NULL || job == NULL) return false;
  bw_lifecycle_approval_bindings derived;
  if (CC_SHA256(binary_bytes, (CC_LONG)binary_length, derived.binary_sha256) == NULL ||
      CC_SHA256(plist_bytes, (CC_LONG)plist_length, derived.plist_sha256) == NULL) return false;
  memcpy(derived.requirement_sha256, requirement_sha256, BW_APPROVAL_DIGEST_BYTES);
  unsigned char recorded_binary[BW_APPROVAL_DIGEST_BYTES];
  unsigned char recorded_plist[BW_APPROVAL_DIGEST_BYTES];
  if (!parse_digest(job->binary_sha256, recorded_binary) ||
      !parse_digest(job->plist_sha256, recorded_plist) ||
      memcmp(derived.binary_sha256, recorded_binary, BW_APPROVAL_DIGEST_BYTES) != 0 ||
      memcmp(derived.plist_sha256, recorded_plist, BW_APPROVAL_DIGEST_BYTES) != 0) return false;
  *bindings = derived;
  return true;
}

static bool verify_artifacts(void *raw, const bw_launchd_job_record *identity) {
  bw_native_lifecycle_wiring *wiring = raw;
  if (wiring == NULL || !wiring->artifact_binding.bound ||
      !same_job(identity, &wiring->request.job_candidate) ||
      !exact_parent_paths(&wiring->artifact_binding)) return false;
  bw_native_artifact_binding *binding = &wiring->artifact_binding;
  return binding->binary != NULL && binding->plist != NULL &&
      bw_verify_owned_file(binding->binary, binding->binary_bytes, binding->binary_length,
          0555, binding->owner, binding->group) == BW_FILE_OK &&
      bw_verify_owned_file(binding->plist, binding->plist_bytes, binding->plist_length,
          0644, binding->owner, binding->group) == BW_FILE_OK;
}

static bool bind_artifacts(
    void *raw, const bw_owned_file *binary, const bw_owned_file *plist) {
  bw_native_lifecycle_wiring *wiring = raw;
  if (wiring == NULL || wiring->artifact_binding.bound || binary == NULL || plist == NULL ||
      !binary->created || !plist->created) return false;
  wiring->artifact_binding.binary = binary;
  wiring->artifact_binding.plist = plist;
  wiring->artifact_binding.bound = true;
  if (!verify_artifacts(wiring, &wiring->request.job_candidate)) {
    wiring->artifact_binding.binary = NULL;
    wiring->artifact_binding.plist = NULL;
    wiring->artifact_binding.bound = false;
    return false;
  }
  return true;
}

static bool init_wiring(
    bw_native_lifecycle_wiring *wiring,
    bw_fixed_command_runner runner,
    bw_mach_presence_probe mach_presence,
    bw_mach_denial_probe denial,
    void *mach_context,
    int binary_parent_fd,
    int plist_parent_fd,
    const unsigned char *binary_bytes,
    size_t binary_length,
    const unsigned char *plist_bytes,
    size_t plist_length,
    const unsigned char requirement_sha256[BW_APPROVAL_DIGEST_BYTES],
    uid_t owner,
    gid_t group,
    const bw_account_record *account,
    const bw_launchd_job_record *job,
    bool fixture_paths) {
  if (wiring == NULL || runner == NULL || mach_presence == NULL || denial == NULL ||
      mach_context == NULL || binary_parent_fd < 0 || plist_parent_fd < 0 ||
      binary_bytes == NULL || binary_length == 0 || plist_bytes == NULL || plist_length == 0 ||
      requirement_sha256 == NULL || account == NULL || job == NULL) return false;
  memset(wiring, 0, sizeof(*wiring));
  wiring->artifact_binding = (bw_native_artifact_binding){
    .binary_bytes = binary_bytes, .binary_length = binary_length,
    .plist_bytes = plist_bytes, .plist_length = plist_length,
    .owner = owner, .group = group, .binary_parent_fd = binary_parent_fd,
    .plist_parent_fd = plist_parent_fd, .fixture_paths = fixture_paths,
  };
  if (!exact_parent_paths(&wiring->artifact_binding)) {
    memset(wiring, 0, sizeof(*wiring));
    return false;
  }
  if (!derive_approval_bindings(&wiring->approval_bindings, binary_bytes, binary_length,
      plist_bytes, plist_length, requirement_sha256, job)) {
    memset(wiring, 0, sizeof(*wiring));
    return false;
  }
  bw_directory_ops directory_ops;
  bw_launchd_ops launchd_ops;
  if (!bw_init_dscl_directory_ops(&wiring->directory_adapter, runner, &directory_ops) ||
      !bw_init_launchctl_job_ops(&wiring->launchctl_adapter, runner, mach_presence, denial,
          verify_artifacts, mach_context, wiring, job, &launchd_ops)) {
    memset(wiring, 0, sizeof(*wiring));
    return false;
  }
  wiring->request = (bw_lifecycle_request){
    .binary_parent_fd = binary_parent_fd, .plist_parent_fd = plist_parent_fd,
    .binary_bytes = binary_bytes, .binary_length = binary_length,
    .plist_bytes = plist_bytes, .plist_length = plist_length,
    .file_owner = owner, .file_group = group,
    .directory_ops = directory_ops, .account_candidate = *account,
    .launchd_ops = launchd_ops, .job_candidate = *job,
    .bind_owned_artifacts = bind_artifacts, .artifact_binding_context = wiring,
  };
  return true;
}

bool bw_init_native_lifecycle_wiring(
    bw_native_lifecycle_wiring *wiring,
    bw_fixed_command_runner runner,
    bw_mach_presence_probe mach_presence,
    bw_mach_denial_probe denial,
    void *mach_context,
    int binary_parent_fd,
    int plist_parent_fd,
    const unsigned char *binary_bytes,
    size_t binary_length,
    const unsigned char *plist_bytes,
    size_t plist_length,
    const unsigned char requirement_sha256[BW_APPROVAL_DIGEST_BYTES],
    uid_t owner,
    gid_t group,
    const bw_account_record *account,
    const bw_launchd_job_record *job) {
  return init_wiring(wiring, runner, mach_presence, denial, mach_context,
      binary_parent_fd, plist_parent_fd, binary_bytes, binary_length, plist_bytes,
      plist_length, requirement_sha256, owner, group, account, job, false);
}

#if defined(BW_NATIVE_WIRING_TESTING)
bool bw_init_native_lifecycle_wiring_for_test(
    bw_native_lifecycle_wiring *wiring,
    bw_fixed_command_runner runner,
    bw_mach_presence_probe mach_presence,
    bw_mach_denial_probe denial,
    void *mach_context,
    int binary_parent_fd,
    int plist_parent_fd,
    const unsigned char *binary_bytes,
    size_t binary_length,
    const unsigned char *plist_bytes,
    size_t plist_length,
    const unsigned char requirement_sha256[BW_APPROVAL_DIGEST_BYTES],
    uid_t owner,
    gid_t group,
    const bw_account_record *account,
    const bw_launchd_job_record *job) {
  return init_wiring(wiring, runner, mach_presence, denial, mach_context,
      binary_parent_fd, plist_parent_fd, binary_bytes, binary_length, plist_bytes,
      plist_length, requirement_sha256, owner, group, account, job, true);
}
#endif

bw_lifecycle_report bw_run_authorized_native_lifecycle(
    bw_native_lifecycle_wiring *wiring,
    int approval_socket_fd) {
  if (wiring == NULL || wiring->artifact_binding.bound) return (bw_lifecycle_report){0};
  bw_lifecycle_approval_bindings current;
  if (!derive_approval_bindings(&current, wiring->request.binary_bytes,
      wiring->request.binary_length, wiring->request.plist_bytes,
      wiring->request.plist_length, wiring->approval_bindings.requirement_sha256,
      &wiring->request.job_candidate) ||
      !bw_receive_and_consume_lifecycle_approval(approval_socket_fd, &current)) {
    return (bw_lifecycle_report){0};
  }
  bw_lifecycle_report report = bw_run_lifecycle(&wiring->request);
  wiring->artifact_binding.binary = NULL;
  wiring->artifact_binding.plist = NULL;
  wiring->artifact_binding.bound = false;
  return report;
}

#if defined(BW_NATIVE_WIRING_TESTING)
bw_lifecycle_report bw_run_native_lifecycle_for_test(bw_native_lifecycle_wiring *wiring) {
  if (wiring == NULL || wiring->artifact_binding.bound) return (bw_lifecycle_report){0};
  bw_lifecycle_report report = bw_run_lifecycle(&wiring->request);
  wiring->artifact_binding.binary = NULL;
  wiring->artifact_binding.plist = NULL;
  wiring->artifact_binding.bound = false;
  return report;
}
#endif
