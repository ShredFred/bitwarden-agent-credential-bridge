#include "macos-mach-service-probes.h"

#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <libproc.h>
#include <pwd.h>
#include <servers/bootstrap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CONTEXT_MAGIC UINT32_C(0x42574D50)
#define SERVICE_NAME "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define ACCOUNT_NAME "_bwagentbridge"
#define PROGRAM_PATH "/Library/PrivilegedHelperTools/" SERVICE_NAME
#define REQUEST_ID 0x425711
#define REPLY_ID 0x425712
#define PROTOCOL_VERSION 1u
#define DENIAL_PROBE_KIND 1u
#define NONCE_BYTES 32u
#define TIMEOUT_MS 2000u

typedef struct {
  mach_msg_header_t header;
  uint32_t protocol_version;
  uint32_t request_kind;
  uint8_t nonce[NONCE_BYTES];
} denial_request_t;

typedef struct {
  mach_msg_header_t header;
  uint32_t protocol_version;
  uint32_t request_kind;
  uint32_t authorization_denied;
  uint8_t nonce[NONCE_BYTES];
} denial_reply_t;

typedef struct {
  denial_reply_t reply;
  uint8_t trailer[sizeof(mach_msg_audit_trailer_t) + 8u];
} reply_buffer_t;

static bool exact_identity(const bw_launchd_job_record *identity) {
  return identity != NULL && strcmp(identity->label, SERVICE_NAME) == 0 &&
      strcmp(identity->mach_service, SERVICE_NAME) == 0 &&
      strcmp(identity->program, PROGRAM_PATH) == 0 &&
      strcmp(identity->user_name, ACCOUNT_NAME) == 0 && identity->demand_activation_only;
}

static bool fixed_account_uid(uid_t *uid) {
  if (uid == NULL) return false;
  struct passwd record;
  struct passwd *result = NULL;
  char storage[4096];
  if (getpwnam_r(ACCOUNT_NAME, &record, storage, sizeof(storage), &result) != 0 ||
      result == NULL || result->pw_name == NULL || result->pw_dir == NULL ||
      result->pw_shell == NULL || strcmp(result->pw_name, ACCOUNT_NAME) != 0 ||
      result->pw_uid != 499 || strcmp(result->pw_dir, "/var/empty") != 0 ||
      strcmp(result->pw_shell, "/usr/bin/false") != 0) return false;
  *uid = result->pw_uid;
  return true;
}

static mach_msg_audit_trailer_t *reply_audit_trailer(reply_buffer_t *buffer) {
  mach_msg_header_t *header = &buffer->reply.header;
  if (header->msgh_size != sizeof(denial_reply_t) ||
      (header->msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0) return NULL;
  uintptr_t start = (uintptr_t)header + ((header->msgh_size + 3u) & ~3u);
  uintptr_t limit = (uintptr_t)buffer + sizeof(*buffer);
  if (start < (uintptr_t)buffer || start > limit ||
      sizeof(mach_msg_audit_trailer_t) > limit - start) return NULL;
  mach_msg_audit_trailer_t *trailer = (mach_msg_audit_trailer_t *)start;
  if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
      trailer->msgh_trailer_size != sizeof(mach_msg_audit_trailer_t)) return NULL;
  return trailer;
}

static bool send_request(
    mach_port_t service, mach_port_t reply_port, const uint8_t nonce[NONCE_BYTES]) {
  denial_request_t request = {0};
  request.header.msgh_bits = MACH_MSGH_BITS(
      MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  request.header.msgh_size = sizeof(request);
  request.header.msgh_remote_port = service;
  request.header.msgh_local_port = reply_port;
  request.header.msgh_voucher_port = MACH_PORT_NULL;
  request.header.msgh_id = REQUEST_ID;
  request.protocol_version = PROTOCOL_VERSION;
  request.request_kind = DENIAL_PROBE_KIND;
  memcpy(request.nonce, nonce, NONCE_BYTES);
  return mach_msg(&request.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
      request.header.msgh_size, 0, MACH_PORT_NULL, TIMEOUT_MS, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
}

static bool receive_reply(
    mach_port_t reply_port,
    const uint8_t nonce[NONCE_BYTES],
    pid_t expected_pid,
    uid_t expected_euid) {
  reply_buffer_t buffer;
  memset(&buffer, 0, sizeof(buffer));
  mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TIMEOUT |
      MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
      MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
  mach_msg_return_t received = mach_msg(&buffer.reply.header, options, 0,
      (mach_msg_size_t)sizeof(buffer), reply_port, TIMEOUT_MS, MACH_PORT_NULL);
  mach_msg_audit_trailer_t *trailer =
      received == MACH_MSG_SUCCESS ? reply_audit_trailer(&buffer) : NULL;
  bool valid = trailer != NULL &&
      buffer.reply.header.msgh_size == sizeof(denial_reply_t) &&
      (buffer.reply.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0 &&
      buffer.reply.header.msgh_id == REPLY_ID &&
      buffer.reply.header.msgh_local_port == reply_port &&
      buffer.reply.header.msgh_remote_port == MACH_PORT_NULL &&
      buffer.reply.header.msgh_voucher_port == MACH_PORT_NULL &&
      buffer.reply.protocol_version == PROTOCOL_VERSION &&
      buffer.reply.request_kind == DENIAL_PROBE_KIND &&
      buffer.reply.authorization_denied == 1u &&
      memcmp(buffer.reply.nonce, nonce, NONCE_BYTES) == 0 &&
      audit_token_to_pid(trailer->msgh_audit) == expected_pid &&
      audit_token_to_euid(trailer->msgh_audit) == expected_euid &&
      audit_token_to_pidversion(trailer->msgh_audit) > 0;
  if (received == MACH_MSG_SUCCESS && !valid) mach_msg_destroy(&buffer.reply.header);
  return valid;
}

typedef struct {
  uint64_t start_seconds;
  uint64_t start_microseconds;
  char path[PROC_PIDPATHINFO_MAXSIZE];
} process_snapshot;

static bool snapshot_process(
    pid_t pid, uid_t expected_euid, const char *required_path, process_snapshot *snapshot) {
  if (pid <= 1 || snapshot == NULL) return false;
  struct proc_bsdinfo info;
  memset(&info, 0, sizeof(info));
  memset(snapshot, 0, sizeof(*snapshot));
  int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
  int path_length = proc_pidpath(pid, snapshot->path, sizeof(snapshot->path));
  if (count != (int)sizeof(info) || info.pbi_pid != (uint32_t)pid ||
      info.pbi_uid != expected_euid || info.pbi_start_tvsec == 0 || path_length < 1 ||
      (required_path != NULL && strcmp(snapshot->path, required_path) != 0)) return false;
  snapshot->start_seconds = info.pbi_start_tvsec;
  snapshot->start_microseconds = info.pbi_start_tvusec;
  return true;
}

static bool same_process_snapshot(
    const process_snapshot *before, const process_snapshot *after) {
  return before != NULL && after != NULL && before->start_seconds == after->start_seconds &&
      before->start_microseconds == after->start_microseconds &&
      strcmp(before->path, after->path) == 0;
}

static bool denial_exchange(
    const char *service_name,
    pid_t expected_pid,
    uid_t expected_euid,
    const char *required_path) {
  process_snapshot before;
  if (!snapshot_process(expected_pid, expected_euid, required_path, &before)) return false;
  mach_port_t service = MACH_PORT_NULL;
  if (bootstrap_look_up(bootstrap_port, service_name, &service) != KERN_SUCCESS ||
      service == MACH_PORT_NULL) return false;
  mach_port_t reply_port = MACH_PORT_NULL;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port) != KERN_SUCCESS) {
    (void)mach_port_deallocate(mach_task_self(), service);
    return false;
  }
  uint8_t nonce[NONCE_BYTES];
  arc4random_buf(nonce, sizeof(nonce));
  bool exchanged = send_request(service, reply_port, nonce) &&
      receive_reply(reply_port, nonce, expected_pid, expected_euid);
  process_snapshot after;
  bool result = exchanged && snapshot_process(
      expected_pid, expected_euid, required_path, &after) && same_process_snapshot(&before, &after);
  (void)mach_port_deallocate(mach_task_self(), service);
  (void)mach_port_mod_refs(mach_task_self(), reply_port, MACH_PORT_RIGHT_RECEIVE, -1);
  return result;
}

void bw_init_mach_probe_context(bw_mach_probe_context *context) {
  if (context == NULL) return;
  context->state_magic = CONTEXT_MAGIC;
}

bool bw_fixed_mach_denial_probe(
    void *raw,
    const bw_launchd_job_record *identity,
    pid_t expected_helper_pid) {
  bw_mach_probe_context *context = raw;
  uid_t helper_uid = 0;
  return context != NULL && context->state_magic == CONTEXT_MAGIC && exact_identity(identity) &&
      expected_helper_pid > 1 && fixed_account_uid(&helper_uid) && helper_uid != geteuid() &&
      denial_exchange(SERVICE_NAME, expected_helper_pid, helper_uid, PROGRAM_PATH);
}

#if defined(BW_MACH_PROBE_TESTING)
bool bw_test_mach_denial_exchange(
    const char *service_name, pid_t expected_helper_pid, uid_t expected_helper_euid) {
  static const char prefix[] = "de.frederikstadler.bw-mach-test.";
  return service_name != NULL && strncmp(service_name, prefix, sizeof(prefix) - 1) == 0 &&
      expected_helper_pid > 1 && denial_exchange(
          service_name, expected_helper_pid, expected_helper_euid, NULL);
}
#endif
