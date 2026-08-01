#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <pwd.h>
#include <servers/bootstrap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERVICE_NAME "de.frederikstadler.bitwarden-agent-credential-bridge.helper"
#define ACCOUNT_NAME "_bwagentbridge"
#define REQUEST_ID 0x425711
#define REPLY_ID 0x425712
#define PROTOCOL_VERSION 1u
#define DENIAL_PROBE_KIND 1u
#define NONCE_BYTES 32u
#define RECEIVE_TIMEOUT_MS 5000u
#define SEND_TIMEOUT_MS 2000u

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
  denial_request_t request;
  uint8_t trailer[sizeof(mach_msg_audit_trailer_t) + 8u];
} receive_buffer_t;

static mach_msg_audit_trailer_t *audit_trailer(receive_buffer_t *buffer) {
  mach_msg_header_t *header = &buffer->request.header;
  if (header->msgh_size != sizeof(denial_request_t) ||
      (header->msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0) return NULL;
  uintptr_t start = (uintptr_t)header + ((header->msgh_size + 3u) & ~3u);
  mach_msg_audit_trailer_t *trailer = (mach_msg_audit_trailer_t *)start;
  if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
      trailer->msgh_trailer_size != sizeof(mach_msg_audit_trailer_t)) return NULL;
  return trailer;
}

static bool nonce_nonzero(const uint8_t nonce[NONCE_BYTES]) {
  uint8_t combined = 0;
  for (size_t index = 0; index < NONCE_BYTES; index++) combined |= nonce[index];
  return combined != 0;
}

static bool receive_request(mach_port_t service_port, receive_buffer_t *buffer) {
  memset(buffer, 0, sizeof(*buffer));
  mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TIMEOUT |
    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
  mach_msg_return_t result = mach_msg(&buffer->request.header, options, 0,
    (mach_msg_size_t)sizeof(*buffer), service_port, RECEIVE_TIMEOUT_MS, MACH_PORT_NULL);
  if (result != MACH_MSG_SUCCESS) return false;
  mach_msg_audit_trailer_t *trailer = audit_trailer(buffer);
  bool valid = buffer->request.header.msgh_id == REQUEST_ID &&
    buffer->request.header.msgh_local_port == service_port &&
    buffer->request.header.msgh_remote_port != MACH_PORT_NULL &&
    buffer->request.header.msgh_voucher_port == MACH_PORT_NULL &&
    MACH_MSGH_BITS_REMOTE(buffer->request.header.msgh_bits) == MACH_MSG_TYPE_MOVE_SEND_ONCE &&
    buffer->request.protocol_version == PROTOCOL_VERSION &&
    buffer->request.request_kind == DENIAL_PROBE_KIND &&
    nonce_nonzero(buffer->request.nonce) &&
    trailer != NULL && audit_token_to_pid(trailer->msgh_audit) > 0 &&
    audit_token_to_pidversion(trailer->msgh_audit) > 0;
  if (!valid) mach_msg_destroy(&buffer->request.header);
  return valid;
}

static bool send_denial(receive_buffer_t *buffer) {
  denial_reply_t reply = {0};
  reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  reply.header.msgh_size = sizeof(reply);
  reply.header.msgh_remote_port = buffer->request.header.msgh_remote_port;
  reply.header.msgh_local_port = MACH_PORT_NULL;
  reply.header.msgh_voucher_port = MACH_PORT_NULL;
  reply.header.msgh_id = REPLY_ID;
  reply.protocol_version = PROTOCOL_VERSION;
  reply.request_kind = DENIAL_PROBE_KIND;
  reply.authorization_denied = 1u;
  memcpy(reply.nonce, buffer->request.nonce, NONCE_BYTES);
  mach_msg_return_t result = mach_msg(&reply.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
    reply.header.msgh_size, 0, MACH_PORT_NULL, SEND_TIMEOUT_MS, MACH_PORT_NULL);
  if (result != MACH_MSG_SUCCESS) mach_msg_destroy(&reply.header);
  return result == MACH_MSG_SUCCESS;
}

static bool fixed_account_identity(void) {
  struct passwd *account = getpwuid(geteuid());
  if (account == NULL || account->pw_name == NULL || account->pw_dir == NULL ||
      account->pw_shell == NULL || account->pw_uid == 0 || account->pw_uid != geteuid() ||
      strcmp(account->pw_name, ACCOUNT_NAME) != 0 ||
      strcmp(account->pw_dir, "/var/empty") != 0) return false;
  return strcmp(account->pw_shell, "/usr/bin/false") == 0 ||
    strcmp(account->pw_shell, "/usr/bin/nologin") == 0 ||
    strcmp(account->pw_shell, "/sbin/nologin") == 0;
}

static int run_launchd_service(void) {
  if (!fixed_account_identity()) return 3;
  mach_port_t service_port = MACH_PORT_NULL;
  if (bootstrap_check_in(bootstrap_port, SERVICE_NAME, &service_port) != KERN_SUCCESS ||
      service_port == MACH_PORT_NULL) return 4;
  receive_buffer_t buffer = {0};
  if (!receive_request(service_port, &buffer)) return 5;
  return send_denial(&buffer) ? 0 : 6;
}

static int run_self_test(void) {
  int count = printf(
    "{\"schema_version\":1,\"platform_darwin\":true,"
    "\"fixed_account_self_check_compiled\":true,\"fixed_mach_service_compiled\":true,"
    "\"launchd_checkin_entrypoint_compiled\":true,"
    "\"audit_trailer_request_verification_compiled\":true,"
    "\"send_once_denial_reply_compiled\":true,\"bounded_messages_compiled\":true,"
    "\"launchd_lifecycle_live_verified\":false,\"distinct_euid_live_verified\":false,"
    "\"helper_code_requirement_live_verified\":false,\"manifest_executor_absent\":true,"
    "\"network_stack_absent\":true,\"keychain_client_absent\":true,"
    "\"vault_client_absent\":true,\"install_gate_eligible\":false}\n");
  return count > 0 ? 0 : 7;
}

int main(int argc, char *argv[]) {
  if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return run_self_test();
  if (argc != 1) return 2;
  return run_launchd_service();
}
