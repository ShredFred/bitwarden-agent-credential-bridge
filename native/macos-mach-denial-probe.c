#include <CommonCrypto/CommonDigest.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/task_info.h>
#include <poll.h>
#include <signal.h>
#include <servers/bootstrap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUEST_ID 0x425701
#define REPLY_ID 0x425702
#define NONCE_BYTES 32
#define TIMEOUT_MS 2000

typedef struct {
  mach_msg_header_t header;
  uint8_t nonce[NONCE_BYTES];
} denial_message_t;

typedef struct {
  denial_message_t message;
  uint8_t trailer[sizeof(mach_msg_audit_trailer_t) + 8];
} receive_buffer_t;

static bool self_audit_token(audit_token_t *token) {
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  return task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)token, &count) == KERN_SUCCESS &&
    count == TASK_AUDIT_TOKEN_COUNT;
}

static mach_msg_audit_trailer_t *audit_trailer(receive_buffer_t *buffer) {
  mach_msg_header_t *header = &buffer->message.header;
  if (header->msgh_size != sizeof(denial_message_t) ||
      (header->msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0) return NULL;
  uintptr_t start = (uintptr_t)header + ((header->msgh_size + 3u) & ~3u);
  mach_msg_audit_trailer_t *trailer = (mach_msg_audit_trailer_t *)start;
  if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
      trailer->msgh_trailer_size != sizeof(mach_msg_audit_trailer_t)) return NULL;
  return trailer;
}

static bool receive_one(mach_port_t port, mach_msg_id_t expected_id,
                        const uint8_t nonce[NONCE_BYTES], receive_buffer_t *buffer) {
  memset(buffer, 0, sizeof(*buffer));
  mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TIMEOUT |
    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
  mach_msg_return_t result = mach_msg(&buffer->message.header, options, 0,
    (mach_msg_size_t)sizeof(*buffer), port, TIMEOUT_MS, MACH_PORT_NULL);
  return result == MACH_MSG_SUCCESS && buffer->message.header.msgh_id == expected_id &&
    buffer->message.header.msgh_local_port == port &&
    buffer->message.header.msgh_voucher_port == MACH_PORT_NULL &&
    audit_trailer(buffer) != NULL &&
    memcmp(buffer->message.nonce, nonce, NONCE_BYTES) == 0;
}

static bool send_one(mach_port_t remote, mach_port_t local,
                     mach_msg_type_name_t remote_disposition,
                     mach_msg_type_name_t local_disposition, mach_msg_id_t id,
                     const uint8_t nonce[NONCE_BYTES]) {
  denial_message_t message = {0};
  message.header.msgh_bits = MACH_MSGH_BITS(remote_disposition, local_disposition);
  message.header.msgh_size = sizeof(message);
  message.header.msgh_remote_port = remote;
  message.header.msgh_local_port = local;
  message.header.msgh_id = id;
  memcpy(message.nonce, nonce, NONCE_BYTES);
  return mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
    message.header.msgh_size, 0, MACH_PORT_NULL, TIMEOUT_MS, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
}

static bool hash_euid(uid_t euid, char output[CC_SHA256_DIGEST_LENGTH * 2 + 1]) {
  char preimage[32];
  int length = snprintf(preimage, sizeof(preimage), "euid:%u", euid);
  if (length < 6 || (size_t)length >= sizeof(preimage)) return false;
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  if (CC_SHA256(preimage, (CC_LONG)length, digest) == NULL) return false;
  static const char hex[] = "0123456789abcdef";
  for (size_t index = 0; index < sizeof(digest); index++) {
    output[index * 2] = hex[digest[index] >> 4];
    output[index * 2 + 1] = hex[digest[index] & 0x0f];
  }
  output[CC_SHA256_DIGEST_LENGTH * 2] = '\0';
  return true;
}

static bool write_token(int fd, const audit_token_t *token) {
  const uint8_t *bytes = (const uint8_t *)token;
  size_t offset = 0;
  while (offset < sizeof(*token)) {
    ssize_t count = write(fd, bytes + offset, sizeof(*token) - offset);
    if (count <= 0) return false;
    offset += (size_t)count;
  }
  return true;
}

static bool read_token(int fd, audit_token_t *token) {
  struct pollfd descriptor = {.fd = fd, .events = POLLIN};
  if (poll(&descriptor, 1, TIMEOUT_MS) != 1 || (descriptor.revents & POLLIN) == 0) return false;
  return read(fd, token, sizeof(*token)) == (ssize_t)sizeof(*token);
}

static bool wait_for_child(pid_t child, int *status) {
  for (int attempt = 0; attempt < 300; attempt++) {
    pid_t result = waitpid(child, status, WNOHANG);
    if (result == child) return true;
    if (result < 0) return false;
    (void)poll(NULL, 0, 10);
  }
  (void)kill(child, SIGKILL);
  (void)waitpid(child, status, 0);
  return false;
}

static int run_client(const char *service_name, const uint8_t nonce[NONCE_BYTES],
                      audit_token_t expected_helper) {
  mach_port_t service_port = MACH_PORT_NULL;
  if (bootstrap_look_up(bootstrap_port, service_name, &service_port) != KERN_SUCCESS ||
      service_port == MACH_PORT_NULL) return 19;
  mach_port_t reply_port = MACH_PORT_NULL;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port) != KERN_SUCCESS) return 20;
  bool sent = send_one(service_port, reply_port, MACH_MSG_TYPE_COPY_SEND,
    MACH_MSG_TYPE_MAKE_SEND_ONCE, REQUEST_ID, nonce);
  receive_buffer_t reply = {0};
  bool received = sent && receive_one(reply_port, REPLY_ID, nonce, &reply);
  mach_msg_audit_trailer_t *trailer = received ? audit_trailer(&reply) : NULL;
  bool helper_bound = trailer != NULL &&
    memcmp(&trailer->msgh_audit, &expected_helper, sizeof(expected_helper)) == 0 &&
    audit_token_to_pid(trailer->msgh_audit) == getppid() &&
    audit_token_to_euid(trailer->msgh_audit) == geteuid() &&
    audit_token_to_pidversion(trailer->msgh_audit) == audit_token_to_pidversion(expected_helper);
  (void)mach_port_deallocate(mach_task_self(), service_port);
  (void)mach_port_mod_refs(mach_task_self(), reply_port, MACH_PORT_RIGHT_RECEIVE, -1);
  return helper_bound ? 0 : 21;
}

int main(void) {
  audit_token_t helper_token = INVALID_AUDIT_TOKEN_VALUE;
  if (!self_audit_token(&helper_token)) return 10;
  mach_port_t service_port = MACH_PORT_NULL;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &service_port) != KERN_SUCCESS ||
      mach_port_insert_right(mach_task_self(), service_port, service_port,
        MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return 11;

  uint8_t nonce[NONCE_BYTES];
  arc4random_buf(nonce, sizeof(nonce));
  char service_name[96];
  int service_name_length = snprintf(service_name, sizeof(service_name),
    "de.frederikstadler.bw-agent-console.%02x%02x%02x%02x%02x%02x%02x%02x",
    nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7]);
  if (service_name_length < 1 || (size_t)service_name_length >= sizeof(service_name) ||
      bootstrap_register(bootstrap_port, service_name, service_port) != KERN_SUCCESS) return 12;
  int token_pipe[2];
  if (pipe(token_pipe) != 0) return 13;
  pid_t child = fork();
  if (child < 0) {
    (void)close(token_pipe[0]);
    (void)close(token_pipe[1]);
    return 13;
  }
  if (child == 0) {
    (void)close(token_pipe[0]);
    audit_token_t caller_token = INVALID_AUDIT_TOKEN_VALUE;
    bool token_sent = self_audit_token(&caller_token) && write_token(token_pipe[1], &caller_token);
    (void)close(token_pipe[1]);
    _exit(token_sent ? run_client(service_name, nonce, helper_token) : 22);
  }
  (void)close(token_pipe[1]);
  audit_token_t expected_caller = INVALID_AUDIT_TOKEN_VALUE;
  bool caller_token_received = read_token(token_pipe[0], &expected_caller);
  (void)close(token_pipe[0]);

  receive_buffer_t request = {0};
  bool received = receive_one(service_port, REQUEST_ID, nonce, &request);
  mach_msg_audit_trailer_t *trailer = received ? audit_trailer(&request) : NULL;
  bool caller_bound = caller_token_received && trailer != NULL &&
    request.message.header.msgh_remote_port != MACH_PORT_NULL &&
    MACH_MSGH_BITS_REMOTE(request.message.header.msgh_bits) == MACH_MSG_TYPE_MOVE_SEND_ONCE &&
    memcmp(&trailer->msgh_audit, &expected_caller, sizeof(expected_caller)) == 0 &&
    audit_token_to_pid(trailer->msgh_audit) == child &&
    audit_token_to_euid(trailer->msgh_audit) == geteuid() &&
    audit_token_to_pidversion(trailer->msgh_audit) == audit_token_to_pidversion(expected_caller) &&
    audit_token_to_pidversion(expected_caller) > 0;
  bool replied = caller_bound && send_one(request.message.header.msgh_remote_port,
    MACH_PORT_NULL, MACH_MSG_TYPE_MOVE_SEND_ONCE, 0, REPLY_ID, nonce);

  int status = 0;
  bool child_reaped = wait_for_child(child, &status);
  bool child_ok = child_reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  char caller_digest[CC_SHA256_DIGEST_LENGTH * 2 + 1];
  char helper_digest[CC_SHA256_DIGEST_LENGTH * 2 + 1];
  bool digests_ok = hash_euid(audit_token_to_euid(trailer != NULL ? trailer->msgh_audit : helper_token),
      caller_digest) && hash_euid(audit_token_to_euid(helper_token), helper_digest);
  bool exchange = received && caller_bound && replied && child_ok && digests_ok;
  (void)mach_port_deallocate(mach_task_self(), service_port);
  (void)mach_port_mod_refs(mach_task_self(), service_port, MACH_PORT_RIGHT_RECEIVE, -1);
  if (!received) return 14;
  if (!caller_bound) return 15;
  if (!replied) return 16;
  if (!child_ok) return 17;
  if (!digests_ok || !exchange) return 18;

  printf("{\"schema_version\":1,\"transport_kind\":\"macos_mach_message_console\","
    "\"mach_service_bound\":false,\"launchd_system_service_verified\":false,"
    "\"mach_peer_exchange_verified\":true,\"request_audit_trailer_verified\":true,"
    "\"request_sender_matches_spawned_caller\":true,\"request_sender_pid_verified\":true,"
    "\"request_sender_pidversion_verified\":true,\"reply_audit_trailer_verified\":true,"
    "\"reply_sender_matches_expected_helper\":true,\"reply_sender_pid_verified\":true,"
    "\"reply_sender_pidversion_verified\":true,\"caller_euid_verified\":true,"
    "\"helper_euid_verified\":true,\"caller_euid_sha256\":\"%s\","
    "\"helper_euid_sha256\":\"%s\",\"same_euid\":true,"
    "\"helper_code_requirement_satisfied\":false,\"manifest_request_sent\":false,"
    "\"manifest_executor_absent\":true,\"authorization_denied\":true,"
    "\"install_gate_eligible\":false}\n", caller_digest, helper_digest);
  return 0;
}
