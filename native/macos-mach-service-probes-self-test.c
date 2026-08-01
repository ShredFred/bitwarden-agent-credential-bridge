#include "macos-mach-service-probes.h"

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUEST_ID 0x425711
#define REPLY_ID 0x425712
#define NONCE_BYTES 32u

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
  mach_msg_max_trailer_t trailer;
} request_buffer_t;

static bool serve_one(mach_port_t port) {
  request_buffer_t buffer;
  memset(&buffer, 0, sizeof(buffer));
  denial_request_t *request = &buffer.request;
  if (mach_msg(&request->header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
      sizeof(buffer), port, 2000, MACH_PORT_NULL) != MACH_MSG_SUCCESS ||
      request->header.msgh_size != sizeof(*request) || request->header.msgh_id != REQUEST_ID ||
      request->header.msgh_remote_port == MACH_PORT_NULL || request->protocol_version != 1u ||
      request->request_kind != 1u) return false;
  denial_reply_t reply = {0};
  reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  reply.header.msgh_size = sizeof(reply);
  reply.header.msgh_remote_port = request->header.msgh_remote_port;
  reply.header.msgh_id = REPLY_ID;
  reply.protocol_version = 1u;
  reply.request_kind = 1u;
  reply.authorization_denied = 1u;
  memcpy(reply.nonce, request->nonce, sizeof(reply.nonce));
  return mach_msg(&reply.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
      sizeof(reply), 0, MACH_PORT_NULL, 2000, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  mach_port_t port = MACH_PORT_NULL;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS ||
      mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
    return 1;
  }
  char name[96];
  (void)snprintf(name, sizeof(name), "de.frederikstadler.bw-mach-test.%d", getpid());
  if (bootstrap_register(bootstrap_port, name, port) != KERN_SUCCESS) return 1;
  pid_t child = fork();
  if (child < 0) return 1;
  if (child == 0) {
    bool valid = bw_test_mach_denial_exchange(name, getppid(), geteuid());
    _exit(valid ? 0 : 2);
  }
  bool served = serve_one(port);
  int status = 0;
  bool child_ok = waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  (void)mach_port_deallocate(mach_task_self(), port);
  (void)mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);

  mach_port_t wrong_port = MACH_PORT_NULL;
  bool wrong_pid_rejected = false;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wrong_port) == KERN_SUCCESS &&
      mach_port_insert_right(mach_task_self(), wrong_port, wrong_port,
          MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS) {
    char wrong_name[96];
    (void)snprintf(wrong_name, sizeof(wrong_name),
        "de.frederikstadler.bw-mach-test.%d.wrong", getpid());
    if (bootstrap_register(bootstrap_port, wrong_name, wrong_port) == KERN_SUCCESS) {
      pid_t wrong_child = fork();
      if (wrong_child == 0) {
        bool incorrectly_valid = bw_test_mach_denial_exchange(
            wrong_name, getpid(), geteuid());
        _exit(incorrectly_valid ? 3 : 0);
      }
      if (wrong_child > 0) {
        bool wrong_served = serve_one(wrong_port);
        int wrong_status = 0;
        wrong_pid_rejected = wrong_served && waitpid(wrong_child, &wrong_status, 0) == wrong_child &&
            WIFEXITED(wrong_status) && WEXITSTATUS(wrong_status) == 0;
      }
    }
    (void)mach_port_deallocate(mach_task_self(), wrong_port);
    (void)mach_port_mod_refs(mach_task_self(), wrong_port, MACH_PORT_RIGHT_RECEIVE, -1);
  }
  bool all = served && child_ok && wrong_pid_rejected;
  (void)printf(
      "{\"schema_version\":1,\"request_served\":%s,\"client_verified\":%s,"
      "\"audit_bound_denial\":%s,\"wrong_pid_rejected\":%s}\n",
      served ? "true" : "false", child_ok ? "true" : "false", all ? "true" : "false",
      wrong_pid_rejected ? "true" : "false");
  return all ? 0 : 1;
}
