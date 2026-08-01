#include "macos-lifecycle-approval.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static bw_lifecycle_approval_bindings bindings(unsigned char value) {
  bw_lifecycle_approval_bindings result;
  memset(&result, value, sizeof(result));
  return result;
}

static bool receipt(
    const bw_lifecycle_approval_bindings *issued,
    const bw_lifecycle_approval_bindings *expected,
    unsigned char nonce) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return false;
  bw_set_lifecycle_approval_nonce_for_test(nonce);
  pid_t child = fork();
  if (child < 0) return false;
  if (child == 0) {
    (void)close(sockets[1]);
    bool answered = bw_answer_lifecycle_approval_challenge(sockets[0], issued, NULL);
    (void)close(sockets[0]);
    _exit(answered ? 0 : 1);
  }
  (void)close(sockets[0]);
  bool accepted = bw_receive_and_consume_lifecycle_approval(sockets[1], expected);
  bool closed = close(sockets[1]) == 0;
  int status = 0;
  bool reaped = waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  return accepted && closed && reaped;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--self-test") != 0) return 64;
  bw_lifecycle_approval_bindings expected = bindings(0x11);
  bw_lifecycle_approval_bindings wrong = bindings(0x22);
  bool mismatch_rejected = !receipt(&expected, &wrong, 0xA1);
  bool exact_consumed = receipt(&expected, &expected, 0xA2);
  bool replay_rejected = exact_consumed && !receipt(&expected, &expected, 0xA2);
  bool all = mismatch_rejected && exact_consumed && replay_rejected;
  (void)printf(
      "{\"schema_version\":1,\"binding_mismatch_rejected\":%s,"
      "\"one_shot_consumed\":%s,\"replay_rejected\":%s}\n",
      mismatch_rejected ? "true" : "false", exact_consumed ? "true" : "false",
      replay_rejected ? "true" : "false");
  return all ? 0 : 1;
}
