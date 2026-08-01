#ifndef BW_AGENT_MACOS_LIFECYCLE_APPROVAL_H
#define BW_AGENT_MACOS_LIFECYCLE_APPROVAL_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define BW_APPROVAL_DIGEST_BYTES 32
#define BW_APPROVAL_NONCE_BYTES 32
#define BW_APPROVAL_MAX_LIFETIME_SECONDS 120

typedef struct {
  unsigned char binary_sha256[BW_APPROVAL_DIGEST_BYTES];
  unsigned char plist_sha256[BW_APPROVAL_DIGEST_BYTES];
  unsigned char requirement_sha256[BW_APPROVAL_DIGEST_BYTES];
} bw_lifecycle_approval_bindings;

/*
 * Consume one exact, short-lived receipt from a connected AF_UNIX socket.
 * Production additionally requires a non-root real UID, root effective UID,
 * and either a stable root-owned /usr/bin/sudo parent or the exact fixed
 * root-owned provisioner with /usr/bin/sudo as its stable parent. The socket
 * peer must be the real UID and the receipt must name this process. No
 * argv/env/path approval input is accepted.
 */
bool bw_receive_and_consume_lifecycle_approval(
    int connected_socket_fd,
    const bw_lifecycle_approval_bindings *expected);

/* Answer exactly one runner-generated challenge as the non-root launcher. */
bool bw_answer_lifecycle_approval_challenge(
    int connected_socket_fd,
    const bw_lifecycle_approval_bindings *approved,
    pid_t *approved_runner_pid);

#if defined(BW_LIFECYCLE_APPROVAL_TESTING)
void bw_set_lifecycle_approval_nonce_for_test(unsigned char nonce_value);
#endif

#endif
