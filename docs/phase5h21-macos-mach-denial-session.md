# Phase 5h.21: macOS Mach audit-trailer denial session

Phase 5h.21 exercises a real cross-process macOS peer-identity path without
installing or loading the production helper. The expected and required outcome
is denial: both processes have the same effective UID, no manifest request is
sent, and no production code or launchd binding is claimed.

## Why raw Mach messages

The current public macOS SDK exposes PID, EUID, and code-requirement controls on
`NSXPCConnection`, but it does not expose the peer's complete `audit_token_t`.
PID and EUID alone cannot bind a process generation. Private
`NSXPCConnection.auditToken` categories and private libxpc getters are therefore
forbidden.

A Mach receive operation can request `MACH_RCV_TRAILER_AUDIT`. The kernel then
attaches the sending process's full audit token to that exact message. The helper
obtains the caller token from the request trailer; the caller obtains the helper
token from the reply trailer. `audit_token_to_pidversion` prevents a recycled PID
from being treated as the same execution.

The production plan now names this transport `macos_mach_message_service`.
Phase 5h.21 uses the separate honest label `macos_mach_message_console`.

## Native denial exchange

The fixed C probe performs one bounded exchange:

1. The helper side allocates one private receive right and registers its send
   right under a cryptographically random ephemeral bootstrap name.
2. A forked caller looks up that ephemeral name. The fixed production Mach
   service name is never registered or queried.
3. The caller sends one fixed-size, non-complex request containing only a random
   non-secret nonce and a send-once reply right.
4. Before the exchange, the child writes its own `TASK_AUDIT_TOKEN` through a
   private pipe created before `fork`. The parent reads it with a bounded wait;
   this value never enters the Mach message or public report.
5. The helper requires the exact message size/ID, no complex bit, no voucher,
   the expected receive port, nonce equality, a send-once reply right, and an
   exact audit trailer. Its trailer PID must equal the PID returned by `fork`;
   EUID must match; the complete request trailer token and pidversion must equal
   the independently received child self token.
6. The helper replies only through that send-once right with the same nonce.
7. The caller requires the exact reply and audit trailer, then compares the
   complete helper audit token with the helper's pre-fork `TASK_AUDIT_TOKEN`.
8. Both sides use bounded send/receive/pipe timeouts. The parent also bounds,
   terminates if necessary, and reaps only its own child before removing port
   rights.

The nonce prevents cross-session confusion but does not establish identity.
Identity comes only from the kernel trailers and independently expected process
relationships.

## Value-free parent contract

The native process emits one exact JSON object. It contains only a transport
kind, SHA-256 digests of canonical `euid:<decimal>` preimages, and booleans. It
contains no audit-token words, PIDs, pidversions, UIDs, port/bootstrap names,
paths, or native errors.

The Node parent hashes its own canonical `euid:<decimal>` value and requires both
native digests to match it in constant time. It also rejects extra fields,
malformed digests, stderr, any failed identity fact, or any claim that the production service,
production code requirement, manifest path, authorization, or install gate was
reached. It recompiles the fixed repo source into a private canonical-temp root
with fixed `/usr/bin/clang` arguments, executes it without arguments, bounds all
time/output, and requires exact cleanup.

## What this proves—and what it does not

This live test proves that public Mach audit trailers can bind both sides of a
real request/reply exchange to specific process generations on this Mac. It also
proves the expected same-EUID denial.

It does not prove a launchd system service, `_bwagentbridge`, the reviewed helper
code requirement, distinct EUIDs, target ACLs, or manifest execution. The next
gate requires an explicitly approved disposable LaunchDaemon lifecycle using the
fixed service name and static helper account. Keychain, Bitwarden, OneCLI,
network access, real credentials, and authorization remain absent.

```bash
npm run test:phase5h21
```
