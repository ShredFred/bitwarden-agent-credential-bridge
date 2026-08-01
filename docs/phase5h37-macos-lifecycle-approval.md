# Phase 5h.37 — macOS lifecycle approval boundary

The native lifecycle controller now has a mandatory one-shot approval capability before its first mutation. This phase does not provide an installer and did not execute privileged operations.

## Authority boundary

- A command-line flag, environment variable, manifest, or path can never authorize mutation.
- Production receipt intake requires a non-root real UID, effective UID 0, and a stable root-owned `/usr/bin/sudo` parent. The intended future launcher must invoke a fresh `sudo -k` consent flow.
- The receipt is read exactly once from a connected `AF_UNIX` stream socket whose kernel-reported peer UID equals the real UID. Regular files and surplus bytes are rejected.
- The fixed receipt binds the approving UID, current runner PID, 32-byte nonce, helper SHA-256, plist SHA-256, designated-requirement SHA-256, and a monotonic expiry no more than 120 seconds away.
- The public API exposes no constructible approval object. One fused native entry point re-hashes the current artifact buffers, receives and consumes the socket receipt, and only then calls the lifecycle controller. A mismatch, expiry, or replay returns an all-false report without mutation.

## Current limitation and next gate

This is the receiving/consumption boundary, not yet the user-facing launcher. The next phase must build a signed, fixed-purpose launcher/runner pair that derives all three digests from retained artifact descriptors, creates the socket receipt, invokes `/usr/bin/sudo -k` without a shell, and never exposes a general command executor. Until that exists and receives explicit operator approval, live lifecycle execution remains unavailable.

The fixture issuer is compiled only with `BW_LIFECYCLE_APPROVAL_TESTING`; it is not present in production builds.
