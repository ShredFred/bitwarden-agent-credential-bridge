# Phase 5h.38 — fixed macOS sudo lifecycle launcher

This phase adds the executable approval transport needed by the future privileged lifecycle runner. It does not install that runner and did not invoke `sudo` or mutate macOS system state.

## Full-duplex approval

The elevated runner creates a fresh 32-byte `arc4random_buf` challenge after `sudo` starts it. The challenge binds the runner PID and has a compile-time-locked binary layout. The non-root launcher reads that challenge over the inherited `AF_UNIX` socket and returns a short-lived receipt containing the same PID and nonce plus the helper, plist, and designated-requirement SHA-256 bindings. The runner rejects mismatches, extra bytes, expiry, replay, wrong peer UID, wrong socket family, or transport timeouts.

This removes the need for the launcher to predict or scrape the post-`sudo` runner PID. The launcher may wait up to 120 seconds for the visible password/consent interaction; once the runner challenge exists, the receipt exchange is limited to five seconds.

## Fixed launcher contract

The production launcher has one invocation only:

```text
/usr/bin/sudo -k -- /Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-runner --approved-denial-lifecycle
```

Both executables must pass the existing root-owned, no-writable-bits, no-setid, no-extended-ACL, path/FD-identity validator before spawn. The launcher uses no shell or PATH lookup, provides a fixed minimal environment, places only the approval socket on stdin, closes unrelated descriptors, isolates the child process group, bounds output, kills timeouts, and accepts only one exact value-free success record.

Production also fails before spawn when no controlling `/dev/tty` exists, so `sudo` cannot mistake the approval socket on stdin for a password source. Approval exchange runs on a dedicated thread while the parent continuously drains bounded stdout/stderr, preventing prompt errors from filling a pipe. Socket writes use `MSG_NOSIGNAL`, the sudo-parent identity is checked again immediately before receipt acceptance, and the recent-nonce cache is a bounded ring rather than a permanent 64-run lockout. A native exec invariant proves that the `dup2`-created stdin descriptor has `FD_CLOEXEC` cleared before the runner starts.

The launch has a 130-second outer child deadline, covering the 120-second consent window and a bounded execution margin. Phase 5h.38 originally paired the recorded runner PID with a fresh `libproc` path/start-time snapshot before termination. Phase 5h.41 removed direct path execution and now terminates and reaps the isolated sudo process group, while the provisioner independently bounds, kills, and reaps its exact fork child before retained-inode cleanup. This covers `/dev/fd` execution without risking a PID-reuse kill of an unrelated process.

The command-line mode only selects the runner's fixed behavior; it is not authorization. Mutation remains gated by the socket challenge/receipt inside the runner.

## Remaining gate

The fixed root-owned runner still needs a reviewed build/provisioning path and must wire the lifecycle package, production probes, and controller into its only approved mode. Until that runner exists and the operator explicitly approves a live test, the production launcher is not called.

## Current composition note

Phase 5h.41 supersedes the direct-runner sudo target described above. The current launcher requires the runner path to be absent and invokes only the fixed, root-owned, package-digest-matched lifecycle provisioner. That provisioner publishes the runner exclusively, executes it through a retained descriptor, bounds/reaps it, and removes it by inode identity. The original Phase 5h.38 duplex approval and exact-output transport remain in use.
