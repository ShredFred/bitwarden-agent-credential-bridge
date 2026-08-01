# Phase 5h.27: native retained-FD file ownership core

Phase 5h.27 adds the native file-ownership primitive required by the future
approved macOS LaunchDaemon lifecycle executor. It does not contain system
paths, invoke launchctl or OpenDirectory, elevate, or install anything.

`macos-retained-file-ops.c` publishes a fixed-name child only with
`openat(parent_fd, ..., O_CREAT|O_EXCL|O_NOFOLLOW)`. It retains both the caller's
already-open parent descriptor and the new file descriptor, records device and
inode identity, writes and fsyncs the reviewed bytes, applies owner/mode through
the retained file descriptor, fsyncs the parent, and re-verifies:

- regular-file type and single link;
- retained FD versus `fstatat(..., AT_SYMLINK_NOFOLLOW)` path identity;
- device, inode, size, owner, group, and mode; and
- byte-for-byte content through `pread` on the retained descriptor.

Cleanup never reacquires ownership from a pathname. `unlinkat` is attempted only
if the current directory entry still matches the retained file descriptor and
recorded device/inode tuple. If another actor removes and replaces the path, the
operation returns `BW_FILE_AMBIGUOUS` and deliberately leaves the foreign file
untouched for manual review.

The native self-test uses only a process-private `/tmp` fixture root. It proves
exclusive creation, collision preservation, normal cleanup, and refusal to
delete a path-replaced foreign file. The component is reusable by the later
single-process native lifecycle controller so the descriptors remain open from
publication through cleanup.

```bash
npm run test:phase5h27
```

This phase performs no root or system mutation and is not live lifecycle,
collector-trust, authorization, or installation evidence.
