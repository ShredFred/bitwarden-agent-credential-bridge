# Phase 5h.31 — macOS fixed command runner

This slice supplies the narrow subprocess boundary required by future native
OpenDirectory and `launchctl` adapters. It is infrastructure, not an adapter and
not live installation evidence.

## Security contract

- The executable is an absolute path and `argv[0]` must match it exactly.
- The executable leaf is a root-owned regular file, not a symlink, executable,
  not group/world writable, has no extended ACL, and has no setuid/setgid bit.
  A no-follow descriptor snapshot must match the path snapshot before spawning.
- Execution uses `posix_spawn` directly. There is no shell, PATH lookup, command
  string, ambient environment, or writable stdin.
- The child receives only the fixed `PATH`, `LANG`, and `LC_ALL` environment.
- `POSIX_SPAWN_CLOEXEC_DEFAULT` closes unrelated inherited descriptors. Each
  invocation also receives a fresh process group so failure cleanup can stop
  descendants. The
  runner explicitly wires `/dev/null`, stdout, and stderr and closes the pipe
  endpoints after duplication.
- Arguments, timeout, stdout, and stderr are bounded. A timeout, output flood,
  or I/O failure sends `SIGKILL` and synchronously reaps the child.
- A normal nonzero process exit is returned as captured process status, distinct
  from spawn, timeout, overflow, and I/O failures.

## Test boundary

The native self-test compiles locally and invokes only `/usr/bin/true`,
`/usr/bin/false`, `/usr/bin/printf`, `/bin/sleep`, and `/usr/bin/yes`. It proves
normal capture, exact nonzero status, timeout termination, output-flood
termination, and rejection of relative execution.

Run it with:

```bash
npm run test:phase5h31
```

No account, launchd job, system file, Mach service, credential, network, or
authorization state is read or changed. The later fixed adapters must add their
own exact executable and argument allowlists and repeat identity checks around
every mutation. A live distinct-EUID lifecycle still requires explicit current
operator approval.
