# Phase 5h.36 — non-activating system Mach-name presence

The controller must prove its fixed Mach name absent before bootstrap and
present afterward without accidentally activating a demand-only service.
`bootstrap_look_up` is therefore forbidden for presence checks.

## Streaming system-domain collector

The collector executes only:

```text
/bin/launchctl print system
```

It uses a fixed C locale/environment, `/dev/null` stdin, close-on-exec-default,
explicit pipe closure, a private process group, a ten-second timeout, and
kill/reap cleanup. The shared Phase 5h.31 validator rebinds `/bin/launchctl`
through a no-follow descriptor and rejects unsafe ownership, modes, set-id bits,
or extended ACLs.

Stdout is validated and streamed up to 8 MiB; it is never accumulated as one
large result. Any stderr, invalid control byte, overlong line, output overflow,
nonzero exit, timeout, or missing final newline produces `PROBE_ERROR`.

The parser accepts only a complete trimmed endpoint-entry line:

```text
"de.frederikstadler.bitwarden-agent-credential-bridge.helper" = {
```

The same name embedded in a program path, another identifier, a prefix, or a
suffix does not match. This intentionally avoids interpreting an ordinary
helper path or label as a registered Mach endpoint.

`bw_fixed_system_probes` bundles this callback with the audit-bound denial
client so production lifecycle wiring can use one initialized callback context.

## Evidence

Synthetic tests cover exact endpoint grammar and path/prefix/suffix rejection.
A real read-only system-domain scan on this Mac reports the fixed name absent.
No bootstrap lookup, account, daemon, `/Library`, credential, Keychain,
Bitwarden, or network operation occurs.

```bash
npm run test:phase5h36
```

Cursor Composer review prompted endpoint-line parsing instead of bare-token
matching and reuse of the hardened executable validator.
