# Phase 4c: OneCLI chained-proxy credential boundary

Phase 4c adds the first bridge path shaped around the pinned OneCLI gateway
contract rather than a fake target credential. The caller connects to a
foreground loopback proxy. The bridge holds one explicit runtime OneCLI agent
access token and sends its exact `Proxy-Authorization: Basic base64(token:)`
form only to the policy-pinned loopback OneCLI gateway. It never retrieves,
injects, logs, persists, or returns a target-service credential.

The exact version-4 policy pins the loopback bind and gateway, one lowercase
ASCII DNS target, port 443, and one fixture-only HTTP method/path. It rejects
IP literals, IDNA, wildcards, trailing dots, non-443 ports, literal tokens,
unknown fields, caller authentication/proxy headers, duplicate headers,
redirects, query/fragment syntax, and non-pinned authorities.

For plain HTTP absolute-form requests the bridge can enforce method and path,
buffer bounded request/response bodies, and prevent raw or encoded agent-token
reflection. For production-shaped HTTPS `CONNECT`, it can enforce only the
exact destination authority and bounded tunnel lifetime/bytes/concurrency.
After the CONNECT handshake, TLS records are opaque: the bridge cannot verify
method, path, headers, redirects, or response content. Those controls and
target-secret injection belong to the trusted OneCLI gateway. A malicious or
compromised gateway could disclose the agent token inside the opaque tunnel;
this local bridge does not claim protection from that upstream trust failure.

The broker rebuilds the gateway request headers, strips caller
`Proxy-Authorization`, `Authorization`, cookies, hop-by-hop, connection-named,
forwarding, API-key, upgrade, and duplicate headers, and adds one fixed gateway
authorization value. Request/response bodies, handshake time, idle time,
connections, headers, per-direction tunnel bytes, and absolute tunnel lifetime
are bounded. Errors and logs are value-free or redacted across the explicitly
tested raw, Basic-payload, URL-encoded, Base64, Base64url, and hexadecimal
variants. This is a bounded known-encoding check, not a claim to recognize every
possible reversible transform.

Tests use only generated sentinels, an ephemeral fake loopback gateway, and a
TLS-free opaque echo tunnel. This phase does not start Docker or OneCLI, pair
Bitwarden, install a CA, read a vault, create a real agent token, or prove
OneCLI/Bitwarden behavior. Run `npm run test:phase4c`.

The runtime entrypoint `scripts/run-onecli-proxy.mjs` accepts no arguments and
reads no environment values or files. A trusted parent supplies exact framed
token and policy bytes on inherited IPC descriptors 3 and 4. Descriptor 5 is a
parent lease: EOF, data, or error closes the broker, preventing an orphaned
listener. All three descriptors must be distinct FIFO/pipe endpoints or local
socketpair endpoints; Node implements extra child-process pipes as Unix
socketpairs on macOS. On Windows, anonymous `stdio: "pipe"` channels report
the FIFO type bit (`0x1000`) while `Stats.isFIFO()` remains false, so the
runtime accepts that exact mode class only and still rejects regular files,
character devices (including `NUL`), directories, and links. Duplicate
descriptors, malformed/oversized/trailing frames, invalid encodings, and
timeouts fail silently with a nonzero exit. Successful stdout contains only one
value-free ready record; shutdown failures remain silent and nonzero.

`src/onecli-proxy-runtime-supervisor.js` is the same-user parent boundary for
that entrypoint. Callers supply only an already validated version-4 policy and
an in-memory token; they cannot select a program, argument, working directory,
environment, or file descriptor. The supervisor starts the fixed repo-owned
entrypoint with a minimal environment, writes the two bounded frames, retains
the lease, accepts exactly one bounded loopback ready record, and treats any
stderr or later stdout as a runtime violation. Closing the frozen handle ends
the lease and escalates through bounded termination if the child does not exit.

This supervisor is not yet a production package identity. A same-user process
can modify repo-owned JavaScript before launch. The macOS integration must bind
the supervisor, entrypoint, imports, and Node runtime to reviewed package bytes
before a privileged helper may start it. The existing lifecycle provisioner
remains denial-only and does not receive or process OneCLI agent tokens.
