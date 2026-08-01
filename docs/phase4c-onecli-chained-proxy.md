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
connections, headers, and per-direction tunnel bytes are bounded. Errors and
logs are value-free or redacted across raw, Basic-payload, URL-encoded, and
base64url variants.

Tests use only generated sentinels, an ephemeral fake loopback gateway, and a
TLS-free opaque echo tunnel. This phase does not start Docker or OneCLI, pair
Bitwarden, install a CA, read a vault, create a real agent token, or prove
OneCLI/Bitwarden behavior. Run `npm run test:phase4c`.
