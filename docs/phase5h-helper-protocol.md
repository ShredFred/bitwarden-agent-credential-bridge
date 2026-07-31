# Phase 5h.1: separate-identity helper protocol

Phase 5g proves transactional apply and rollback semantics inside a marked
temporary workspace. It does not stop another process running as the same OS
user from racing those filesystem operations. Phase 5h introduces the missing
writer boundary incrementally; 5h.1 implements only its platform-neutral wire
contract.

The caller sends one canonical UTF-8 JSON request of at most 64 KiB. It binds:

- an opaque request id;
- the disposable workspace platform, absolute root, and marker nonce;
- the complete byte-exact confirmed apply manifest;
- launcher SHA-256 and byte length;
- the fixed future transport `inherited_readonly_handle`.

Launcher content is deliberately absent from JSON. A later OS adapter must pass
it through a read-only inherited handle and the helper must independently hash
that handle before use.

Authorization accepts only value-free platform evidence proving all five facts:
local transport, verified peer identity, a different writer principal, caller
write denial, and helper write permission. Same-principal execution is an
explicit failure, not a degraded mode. Responses contain a fixed code, request
id, action count, and rollback state only; they contain no paths, identities, OS
errors, or exception text.

5h.1 performs no I/O. Windows named-pipe/token handling, macOS XPC/audit-token or
sandbox handling, Linux Unix-socket peer credentials/user namespaces, inherited
handle transfer, helper launch, and real execution remain unimplemented. Real
user roots, persistent services, Bitwarden, OneCLI, network access, and real
credentials remain outside the gate.

```bash
npm run test:phase5h
```
