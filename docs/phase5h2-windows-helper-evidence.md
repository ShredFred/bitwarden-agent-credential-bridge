# Phase 5h.2: Windows helper peer evidence

Phase 5h.2 compiles trusted Win32 probe facts into the five value-free booleans
required by the Phase 5h.1 helper protocol. It does no I/O.

The future Windows adapter must independently prove:

- a local named pipe configured to reject remote clients;
- verified client and server process binding;
- successfully inspected caller and helper process tokens;
- unequal SHA-256 digests of the two `TokenUser` SIDs;
- complete effective-access checks over every manifest-bound target;
- no effective caller write right and the required helper write rights.

Restricted tokens and AppContainers are useful defense-in-depth controls but are
not separate writer principals when `TokenUser` is unchanged. The evaluator
therefore forces `different_principal` to false for any equal `TokenUser` digest,
regardless of restricted-token or AppContainer flags.

The evaluator never returns SID digests or any other identity, path, process, or
ACL detail. Missing, extra, accessor-backed, wrongly typed, raw-SID-shaped, or
otherwise malformed evidence fails with the fixed `peer_identity_unverified`
code.

The actual Win32 collector remains live-gated. Its production shape is a local
named-pipe helper running under a dedicated low-privilege principal, with target
DACLs that exclude caller writes. Account/service creation, pipe I/O, token
inspection, AccessCheck calls, ACL mutation, helper launch, inherited-handle
transfer, real user roots, and Bitwarden access are not implemented in 5h.2.

```bash
npm run test:phase5h2
```
