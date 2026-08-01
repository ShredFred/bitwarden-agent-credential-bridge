# Phase 5h.32 — fixed macOS dscl directory adapter

This phase connects the native account soft-ownership state machine to an exact
`/usr/bin/dscl` argument-array adapter. The test suite injects a fake command
runner; it never invokes `dscl` or changes the host directory service.

## Fixed identity and commands

The adapter accepts only the `_bwagentbridge` account with a UniqueID from 1 to
499, an uppercase UUIDv4 with a valid variant, `/usr/bin/false` as its shell, and
`/var/empty` as its home. It additionally creates fixed `PrimaryGroupID=20`,
`IsHidden=1`, and `RealName=Bitwarden Agent Bridge` properties.

Name, UniqueID, and GeneratedUID collision probes use exact `dscl -search`
argument arrays. Record reads request exactly the four ownership attributes.
Output must be silent on stderr, bounded, printable, structurally exact, and
free of embedded NULs or whitespace inside scalar values.

## Failure and deletion rules

Any failed or noisy create/property command is classified as ambiguous because
the account may be partially present. The adapter never claims rollback or
deletes a partially created record it could not fully verify.

Deletion receives the full expected identity, re-reads the live record, and
requires every tuple field to match immediately before issuing the fixed delete.
The account ownership layer independently verifies before this adapter call and
proves all three namespaces absent afterward. This narrows, but cannot make
`dscl` path deletion transactionally race-free; any live run therefore remains
subject to the controller's explicit approval, isolation, and manual-recovery
rules.

Run the fake-only tests with:

```bash
npm run test:phase5h32
```

No Bitwarden, Keychain, network, Mach, launchd, elevation, or system mutation is
part of this phase.
