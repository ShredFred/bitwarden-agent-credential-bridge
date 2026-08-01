# Phase 5h.33 — fixed macOS launchctl job adapter

This phase connects the launchd soft-ownership state machine to fixed
`/bin/launchctl` argument arrays. Its mutation tests inject a fake runner and do
not load, start, signal, or remove a real job.

## Fixed command surface

The only accepted target is
`system/de.frederikstadler.bitwarden-agent-credential-bridge.helper`; bootstrap
uses its fixed `/Library/LaunchDaemons/...helper.plist`. The adapter exposes only
`print`, `bootstrap system`, `kickstart`, `kill SIGTERM`, and `bootout` for those
constants. There is no shell, PATH lookup, caller-provided label, plist, signal,
or subcommand.

A mutation counts as successful only when the runner reports a normal zero exit
with empty stdout and stderr. Unknown errors remain ambiguous. The adapter does
not guess `NO_EFFECT` from undocumented or version-variable messages.

## Live identity binding

Bounded `launchctl print` output must contain exactly one matching service
header, program, and username. Process verification additionally requires one
`state = running` value and one canonical bounded PID. Duplicate/conflicting
keys, controls, embedded NULs, noise, truncation, or nonzero exits fail closed.

Each loaded-job read and the checks immediately before stop/bootout also invoke
a mandatory artifact/policy probe. Production wiring must bind that probe to
the controller's retained binary/plist descriptors, their SHA-256 identities,
and the already validated demand-only plist. Only after live fields and bound
artifacts agree does the adapter return the expected complete record.

Mach-service presence and denial are separate mandatory callbacks. Production
wiring must implement them using the bounded system-domain/Mach audit-token
collectors; a test callback is not trusted live evidence.

Cursor Composer review led to unique-key/PID parsing, pre-stop revalidation, and
the explicit artifact/policy probe. A residual race remains between the final
print and launchctl's name-targeted stop/bootout because launchd provides no
public retained job handle; any mismatch or ambiguous cleanup therefore remains
a manual-recovery outcome.

Run the fake mutation tests with:

```bash
npm run test:phase5h33
```

The current Mac additionally passed a read-only `launchctl print` grammar check
against Apple's existing `system/com.apple.syslogd` job. No bridge system state,
credential, Keychain, Bitwarden, or network state was accessed.
