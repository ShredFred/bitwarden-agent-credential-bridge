# Phase 5h.43: fail-closed macOS distribution readiness

Phase 5h.43 performs one read-only Apple trust check on the exact branded Phase
5h.42 component-package bytes. It copies them into a private `0700` temporary
root, binds the copy by inode metadata, SHA-256, length, and content, and invokes
only fixed `/usr/sbin/pkgutil --check-signature`. The snapshot is rechecked
afterward and removed exactly. Because `pkgutil` accepts a path rather than a
retained descriptor, this is a bounded before/after snapshot check; it does not
claim to defeat a malicious concurrent process already running as the same UID.

The parser accepts only the characterized unsigned response or a complete
Developer ID Installer response with a trusted timestamp, three-certificate
Apple chain, and SHA-256 fingerprints. It returns booleans; certificate names,
paths, tool output, and diagnostics are not exposed. A valid `pkgutil` result is
necessary but deliberately insufficient for production readiness.

No production certificate fingerprint has been operator-approved and pinned.
Consequently `certificate_pin_configured`, `certificate_pin_matches`,
`installer_signature_verified`, `notarization_verified`, and
`distribution_ready` remain false. A `pkgutil` notarization status may be
recorded only as observed text; it is not promoted to cryptographic
notarization evidence.

This phase does not invoke `codesign`: Apple documents `pkgutil
--check-signature` as the validity/trust check for installer packages, while
`codesign` is the debugging tool for software other than installer packages.
It also does not invoke `stapler validate`, because the local Apple manpage says
validation requires internet access and compares against the ticketing service.
There is no `spctl`, `productsign`, `notarytool`, Keychain access, network,
installer execution, elevation, or `/Library` mutation.

The current unsigned package must produce a complete inspection with every
signature, notarization, distribution, installation, authorization, and live
claim false. Run `npm run test:phase5h43`.
