# Phase 5h.42 — non-installing macOS provisioner bootstrap package

Phase 5h.42 packages the fixed Phase 5h.41 lifecycle provisioner as a macOS component package without installing it. It invokes `pkgbuild`, `pkgutil`, `lsbom`, `ditto`, and `xattr` only inside private temporary build roots. It never invokes `installer`, sudo, launchctl, dscl, Keychain, Bitwarden, OneCLI, or a network client, and it never writes under `/Library`.

## Exact package contract

The package identifier is fixed to:

`de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-provisioner`

The install location is `/`, and the single effective filesystem payload is:

`/Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-provisioner`

The builder accepts no paths, package metadata, bytes, scripts, signing identity, or installation options. It obtains the branded Phase 5h.41 package in-process, copies only its provisioner bytes, and checks their SHA-256 and byte length before constructing a destination root. The public bootstrap object exposes only provisioner bindings and independently copied PKG bytes; it does not re-export the lifecycle package authority.

Two complete builds must have identical provisioner payload bytes, normalized payload-file manifest, BOM, and PackageInfo. The PKG container may contain tool-generated timestamps, so container reproducibility is measured and reported rather than assumed.

## Post-build verification

Each package is expanded and inspected before it can become a branded bootstrap object:

- the flat package has exactly `Bom`, `PackageInfo`, and `Payload` members;
- PackageInfo has one package root, one payload element, the fixed identifier/version/install location, root authorization, an exact payload-file count, and only the six exact empty metadata markers emitted by `pkgbuild` (`bundle-version`, upgrade/update/atomic-update bundle, strict-identifier, and relocate); scripts or any other sibling are forbidden;
- `pkgutil --payload-files` must match the complete pinned archive manifest with no extras;
- every BOM entry is pinned, root:wheel, and has the expected directory or `0555` executable mode;
- AppleDouble entries are accepted only at the three exact tool-generated metadata paths and are included in the manifest/file-count proof;
- `ditto` extraction must produce only the effective `Library/PrivilegedHelperTools/<provisioner>` tree, with no sidecar files and byte-exact provisioner content;
- extracted extended attributes may contain only macOS-generated `com.apple.provenance`; every other attribute fails the build;
- no `Scripts` package member, PackageInfo element, BOM path, or extracted filesystem object is permitted.

Private roots are verified as canonical temp descendants, owned by the current user, mode `0700`, and not symlinks. Cleanup walks only that verified root, never follows symlink entries, and cleanup failures invalidate a successful build. If a primary verification failure and cleanup failure coincide, the primary code is preserved and cleanup failure is attached or appended.

## Authority and remaining gates

The branded object keeps all deployment claims false:

- `installer_signature_verified`
- `notarization_verified`
- `bootstrap_installed`
- `install_authorized`
- `live_test_verified`

This unsigned development package is evidence for payload correctness, not a production distributor. A production release needs a reviewed Developer ID Installer signature, notarization/stapling policy, upgrade/uninstall behavior, and explicit operator approval. The first real install and the subsequent sudo→provisioner→runner denial lifecycle remain separate privileged live gates.

Run `npm run test:phase5h42`. On Windows, native package construction is skipped while source-contract checks remain mandatory.
