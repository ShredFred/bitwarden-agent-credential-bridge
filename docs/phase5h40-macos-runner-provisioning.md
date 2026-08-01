# Phase 5h.40 — bound launcher and retained-FD runner provisioning

This phase closes two non-live composition gaps: the sudo launcher is now built from the same branded lifecycle package as the runner, and a native root-side primitive can publish, execute, and remove that runner without adopting path replacements. No sudo command was run and nothing under `/Library` was changed.

## Package-bound launcher

The lifecycle runner package now snapshots, builds, ad-hoc signs, strictly verifies, and FD-content remeasures a fixed launcher alongside the runner. Two independent builds must produce identical bytes and designated requirements for both executables. The launcher has no caller-supplied binding API: its generated read-only header contains the exact helper, plist, helper-requirement, and packaged-runner SHA-256 values. Post-link Mach-O section checks compare all four embedded binary digests byte-for-byte. Immediately before elevation the launcher hashes a stable no-follow snapshot of the fixed root-owned runner and requires the packaged-runner digest.

The launcher accepts only `--run-approved-denial-lifecycle`. Its production entrypoint invokes the fixed `/usr/bin/sudo -k -- /Library/PrivilegedHelperTools/de.frederikstadler.bitwarden-agent-credential-bridge.lifecycle-runner --approved-denial-lifecycle` path and reports success only after the bound one-shot approval challenge, denial lifecycle, and cleanup all succeed. Package construction itself never invokes sudo or performs host mutation.

## Root-side provisioning primitive

`bw_provision_run_cleanup_runner` accepts a retained descriptor for the already validated root-owned parent directory and one fixed runner name. It requires a non-group/world-writable directory owned by the requested owner, rejects an existing destination, uses exclusive no-follow retained-FD publication, and verifies exact bytes/owner/group/mode. Production execution forks and invokes the fixed mode through macOS `/dev/fd/<retained-fd>`, so it never reconstructs or executes the published pathname. A callback exists only in explicitly test-compiled fixtures.

Cleanup is identity-bound to the created inode. A pre-existing collision is preserved. If an attacker or concurrent actor replaces the pathname, the primitive refuses to unlink the replacement and reports manual recovery required. Its final result separately records publication, execution, cleanup, and final absence; execution success never masks cleanup failure.

## Verification and remaining live gate

Run `npm run test:phase5h40` for adversarial provisioning fixtures and `npm run test:phase5h39` for the reproducible runner/launcher package. Fixtures prove success cleanup, collision preservation, and replacement preservation without elevation or writes outside a private temporary directory.

This is still not an installer. The production launcher does not yet provision its packaged runner into `/Library`, and the root-side callback is deliberately not wired to a live system transaction. A later explicitly approved macOS test must establish the root-owned directory, provision the exact packaged runner, execute the denial-only lifecycle, verify aggregate absence, and remove every created object. Until then `mutation_authorized`, `live_test_verified`, and `install_gate_eligible` remain false.
