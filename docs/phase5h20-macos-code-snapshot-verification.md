# Phase 5h.20: fd-content-bound macOS code verification

Phase 5h.20 closes the explicit Phase 5h.19 path-TOCTOU gap for static code
measurement. It does not install, load, connect to, or authorize the helper.

## Why a private snapshot is required

Apple's public static-code interfaces operate on code objects addressed by a
path. They do not expose a supported `SecStaticCode` file-descriptor constructor,
and `/usr/bin/codesign` does not provide a documented descriptor-bound code
object. Re-resolving the installed helper path, including through `F_GETPATH`,
would retain the swap-and-restore problem.

The verifier therefore receives bytes already read from the fixed helper's open
`O_NOFOLLOW` descriptor. It creates one unpredictable private directory directly
beneath the canonical OS temporary directory and one exclusive file inside it.
The file is a byte-identical measurement object, not an installation artifact.

## Exact verification sequence

1. Reject non-macOS use, empty/oversized bytes, and malformed requirement pins.
2. Create a fresh `mkdtemp` directory and require current-EUID ownership, mode
   `0700`, a real directory, and direct canonical-temp containment.
3. Create the fixed snapshot filename with
   `O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW` and mode `0600`.
4. Write all bytes through the retained handle, `fsync`, re-read, and compare
   SHA-256 with the source bytes.
5. Run fixed `/usr/bin/codesign --verify --strict` and `codesign -d -r-` only on
   the private snapshot.
6. Require the exact canonical `designated => ...\n` digest pinned by the plan.
7. Recheck snapshot handle/path device, inode, size, timestamps, owner, mode,
   and content digest.
8. Back in the host probe, recheck the original installed descriptor's identity
   and content. Only then may `designated_requirement_verified` be true.
9. Close, unlink the exact snapshot, and remove the exact directory on every
   outcome. Cleanup failure fails the probe.

The existing path-based result remains a separate advisory diagnostic. It is not
needed for the content-bound verified bit and cannot substitute for it.

## Remaining boundary

`snapshot_matches_plan` may now become true when every static host fact matches.
`authorization_ready` remains structurally and parent-enforced false. Static
preflight does not prove which launchd job is loaded or which process is connected
over XPC. A later denial-only live collector must bind the launchd job, helper and
caller audit tokens, PIDs plus PID generations, distinct EUIDs, code requirement,
and target access before any request could become eligible.

The only filesystem mutation added here is the exclusive private temporary copy
and its mandatory exact cleanup. There is no write to `/Library`, a user home,
Keychain, Bitwarden, OneCLI, or any manifest target. A malicious process already
able to compromise another same-EUID process remains outside this preflight's
claim; directory/file exclusivity, retained handles, and post-verification checks
reduce accidental and pathname races but are not a new principal boundary.

```bash
npm run test:phase5h20
```
