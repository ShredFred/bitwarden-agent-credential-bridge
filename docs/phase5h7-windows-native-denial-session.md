# Phase 5h.7: combined Windows native denial session

This phase combines the previously separate Windows transport, launcher, token,
and target-access evidence in one real short-lived helper process. Its only
valid result on the current workstation remains denial.

## Two independent channels

The calling Bridge process connects directly to the first-instance named pipe.
It sends a bounded frame containing the workspace nonce, an eight-digit
lowercase hexadecimal request length, and the byte-exact canonical Phase 5h.1
request. The native probe caps and strictly decodes every frame component.

Launcher bytes never enter the pipe, argv, environment, stdout, or returned
result. The parent writes generated non-secret bytes to an exclusive random file
inside the verified disposable root, opens a separate read-only handle, unlinks
the name, closes the writer, and inherits only the reader as probe stdin. The
probe reads it to EOF with a 1 MiB limit and independently matches request
length and SHA-256.

## Native effective-access checks

This slice accepts first-install manifests only. It checks the five canonical
paths: configuration directory/file, install root, binary directory, and
launcher. For each caller and helper process token, the probe:

1. opens and duplicates the primary token at impersonation level;
2. verifies the target and every existing ancestor stay inside the disposable
   root and are not reparse points;
3. obtains a complete owner/group/DACL security descriptor; and
4. calls Win32 `AccessCheck` for the exact existing-object write rights or the
   first missing file/directory creation right.

All five checks must finish before `acl_checks_verified` and
`all_targets_checked` become true. Since caller and helper currently have the
same `TokenUser`, the live result correctly shows caller write is not denied and
helper write is allowed.

## Authorization outcome

The probe emits digest-only platform facts plus two booleans for request and
launcher-handle verification. The Node side strips those two fields before
feeding the exact Phase 5h.2 evaluator, then calls Phase 5h.1 authorization.
Equal `TokenUser` digests terminate at `same_principal_rejected`; the manifest
executor is never imported or invoked.

Upgrade/backup targets, ACL mutation, a distinct account/service, and successful
apply remain behind a separately approved disposable live gate. Linux and macOS
still have evidence compilers but not equivalent native combined sessions.
