# Phase 5h.17: Linux systemd distinct-writer boundary plan

Phase 5h.17 defines a pure, non-executable contract for a future Linux helper
managed by the **system** instance of systemd. It deliberately does not claim
support for systemd user services, OpenRC, launchd, containers without the
required kernel/systemd controls, or generic POSIX systems.

The plan fixes a non-login, passwordless, static system account and fixed service
and socket unit names. A static account is required because filesystem ownership
and the initial-user-namespace UID comparison must remain stable across service
restarts; `DynamicUser=` is explicitly not treated as a substitute for that
long-lived ownership proof.

The future installation must independently prove root-owned, caller-nonwritable
unit and binary objects **and every containing directory/mount boundary**. A
trusted inode is insufficient when the caller can rename or unlink it through a
writable parent. The collector must resolve without symlinks beneath retained
directory handles, bind the binary and loaded unit identities to retained file
descriptors, and after `daemon-reload` reverify systemd's loaded fragment path,
empty drop-in set, and reviewed content digests. It must also prove absence of
aliases and a root-owned filesystem AF_UNIX endpoint whose ACL permits the
approved caller to connect but not replace the socket. Abstract sockets are
excluded because they do not provide the required filesystem ownership boundary.
The native collector must still bind kernel peer credentials and process
identity as required by Phase 5h.3.

The service contract requires `Type=exec` semantics, an empty capability and
ambient-capability set, no-new-privileges, strict filesystem protection, private
devices/temp, no interactive login, and no vault access. No-network is a real
enforcement requirement, not a statement of intent: a future verifier must prove
an isolated network namespace, an exact AF_UNIX-only address-family restriction,
`IPAddressDeny=any`, and that the host actually enforced those controls. These are
requirements for a future native verifier; the plan does not generate a unit
file or assume unsupported sandbox features silently took effect.

The API accepts only platform, the exact `systemd-system` runtime profile, and a
reviewed binary digest/length. It emits no commands, paths, UIDs, unit contents,
approval value, credential, vault reference, or executable configuration. Plans
are branded in-process; serialization or cloning does not create a capability.

Still absent: host preflight, account/unit creation, elevation, lifecycle gate,
trusted transcript collector, AF_UNIX listener, real different-UID denial test,
manifest executor, normal user-root access, OneCLI, or Bitwarden access.

The design relies on the Linux AF_UNIX peer-credential semantics and systemd
service/sandbox behavior described by the current `unix(7)`, `systemd.service(5)`,
and `systemd.exec(5)` manuals. Those runtime properties must be reverified on the
actual target host before any future live gate.

```bash
npm run test:phase5h17
```
