# Cross-platform production authorization parity

Windows already has the live operator path to evidence-driven
`authorization_ready=true` (Phases 9–10c).

macOS and Linux now have the **same pure compiler ladder**:

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Install-gate + layout | 5h.46/47 | 11a/11b | 12a–12f |
| Production 9a compiler | 9a | 11e | 12p |
| Operational wire | 9e | 11j | 12t |
| Ready bootstrap (injected) | 10b | 11l | 12u |
| Day-2 operator | 10c | host handoff | host handoff |
| Live collectors | done on Win | **Mac host** | **Linux host** |

Synthetic complete fixtures may set `authorization_ready=true` in unit tests on
any host. Live Mac/Linux readiness still requires the host handoffs:

- [`docs/phase11c-macos-disposable-denial-handoff.md`](phase11c-macos-disposable-denial-handoff.md)
- [`docs/phase12n-linux-disposable-denial-handoff.md`](phase12n-linux-disposable-denial-handoff.md)

Platform reports stay isolated: Windows ready never implies darwin/linux ready.

```bash
npm run test:cross-platform-auth
```
