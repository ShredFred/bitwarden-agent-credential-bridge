# Agent Credential Bridge Experiment Rules

This repository is a sample-only security experiment.

- Never use, request, read, copy, log, or store real credentials, vault exports, cookies, recovery codes, authentication tokens, or private service inventories.
- Use generated fake values only. Tests must fail if a fake sentinel secret appears on an agent-readable surface.
- Do not connect to a personal or company Bitwarden vault in Phase 1.
- Do not add custom cryptography. Prefer standard-library code and pinned upstream tools.
- Unsupported credential classes must fail closed. Never fall back to printing or general process-environment injection.
- Keep the first slice dependency-free where practical and cross-platform across Windows, macOS, and Linux.
- One writer at a time. Preserve unrelated changes and keep diffs narrow.
- Run tests before claiming completion. Report limitations explicitly.
- Do not create a remote or push this repository until a separate secret scan and publication review pass succeeds.

## Phase 1 scope

Implement only:

- a local fake HTTP API that accepts one bearer-token sentinel and returns a constant response;
- a declarative sample policy for the fake service;
- policy validation;
- a foreground-only fake broker that applies the policy and injects the sentinel at the outbound boundary;
- functional and exposure tests proving the caller receives no plaintext secret;
- documentation explaining that this harness tests the contract, not Bitwarden or OneCLI production security.

Do not implement Bitwarden pairing, OneCLI deployment, TLS interception, certificate installation, firewall mutation, background services, browser login, MFA, SSH, databases, RDP, or desktop credential handling in this slice.
