# Phase 16: Fake-loopback SSH/FTP session brokers

Phase 16 adds policy versions 7 (`ssh`) and 8 (`ftp`) with dedicated session
brokers. Credentials resolve from Secrets Manager (DPAPI machine token on
Windows) into broker memory only. Agents see opaque session ids and allow-listed
ops — never passwords, never `process.env` injection.

## What works

- Loopback fake SSH/FTP JSON-line servers (not OpenSSH / wire FTP)
- HTTP agent surfaces: `/status`, SSH `/exec`, FTP `/list` + `/retr`
- Exact command/path allow-lists; concurrent writer forbidden per class
- Exposure redaction on logs and responses
- Operational SM matrix over private-hq for bearer, API-key header/query,
  Basic, browser form-login, SSH, and FTP

## Commands

```bash
npm run test:phase16
npm run live:sm-matrix -- --i-approve-secrets-manager-machine-resolve
```

## Non-claims

- Not production SSH/FTP clients
- Not non-loopback remotes without a later live gate
- Not `env_inject`; `authorization_ready` stays false
- Helper remains vault-free
