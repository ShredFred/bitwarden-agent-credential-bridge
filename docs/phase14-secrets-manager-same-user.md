# Phase 14: Secrets Manager same-user (produktiv)

Productive default: resolve Bitwarden **Secrets Manager** secrets into the
Bridge/broker process under your normal login. No extra OS user accounts. No
vault client in LocalService. `authorization_ready` stays evidence-driven and
is **not** set by SM unlock.

## Model

| Piece | Role |
|---|---|
| Machine account (per PC) | Bitwarden SM non-human identity |
| Access token | Stored locally (Windows DPAPI / macOS token file) |
| Projects | Allowlisted UUIDs (e.g. MiViA + private-hq) |
| Binding table | Alias → project id + secret key (no secret values) |
| `bws` CLI | Pinned upstream tool used by Bridge only |

```text
Agent  --no secrets-->  Bridge(same user)  --bws+token-->  SM (MiViA / private-hq)
                              |
                              +--inject at boundary--> upstream
```

## One-time Bitwarden SM setup

1. Create **one machine account per device** (company laptop, desktop, private Mac).
2. Assign **both** projects to each machine account (read access):
   - MiViA
   - private-hq
3. Create an access token per machine account; copy it once (cannot be retrieved later).
4. Create secrets whose `key` matches your binding table (`sm_secret_key`).
5. Install the Secrets Manager CLI (`bws`) on the host.

Pin a current `bws` release from Bitwarden docs and keep it on `PATH`.

## Local machine config

Copy [`samples/sm-machine.allow.example.json`](../samples/sm-machine.allow.example.json) to:

- Windows: `%LOCALAPPDATA%\BitwardenAgentCredentialBridge\sm-machine.allow.json`
- macOS: `~/Library/Application Support/BitwardenAgentCredentialBridge/sm-machine.allow.json`

Set `machine_id` and your real project UUIDs. Do not commit this file.

### Windows token store (DPAPI)

Create `~\.codex\secrets\bitwarden-agent-sm-machine.credential.xml` with:

- `Purpose = bitwarden-agent-credential-bridge-sm-machine-token-v1`
- `SecretsManagerAllowed = $true`
- `PersonalVaultAllowed = $false`
- Credential password = access token (username may be the machine id)

Example (operator-local, never commit output):

```powershell
$purpose = 'bitwarden-agent-credential-bridge-sm-machine-token-v1'
$dir = Join-Path $env:USERPROFILE '.codex\secrets'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$cred = Get-Credential -UserName 'laptop-company' -Message 'Paste SM access token as password'
$obj = [pscustomobject]@{
  Purpose = $purpose
  SecretsManagerAllowed = $true
  PersonalVaultAllowed = $false
  Credential = $cred
}
$obj | Export-Clixml -Path (Join-Path $dir 'bitwarden-agent-sm-machine.credential.xml')
```

### macOS token file

Write the access token as a single line to:

`~/Library/Application Support/BitwardenAgentCredentialBridge/sm-machine.token`

```bash
mkdir -p "$HOME/Library/Application Support/BitwardenAgentCredentialBridge"
chmod 700 "$HOME/Library/Application Support/BitwardenAgentCredentialBridge"
# paste token once, then:
chmod 600 "$HOME/Library/Application Support/BitwardenAgentCredentialBridge/sm-machine.token"
```

## Bindings

Tracked example: [`samples/operational/bindings-sm.example.json`](../samples/operational/bindings-sm.example.json)

Replace placeholder project UUIDs with MiViA / private-hq. Secret keys must exist in SM.

## Commands

Smoke one secret (no token/secret printed):

```powershell
npm run live:sm-machine -- --i-approve-secrets-manager-machine-resolve
```

Start the SM operational bridge:

```powershell
npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve
```

Optional custom bindings path (must stay under `samples/`):

```powershell
npm run start:operational:sm -- samples/operational/bindings-sm.example.json --i-approve-secrets-manager-machine-resolve
```

## Hard rules

- Approval flag is CLI-only
- Never put `BWS_ACCESS_TOKEN` on agent-visible process environment
- Helper / LocalService stays vault-free
- Fake harness (`npm run start:operational`) remains unchanged for CI
- Day-2 LocalService install is optional harder isolation, not required for SM productivity
