# Agent Credential Manifesto

Agents are extraordinary at using tools and terrible at keeping secrets.
This project exists so an agent can **use** a credential without **possessing**
it.

1. **Use, not possession.** The calling agent may trigger an allowed action.
   It does not receive the password, token, cookie, or session material.
2. **Allow-lists, not templates.** Policies name exact routes, headers, fields,
   and ops. They never contain secret values.
3. **Fail closed.** Unsupported classes, ambiguous input, MFA, CAPTCHA, and
   oversized or echoing responses stop. They do not dump HTML, titles, or
   secrets into the agent context.
4. **No environment injection.** Secrets do not ride `process.env`, child
   environments, or agent-readable stdout. That is a permanent product decision,
   including where upstream Agent Access uses `aac run`.
5. **Evidence over slogans.** `authorization_ready` is compiled from branded
   platform evidence. Unlocking Secrets Manager does not set it true.
6. **The helper stays vault-free.** OS writer research (LocalService,
   LaunchDaemon, systemd) must never grow a vault client or a secret on the
   helper pipe.
7. **Honest limits.** This is experimental. It is not a Bitwarden product, not
   a production password manager, and not a claim that same-user memory
   isolation is a production writer boundary.

If that is the contract you want for agent tooling, use the Bridge, file
issues, or send a narrow pull request. If you need the agent to *see* the
secret, this repository is the wrong tool.
