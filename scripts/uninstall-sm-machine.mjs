#!/usr/bin/env node
/**
 * Remove local SM machine allowlist + access-token store.
 * Does not revoke the Bitwarden-side access token (do that in the SM UI).
 */
import process from 'node:process';
import {
  SM_UNINSTALL_APPROVAL_FLAG,
} from '../src/secrets-manager-defaults.mjs';
import {
  uninstallSecretsManagerLocalState,
} from '../src/secrets-manager-local-lifecycle.mjs';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

if (!process.argv.includes(SM_UNINSTALL_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_UNINSTALL_APPROVAL_FLAG,
    hint: `npm run uninstall:sm -- ${SM_UNINSTALL_APPROVAL_FLAG}`,
    authorization_ready: false,
  }, 1);
} else {
  const report = await uninstallSecretsManagerLocalState();
  emit({
    ok: report.uninstall_complete === true,
    ...report,
    note: 'Local token/allowlist removed. Revoke the machine access token in Bitwarden SM if this PC should lose access.',
  }, report.uninstall_complete ? 0 : 1);
}
