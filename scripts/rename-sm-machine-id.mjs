#!/usr/bin/env node
/**
 * Rename the local SM machine_id and re-home the macOS Keychain item.
 * Usage: node scripts/rename-sm-machine-id.mjs pc-macbookm1-andrada
 * Never prints the token.
 */
import process from 'node:process';
import {
  renameSecretsManagerMachineId,
  SecretsManagerLifecycleError,
} from '../src/secrets-manager-local-lifecycle.mjs';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

const newId = process.argv[2];
if (typeof newId !== 'string' || newId.length < 1) {
  emit({
    ok: false,
    code: 'usage',
    hint: 'node scripts/rename-sm-machine-id.mjs pc-macbookm1-andrada',
    authorization_ready: false,
  }, 1);
} else {
  try {
    const result = await renameSecretsManagerMachineId(newId);
    emit({ ...result, helper_vault_free: true });
  } catch (error) {
    const code = error instanceof SecretsManagerLifecycleError
      ? error.code
      : 'rename_failed';
    emit({ ok: false, code, authorization_ready: false, helper_vault_free: true }, 1);
  }
}
