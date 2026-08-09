#!/usr/bin/env node
/**
 * Apply wizard inputs: machine id (+ optional server_url) from env, token on stdin.
 * Never prints the token. Used by the Windows WinForms first-run wizard.
 */
import process from 'node:process';
import {
  SM_SETUP_APPROVAL_FLAG,
  SM_DEFAULT_ALLOWED_PROJECT_IDS,
} from '../src/secrets-manager-defaults.mjs';
import {
  storeSecretsManagerAccessToken,
  writeSecretsManagerAllowConfig,
  SecretsManagerLifecycleError,
} from '../src/secrets-manager-local-lifecycle.mjs';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function readStdinLine() {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => reject(new Error('stdin_timeout')), 30000);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => {
      clearTimeout(timer);
      resolve(data.replace(/\r?\n$/, '').trim());
    });
    process.stdin.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

if (!process.argv.includes(SM_SETUP_APPROVAL_FLAG)) {
  emit({ ok: false, code: 'approval_flag_required' }, 1);
} else {
  try {
    const machineId = process.env.SM_WIZARD_MACHINE_ID;
    const serverUrl = process.env.SM_WIZARD_SERVER_URL;
    delete process.env.SM_WIZARD_MACHINE_ID;
    delete process.env.SM_WIZARD_SERVER_URL;
    const accessToken = await readStdinLine();
    const allowInput = {
      machine_id: machineId,
      allowed_project_ids: [...SM_DEFAULT_ALLOWED_PROJECT_IDS],
    };
    if (typeof serverUrl === 'string' && serverUrl.length > 0) {
      allowInput.server_url = serverUrl;
    }
    const allow = await writeSecretsManagerAllowConfig(allowInput);
    await storeSecretsManagerAccessToken({
      accessToken,
      machine_id: allow.machine_id,
    });
    emit({
      ok: true,
      setup_complete: true,
      machine_id: allow.machine_id,
      project_count: allow.project_count,
      cloud_default: allow.cloud_default === true,
      authorization_ready: false,
      helper_vault_free: true,
    });
  } catch (error) {
    const code = error instanceof SecretsManagerLifecycleError
      ? error.code
      : 'setup_failed';
    emit({ ok: false, code, authorization_ready: false }, 1);
  }
}
