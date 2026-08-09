#!/usr/bin/env node
/**
 * Guided same-user Secrets Manager setup.
 *
 * Windows: opens a credential window — paste the machine access token as the
 * password. Writes allowlist (MiViA + private-hq) + DPAPI store.
 * macOS: prompts once in the terminal for the token (not echoed).
 *
 * Never prints the token. LocalService not required.
 */
import process from 'node:process';
import os from 'node:os';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { spawn } from 'node:child_process';
import path from 'node:path';
import {
  SM_DEFAULT_ALLOWED_PROJECT_IDS,
  SM_SETUP_APPROVAL_FLAG,
} from '../src/secrets-manager-defaults.mjs';
import {
  checkBwsAvailable,
  storeSecretsManagerAccessToken,
  writeSecretsManagerAllowConfig,
  SecretsManagerLifecycleError,
} from '../src/secrets-manager-local-lifecycle.mjs';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function defaultMachineId() {
  const host = (os.hostname() || 'machine').toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
  const cleaned = host.replace(/^-+|-+$/g, '').slice(0, 48);
  return cleaned.length > 0 ? `pc-${cleaned}` : 'pc-local';
}

async function promptMachineId() {
  const rl = readline.createInterface({ input, output });
  try {
    const suggested = defaultMachineId();
    const answer = (await rl.question(
      `Machine id [${suggested}] (letters/digits/_/-): `,
    )).trim();
    return answer.length > 0 ? answer.toLowerCase() : suggested;
  } finally {
    rl.close();
  }
}

async function promptTokenWindows(machineId) {
  // Comfortable Windows credential dialog: password field = access token.
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
    throw new SecretsManagerLifecycleError('system_root_absent');
  }
  const powershell = path.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  const ps = `
$ErrorActionPreference = 'Stop'
$cred = Get-Credential -UserName '${machineId.replace(/'/g, "''")}' -Message 'Paste Bitwarden Secrets Manager access token as the password'
if ($null -eq $cred) { [Console]::Error.Write('cancelled'); exit 2 }
$net = $cred.GetNetworkCredential()
if ($null -eq $net -or [string]::IsNullOrWhiteSpace($net.Password)) {
  [Console]::Error.Write('token_absent'); exit 3
}
[Console]::Out.Write($net.Password)
`;
  return await new Promise((resolve, reject) => {
    const child = spawn(powershell, [
      '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps,
    ], {
      windowsHide: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => {
      if (code !== 0 || !stdout) {
        reject(new SecretsManagerLifecycleError(
          stderr.includes('cancelled') ? 'cancelled' : 'token_prompt_failed',
        ));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

async function promptTokenMac() {
  const rl = readline.createInterface({ input, output });
  try {
    output.write('Paste SM access token (hidden), then Enter:\n');
    // Best-effort hide: turn off echo via readline isn't portable; read once.
    // Prefer stdin raw mute where possible.
    if (input.isTTY && typeof input.setRawMode === 'function') {
      return await readHiddenLine();
    }
    const line = await rl.question('');
    return line.trim();
  } finally {
    rl.close();
  }
}

function readHiddenLine() {
  return new Promise((resolve) => {
    const chunks = [];
    input.setRawMode(true);
    input.resume();
    input.setEncoding('utf8');
    const onData = (char) => {
      if (char === '\n' || char === '\r' || char === '\u0004') {
        input.setRawMode(false);
        input.pause();
        input.removeListener('data', onData);
        output.write('\n');
        resolve(chunks.join('').trim());
        return;
      }
      if (char === '\u0003') {
        process.exit(1);
      }
      if (char === '\u007f' || char === '\b') {
        chunks.pop();
        return;
      }
      chunks.push(char);
      output.write('*');
    };
    input.on('data', onData);
  });
}

if (!process.argv.includes(SM_SETUP_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_SETUP_APPROVAL_FLAG,
    hint: `npm run setup:sm -- ${SM_SETUP_APPROVAL_FLAG}`,
    authorization_ready: false,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
} else {
  try {
    output.write('\n=== Bitwarden Secrets Manager setup (same-user) ===\n');
    output.write('1) Machine account token from Bitwarden SM\n');
    output.write('2) Projects MiViA + private-hq are preconfigured\n');
    output.write('3) No LocalService / no extra Windows user needed\n\n');

    const bws = await checkBwsAvailable();
    if (!bws.bws_available) {
      emit({
        ok: false,
        code: 'bws_missing',
        hint: 'Install Bitwarden Secrets Manager CLI (bws) and ensure it is on PATH',
        authorization_ready: false,
      }, 1);
    } else {
      const machineId = await promptMachineId();
      const accessToken = process.platform === 'win32'
        ? await promptTokenWindows(machineId)
        : await promptTokenMac();

      const allow = await writeSecretsManagerAllowConfig({
        machine_id: machineId,
        allowed_project_ids: [...SM_DEFAULT_ALLOWED_PROJECT_IDS],
      });
      await storeSecretsManagerAccessToken({
        accessToken,
        machine_id: machineId,
      });

      emit({
        ok: true,
        setup_complete: true,
        machine_id: allow.machine_id,
        project_count: allow.project_count,
        bws_available: true,
        token_stored: true,
        allow_config_written: true,
        authorization_ready: false,
        helper_vault_free: true,
        next: 'npm run start:operational:sm -- --i-approve-secrets-manager-machine-resolve',
      });
    }
  } catch (error) {
    const code = error instanceof SecretsManagerLifecycleError
      ? error.code
      : 'setup_failed';
    emit({ ok: false, code, authorization_ready: false, helper_vault_free: true }, 1);
  }
}
