/**
 * macOS SM first-run wizard helpers. Token values must never be logged.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseOsascriptJson } from './macos-osascript-json.mjs';
import {
  storeSecretsManagerAccessToken,
  writeSecretsManagerAllowConfig,
} from './secrets-manager-local-lifecycle.mjs';
import { verifySecretsManagerMachineToken } from './secrets-manager-bws-adapter.mjs';

/** Fake sentinel for JXA --self-test only. Never a live SM token. */
export const MACOS_WIZARD_SELF_TEST_TOKEN = '0.fake-macos-wizard-self-test==';
export const MACOS_WIZARD_SELF_TEST_MACHINE_ID = 'pc-selftest-wizard';

const MACHINE_ID = /^[a-z][a-z0-9_-]{0,63}$/;

/**
 * @param {unknown} parsed
 * @returns {{
 *   ok: true, machineId: string, token: string, serverUrl: string
 * } | {
 *   ok: false, code: string
 * }}
 */
export function interpretMacosWizardDialog(parsed) {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return Object.freeze({ ok: false, code: 'wizard_output_invalid' });
  }
  const rec = /** @type {Record<string, unknown>} */ (parsed);
  if (rec.ok !== true) {
    return Object.freeze({
      ok: false,
      code: typeof rec.code === 'string' ? rec.code : 'wizard_failed',
    });
  }
  const machineId = typeof rec.machine_id === 'string'
    ? rec.machine_id.trim().toLowerCase()
    : '';
  const token = typeof rec.token === 'string' ? rec.token.trim() : '';
  const serverUrl = typeof rec.server_url === 'string' ? rec.server_url.trim() : '';
  if (!MACHINE_ID.test(machineId)) {
    return Object.freeze({ ok: false, code: 'invalid_machine_id' });
  }
  if (token.length < 16 || token.length > 8192 || /[\r\n]/.test(token)) {
    return Object.freeze({ ok: false, code: 'invalid_token' });
  }
  if (serverUrl.length > 0 && !/^https:\/\//.test(serverUrl)) {
    return Object.freeze({ ok: false, code: 'invalid_server_url' });
  }
  return Object.freeze({
    ok: true,
    machineId,
    token,
    serverUrl,
  });
}

/**
 * @param {{
 *   machineId: string,
 *   token: string,
 *   serverUrl?: string,
 * }} input
 * @param {{
 *   allowPath?: string,
 *   storeToken?: Function,
 *   runSecurity?: Function,
 *   skipVerify?: boolean,
 *   runCommand?: Function,
 * }} [options]
 */
export async function applySecretsManagerWizardSetup(input, options = {}) {
  /** @type {{ machine_id: string, server_url?: string }} */
  const allowInput = { machine_id: input.machineId };
  if (typeof input.serverUrl === 'string' && input.serverUrl.length > 0) {
    allowInput.server_url = input.serverUrl;
  }
  const allow = await writeSecretsManagerAllowConfig(allowInput, {
    allowPath: options.allowPath,
  });
  const skipVerify = options.skipVerify === true ||
    typeof options.storeToken === 'function';
  let projectsListed = null;
  let allowedVisible = null;
  if (!skipVerify) {
    const probe = await verifySecretsManagerMachineToken({
      accessToken: input.token,
      allowedProjectIds: allow.allowed_project_ids,
      allowConfig: allow,
      runCommand: options.runCommand,
    });
    projectsListed = probe.projects_listed;
    allowedVisible = probe.allowed_projects_visible;
  }
  await storeSecretsManagerAccessToken({
    accessToken: input.token,
    machine_id: allow.machine_id,
    storeToken: options.storeToken,
    runSecurity: options.runSecurity,
  });
  return Object.freeze({
    ok: true,
    setup_complete: true,
    machine_id: allow.machine_id,
    project_count: allow.project_count,
    cloud_default: allow.cloud_default === true,
    projects_listed: projectsListed,
    allowed_projects_visible: allowedVisible,
    authorization_ready: false,
    helper_vault_free: true,
  });
}

function spawnCaptured(command, args, options, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      resolve({ code: 1, stdout, stderr: 'timeout' });
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve({ code: 1, stdout, stderr: 'spawn_failed' });
    });
  });
}

/**
 * Run the JXA wizard without GUI (--self-test).
 * @param {{ machineId?: string, timeoutMs?: number }} [options]
 */
export async function runMacosWizardJxaSelfTest(options = {}) {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
  const script = path.join(root, 'scripts', 'macos-sm-first-run-wizard.jxa');
  const machineId = options.machineId ?? MACOS_WIZARD_SELF_TEST_MACHINE_ID;
  const dialog = await spawnCaptured('/usr/bin/osascript', [
    '-l', 'JavaScript',
    script,
    '--',
    '--self-test',
    '--machine-id', machineId,
    '--bws-ok', '1',
  ], {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env,
  }, Number.isInteger(options.timeoutMs) ? options.timeoutMs : 15000);

  const trimmed = dialog.stdout.trim();
  if (!trimmed) {
    const scriptError = /execution error/i.test(dialog.stderr);
    return Object.freeze({
      ok: false,
      code: scriptError ? 'wizard_script_error' : (
        dialog.code === 0 ? 'empty_wizard_output' : 'wizard_failed'
      ),
    });
  }
  let parsed;
  try {
    parsed = parseOsascriptJson(trimmed);
  } catch {
    return Object.freeze({ ok: false, code: 'wizard_output_invalid' });
  }
  const interpreted = interpretMacosWizardDialog(parsed);
  if (interpreted.ok !== true) {
    return interpreted;
  }
  return interpreted;
}
