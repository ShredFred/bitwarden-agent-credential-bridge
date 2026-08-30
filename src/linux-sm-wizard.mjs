/**
 * Linux same-user SM first-run wizard. Token never logged.
 * Prefers zenity/kdialog when DISPLAY is set; otherwise a TTY hidden prompt.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import process from 'node:process';
import { interpretMacosWizardDialog } from './macos-sm-wizard.mjs';

export const LINUX_WIZARD_SELF_TEST_TOKEN = '0.fake-linux-wizard-self-test==';
export const LINUX_WIZARD_SELF_TEST_MACHINE_ID = 'pc-selftest-wizard';

const MACHINE_ID = /^[a-z][a-z0-9_-]{0,63}$/;

function spawnCaptured(command, args, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
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

function whichGui() {
  if (typeof process.env.DISPLAY !== 'string' || process.env.DISPLAY.length < 1) {
    if (typeof process.env.WAYLAND_DISPLAY !== 'string' ||
        process.env.WAYLAND_DISPLAY.length < 1) {
      return null;
    }
  }
  const zenity = '/usr/bin/zenity';
  const kdialog = '/usr/bin/kdialog';
  if (fs.existsSync(zenity)) return { kind: 'zenity', bin: zenity };
  if (fs.existsSync(kdialog)) return { kind: 'kdialog', bin: kdialog };
  return null;
}

async function promptZenity(gui, { machineId, bwsOk, timeoutMs }) {
  const idDialog = await spawnCaptured(gui.bin, [
    '--entry',
    '--title', 'Bitwarden Agent Bridge',
    '--text', bwsOk
      ? 'Confirm local machine id (not the Bitwarden secret key):'
      : 'bws CLI missing. Confirm machine id anyway, then install bws:',
    '--entry-text', machineId,
  ], timeoutMs);
  if (idDialog.code !== 0) {
    return { ok: false, code: idDialog.stderr === 'timeout' ? 'wizard_timeout' : 'cancelled' };
  }
  const nextId = idDialog.stdout.trim().toLowerCase();
  if (!MACHINE_ID.test(nextId)) {
    return { ok: false, code: 'invalid_machine_id' };
  }
  const tokenDialog = gui.kind === 'zenity'
    ? await spawnCaptured(gui.bin, [
      '--password',
      '--title', 'Bitwarden Agent Bridge',
      '--text', 'Paste the Secrets Manager machine access token. Do not paste it into chat.',
    ], timeoutMs)
    : await spawnCaptured(gui.bin, [
      '--password',
      'Paste the Secrets Manager machine access token. Do not paste it into chat.',
    ], timeoutMs);
  if (tokenDialog.code !== 0) {
    return { ok: false, code: tokenDialog.stderr === 'timeout' ? 'wizard_timeout' : 'cancelled' };
  }
  return interpretMacosWizardDialog({
    ok: true,
    machine_id: nextId,
    token: tokenDialog.stdout.trim(),
    server_url: '',
  });
}

/**
 * @param {{
 *   selfTest?: boolean,
 *   machineId: string,
 *   bwsOk?: boolean,
 *   timeoutMs?: number,
 *   promptToken?: () => Promise<string>,
 *   promptMachineId?: () => Promise<string>,
 * }} options
 */
export async function collectLinuxWizardAnswers(options) {
  if (options.selfTest === true) {
    return interpretMacosWizardDialog({
      ok: true,
      machine_id: options.machineId || LINUX_WIZARD_SELF_TEST_MACHINE_ID,
      token: LINUX_WIZARD_SELF_TEST_TOKEN,
      server_url: '',
    });
  }
  if (typeof options.promptToken === 'function') {
    const machineId = typeof options.promptMachineId === 'function'
      ? await options.promptMachineId()
      : options.machineId;
    const token = await options.promptToken();
    return interpretMacosWizardDialog({
      ok: true,
      machine_id: machineId,
      token,
      server_url: '',
    });
  }
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : 3600000;
  const gui = whichGui();
  if (gui) {
    return promptZenity(gui, {
      machineId: options.machineId,
      bwsOk: options.bwsOk === true,
      timeoutMs,
    });
  }
  return Object.freeze({ ok: false, code: 'wizard_display_unavailable' });
}
