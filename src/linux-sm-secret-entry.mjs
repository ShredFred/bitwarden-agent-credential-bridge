/**
 * Linux agent-blind SM secret-entry: zenity/kdialog per field, or injected prompts.
 * Never logs secret values.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import process from 'node:process';

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
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
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
  if ((typeof process.env.DISPLAY !== 'string' || process.env.DISPLAY.length < 1) &&
      (typeof process.env.WAYLAND_DISPLAY !== 'string' || process.env.WAYLAND_DISPLAY.length < 1)) {
    return null;
  }
  if (fs.existsSync('/usr/bin/zenity')) return { kind: 'zenity', bin: '/usr/bin/zenity' };
  if (fs.existsSync('/usr/bin/kdialog')) return { kind: 'kdialog', bin: '/usr/bin/kdialog' };
  return null;
}

/**
 * @param {{
 *   form: { title: string, info?: string, fields: Array<{ sm_key: string, label: string, secret: boolean }> },
 *   timeoutMs?: number,
 *   promptField?: (field: { sm_key: string, label: string, secret: boolean }) => Promise<string | null>,
 * }} options
 */
export async function collectLinuxSecretEntryValues(options) {
  const form = options.form;
  if (typeof options.promptField === 'function') {
    /** @type {Record<string, string>} */
    const values = {};
    for (const field of form.fields) {
      const got = await options.promptField(field);
      if (got === null) {
        return Object.freeze({ ok: false, cancelled: true, code: 'cancelled', values: {} });
      }
      values[field.sm_key] = got;
    }
    return Object.freeze({ ok: true, cancelled: false, values });
  }
  const gui = whichGui();
  if (!gui) {
    return Object.freeze({ ok: false, cancelled: false, code: 'dialog_display_unavailable', values: {} });
  }
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : 3600000;
  /** @type {Record<string, string>} */
  const values = {};
  for (const field of form.fields) {
    const text = `${form.title}\n${field.label}`;
    const dialog = gui.kind === 'zenity'
      ? await spawnCaptured(gui.bin, field.secret
        ? ['--password', '--title', 'Bitwarden Agent Bridge', '--text', text]
        : ['--entry', '--title', 'Bitwarden Agent Bridge', '--text', text], timeoutMs)
      : await spawnCaptured(gui.bin, field.secret
        ? ['--password', text]
        : ['--inputbox', text, ''], timeoutMs);
    if (dialog.code !== 0) {
      return Object.freeze({
        ok: false,
        cancelled: dialog.stderr !== 'timeout',
        code: dialog.stderr === 'timeout' ? 'dialog_timeout' : 'cancelled',
        values: {},
      });
    }
    values[field.sm_key] = dialog.stdout.replace(/\n$/, '');
  }
  return Object.freeze({ ok: true, cancelled: false, values });
}
