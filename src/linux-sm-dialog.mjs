/**
 * Shared Linux GUI dialog runner for SM wizard / secret-entry.
 * Absolute /usr/bin tools only. Bounded output. No token in the child env.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import process from 'node:process';

export const LINUX_DIALOG_MAX_OUTPUT = 16 * 1024;

const ZENITY = '/usr/bin/zenity';
const KDIALOG = '/usr/bin/kdialog';

function hasDisplay() {
  return (typeof process.env.DISPLAY === 'string' && process.env.DISPLAY.length > 0) ||
    (typeof process.env.WAYLAND_DISPLAY === 'string' && process.env.WAYLAND_DISPLAY.length > 0);
}

function isSafeSystemExecutable(bin) {
  try {
    const link = fs.lstatSync(bin);
    const st = link.isSymbolicLink() ? fs.statSync(bin) : link;
    return st.isFile() && (st.mode & 0o022) === 0;
  } catch {
    return false;
  }
}

/**
 * @returns {{ kind: 'zenity' | 'kdialog', bin: string } | null}
 */
export function resolveLinuxGuiTool() {
  if (!hasDisplay()) return null;
  if (isSafeSystemExecutable(ZENITY)) return { kind: 'zenity', bin: ZENITY };
  if (isSafeSystemExecutable(KDIALOG)) return { kind: 'kdialog', bin: KDIALOG };
  return null;
}

function dialogEnv() {
  /** @type {NodeJS.ProcessEnv} */
  const env = {
    PATH: '/usr/bin:/bin',
    LANG: 'C',
    LC_ALL: 'C',
  };
  if (typeof process.env.HOME === 'string') env.HOME = process.env.HOME;
  if (typeof process.env.DISPLAY === 'string') env.DISPLAY = process.env.DISPLAY;
  if (typeof process.env.WAYLAND_DISPLAY === 'string') {
    env.WAYLAND_DISPLAY = process.env.WAYLAND_DISPLAY;
  }
  if (typeof process.env.XAUTHORITY === 'string') env.XAUTHORITY = process.env.XAUTHORITY;
  if (typeof process.env.XDG_RUNTIME_DIR === 'string') {
    env.XDG_RUNTIME_DIR = process.env.XDG_RUNTIME_DIR;
  }
  return env;
}

/**
 * @param {string} command
 * @param {string[]} args
 * @param {number} timeoutMs
 * @returns {Promise<{ code: number, stdout: string, stderr: string }>}
 */
export function spawnLinuxDialog(command, args, timeoutMs) {
  return new Promise((resolve) => {
    if (command !== ZENITY && command !== KDIALOG) {
      resolve({ code: 1, stdout: '', stderr: 'spawn_failed' });
      return;
    }
    if (!isSafeSystemExecutable(command)) {
      resolve({ code: 1, stdout: '', stderr: 'spawn_failed' });
      return;
    }
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: dialogEnv(),
    });
    let stdout = '';
    let stderr = '';
    let overflow = false;
    let settled = false;
    let killTimer;
    const requestStop = () => {
      child.kill('SIGTERM');
      if (!killTimer) {
        killTimer = setTimeout(() => {
          child.kill('SIGKILL');
        }, 250);
      }
    };
    const dropCapture = () => {
      stdout = '';
      stderr = '';
      child.stdout.pause();
      child.stderr.pause();
    };
    const finish = (code, err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (overflow) dropCapture();
      resolve({
        code,
        stdout: overflow ? '' : stdout,
        stderr: overflow ? 'output_overflow' : err,
      });
    };
    const timer = setTimeout(() => {
      requestStop();
      finish(1, 'timeout');
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      if (overflow || settled) return;
      stdout += chunk;
      if (stdout.length > LINUX_DIALOG_MAX_OUTPUT) {
        overflow = true;
        dropCapture();
        requestStop();
      }
    });
    child.stderr.on('data', (chunk) => {
      if (overflow || settled) return;
      stderr += chunk;
      if (stderr.length > LINUX_DIALOG_MAX_OUTPUT) {
        overflow = true;
        dropCapture();
        requestStop();
      }
    });
    child.on('close', (code) => {
      clearTimeout(killTimer);
      finish(overflow ? 1 : (code ?? 1), overflow ? 'output_overflow' : stderr);
    });
    child.on('error', () => {
      requestStop();
      finish(1, 'spawn_failed');
    });
  });
}
