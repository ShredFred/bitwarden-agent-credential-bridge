#!/usr/bin/env node
/**
 * Launch the Windows WinForms first-run SM wizard.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const script = path.join(root, 'scripts', 'windows-sm-first-run-wizard.ps1');

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

if (process.platform !== 'win32') {
  emit({ ok: false, code: 'unsupported_platform' }, 1);
} else {
  const systemRoot = process.env.SystemRoot;
  const powershell = path.join(
    systemRoot || 'C:\\Windows',
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
  const localBwsDir = path.join(
    process.env.LOCALAPPDATA || '',
    'Programs',
    'Bitwarden',
  );
  const env = { ...process.env };
  if (localBwsDir && !String(env.Path || env.PATH || '').toLowerCase().includes(localBwsDir.toLowerCase())) {
    const current = env.Path || env.PATH || '';
    env.Path = `${localBwsDir};${current}`;
  }
  const child = spawn(powershell, [
    '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', script,
    '-InstallRoot', root,
  ], {
    cwd: root,
    windowsHide: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (c) => { stdout += c; });
  child.stderr.on('data', (c) => { stderr += c; });
  child.on('close', (code) => {
    if (stdout.trim()) {
      process.stdout.write(stdout.trim().endsWith('\n') ? stdout : `${stdout.trim()}\n`);
    } else {
      emit({
        ok: false,
        code: code === 0 ? 'empty_wizard_output' : 'wizard_failed',
        authorization_ready: false,
      }, code === 0 ? 0 : 1);
      return;
    }
    process.exitCode = code ?? 1;
  });
}
