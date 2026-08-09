#!/usr/bin/env node
/**
 * Phase 10c: Windows Day-2 operator session (foreground).
 *
 * Bootstraps branded authorization_ready, wires the operational bridge, and
 * keeps Phase 10a evidence refresh running. Drift fails closed. Never hardcodes
 * authorization_ready=true.
 *
 * Flags:
 *   --i-approve-persistent-install  elevated persistent install first
 *   --skip-apply                    skip vault-free first-install apply
 *   --uninstall-after               uninstall on exit (default leaves service)
 *   --interval-ms=N                 refresh interval (clamped by Phase 10a)
 *
 * Personal/company Bitwarden remain forbidden. Helper stays vault-free.
 * Does not claim same-user memory isolation.
 */
import { spawn } from 'node:child_process';
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  startWindowsDay2OperatorSession,
  WindowsDay2OperatorSessionError,
} from '../src/windows-day2-operator-session.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const APPROVE_INSTALL = process.argv.includes('--i-approve-persistent-install');
const SKIP_APPLY = process.argv.includes('--skip-apply');
const UNINSTALL_AFTER = process.argv.includes('--uninstall-after');
const intervalArg = process.argv.find((arg) => arg.startsWith('--interval-ms='));
const intervalMs = intervalArg === undefined
  ? undefined
  : Number(intervalArg.slice('--interval-ms='.length));

function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

function runNodeScript(scriptRel, args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(root, scriptRel), ...args], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

if (process.platform !== 'win32') {
  emit({
    ok: false,
    code: 'unsupported_platform',
    authorization_ready: false,
    mutation_authorized: false,
  });
  process.exit(1);
}

let session = null;
let stopping = false;

async function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  if (session !== null) {
    await session.stop().catch(() => {});
    session = null;
  }
  if (UNINSTALL_AFTER) {
    emit({ kind: 'uninstall_after', started: true });
    const un = await runNodeScript('scripts/run-windows-persistent-service-lifecycle.mjs', ['uninstall']);
    emit({ kind: 'uninstall_after', exit_code: un.code });
  }
  process.exit(code);
}

process.once('SIGINT', () => { void shutdown(0); });
process.once('SIGTERM', () => { void shutdown(0); });

async function main() {
  if (APPROVE_INSTALL) {
    emit({ kind: 'persistent_install', started: true });
    const installed = await runNodeScript(
      'scripts/run-windows-persistent-service-lifecycle.mjs',
      ['install'],
    );
    emit({
      kind: 'persistent_install',
      exit_code: installed.code,
      ok: installed.code === 0,
    });
    if (installed.code !== 0) {
      emit({
        ok: false,
        code: 'persistent_install_failed',
        authorization_ready: false,
        mutation_authorized: false,
      });
      await shutdown(1);
      return;
    }
  }

  session = await startWindowsDay2OperatorSession({
    repoRoot: root,
    skipApply: SKIP_APPLY,
    intervalMs,
    onEvent: (event) => { emit(event); },
  });
}

try {
  await main();
} catch (error) {
  const code = error instanceof WindowsDay2OperatorSessionError
    ? error.code
    : (error && typeof error === 'object' && typeof error.code === 'string'
      ? error.code
      : 'day2_failed');
  emit({
    ok: false,
    code,
    authorization_ready: false,
    mutation_authorized: false,
  });
  await shutdown(1);
}
