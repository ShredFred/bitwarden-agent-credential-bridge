#!/usr/bin/env node
/**
 * Phase 13 laptop-ready entry (Windows).
 *
 * Flags:
 *   --i-approve-persistent-install              Day-2 LocalService install + ready bootstrap
 *   --i-approve-personal-bitwarden-agent-resolve  personal Bitwarden smoke after/ besides Day-2
 *   --skip-day2                                 skip Day-2 path
 *   --uninstall-after                           uninstall persistent service on exit
 *
 * authorization_ready comes only from Day-2 compose when Day-2 runs.
 * Personal vault unlock never sets authorization_ready=true.
 * Helper stays vault-free. Company/org remain forbidden.
 */
import { spawn } from 'node:child_process';
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const APPROVE_INSTALL = process.argv.includes('--i-approve-persistent-install');
const APPROVE_PERSONAL = process.argv.includes('--i-approve-personal-bitwarden-agent-resolve');
const SKIP_DAY2 = process.argv.includes('--skip-day2');
const UNINSTALL_AFTER = process.argv.includes('--uninstall-after');

function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

function runNpm(script, args = []) {
  return new Promise((resolve) => {
    const child = spawn(
      process.platform === 'win32' ? 'npm.cmd' : 'npm',
      ['run', script, '--', ...args],
      {
        cwd: root,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: process.env,
        shell: process.platform === 'win32',
      },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

if (!APPROVE_INSTALL && !APPROVE_PERSONAL) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    note: 'Pass --i-approve-persistent-install and/or --i-approve-personal-bitwarden-agent-resolve',
    authorization_ready: false,
    helper_vault_free: true,
  });
  process.exit(1);
}

if (process.platform !== 'win32') {
  emit({
    ok: false,
    code: 'unsupported_platform',
    authorization_ready: false,
    helper_vault_free: true,
  });
  process.exit(1);
}

let day2Ok = !APPROVE_INSTALL || SKIP_DAY2;
let personalOk = !APPROVE_PERSONAL;
let authorizationReady = false;

if (APPROVE_INSTALL && !SKIP_DAY2) {
  emit({ kind: 'day2', started: true });
  const args = ['--i-approve-persistent-install'];
  if (UNINSTALL_AFTER) args.push('--uninstall-after');
  // Short-lived: use authorization-ready bootstrap once rather than keep-alive.
  const result = await runNpm('live:windows-authorization-ready', args);
  // Prefer last JSON line.
  const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean);
  let last = null;
  for (const line of lines) {
    try { last = JSON.parse(line); } catch { /* ignore */ }
  }
  authorizationReady = last?.authorization_ready === true ||
    (last?.kind === 'bootstrap' && last?.authorization_ready === true);
  day2Ok = result.code === 0 && authorizationReady === true;
  emit({
    kind: 'day2',
    ok: day2Ok,
    exit_code: result.code,
    authorization_ready: authorizationReady,
  });
  if (!day2Ok) {
    emit({
      ok: false,
      code: 'day2_failed',
      authorization_ready: false,
      helper_vault_free: true,
    });
    process.exit(1);
  }
}

if (APPROVE_PERSONAL) {
  emit({ kind: 'personal_bitwarden', started: true });
  const result = await runNpm('live:personal-bitwarden', [
    '--i-approve-personal-bitwarden-agent-resolve',
  ]);
  const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean);
  let last = null;
  for (const line of lines) {
    try { last = JSON.parse(line); } catch { /* ignore */ }
  }
  personalOk = result.code === 0 && last?.ok === true;
  emit({
    kind: 'personal_bitwarden',
    ok: personalOk,
    exit_code: result.code,
    live_secret_resolved: last?.live_secret_resolved === true,
    account_email_digest: typeof last?.account_email_digest === 'string'
      ? last.account_email_digest
      : undefined,
    authorization_ready: false,
    company_vault_forbidden: true,
    organization_vault_forbidden: true,
    helper_vault_free: true,
  });
  if (!personalOk) {
    emit({
      ok: false,
      code: 'personal_bitwarden_failed',
      authorization_ready: authorizationReady === true,
      helper_vault_free: true,
    });
    process.exit(1);
  }
}

emit({
  ok: day2Ok && personalOk,
  day2_ok: day2Ok,
  personal_bitwarden_ok: personalOk,
  authorization_ready: authorizationReady === true,
  company_vault_forbidden: true,
  organization_vault_forbidden: true,
  helper_vault_free: true,
  note: 'Laptop-ready path complete. Personal unlock does not set authorization_ready.',
});
process.exit(0);
