#!/usr/bin/env node
/**
 * Phase 10b: bootstrap Windows authorization_ready from branded live evidence.
 *
 * Exit 0 only when compose reports authorization_ready===true (never hardcoded).
 *
 * Flags:
 *   --i-approve-persistent-install  run elevated persistent install first
 *   --with-operational-bridge       start fake-vault operational bridge after ready
 *   --keep-refresh                  after ready, enter Phase 10a refresh loop
 *   --skip-apply                    do not attempt vault-free first-install apply
 *   --uninstall-after               uninstall persistent service before exit
 *
 * Personal/company Bitwarden remain forbidden. Helper stays vault-free.
 * Agent-readable surface non-disclosure is the exposure-test contract; this
 * path does not claim same-user memory isolation.
 */
import { spawn } from 'node:child_process';
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runWindowsAuthorizationReadyBootstrap,
  WindowsAuthorizationReadyBootstrapError,
} from '../src/windows-authorization-ready-bootstrap.mjs';
import {
  startWindowsAuthorizationEvidenceRefresh,
} from '../src/windows-authorization-evidence-refresh.mjs';
import { createLiveWindowsAuthorizationEvidenceCollectors } from '../src/windows-authorization-evidence-live-collectors.mjs';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
} from '../src/operational-bridge.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const APPROVE_INSTALL = process.argv.includes('--i-approve-persistent-install');
const WITH_BRIDGE = process.argv.includes('--with-operational-bridge');
const KEEP_REFRESH = process.argv.includes('--keep-refresh');
const SKIP_APPLY = process.argv.includes('--skip-apply');
const UNINSTALL_AFTER = process.argv.includes('--uninstall-after');

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

let bridge = null;
let refresh = null;
let collectors = null;
let stopping = false;

async function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  if (refresh !== null) {
    await refresh.stop().catch(() => {});
    refresh = null;
  }
  if (bridge !== null) {
    await bridge.close().catch(() => {});
    bridge = null;
  }
  if (collectors !== null && typeof collectors.dispose === 'function') {
    await collectors.dispose().catch(() => {});
    collectors = null;
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

  const result = await runWindowsAuthorizationReadyBootstrap({
    skipApply: SKIP_APPLY,
  });

  emit({
    kind: 'bootstrap',
    ok: result.authorization_ready === true,
    authorization_ready: result.authorization_ready === true,
    terminal_code: result.terminal_code,
    apply_attempted: result.apply_attempted === true,
    apply_succeeded: result.apply_succeeded === true,
    helper_vault_free: result.helper_vault_free === true,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    mutation_authorized: false,
    collector_error: result.collector_error === true,
  });

  if (result.authorization_ready !== true) {
    await shutdown(1);
    return;
  }

  if (WITH_BRIDGE) {
    const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    bridge = await startOperationalBridge({
      repoRoot: root,
      bindings,
      productionAuthorizationEvidence: result.evidence,
    });
    emit({
      kind: 'operational_bridge',
      harness_ready: bridge.harness_ready === true,
      authorization_ready: bridge.authorization_ready === true,
      operational_authorization_wired: bridge.operational_authorization_wired === true,
      production_authorization_terminal_code: bridge.production_authorization_terminal_code,
    });
  }

  if (KEEP_REFRESH) {
    collectors = createLiveWindowsAuthorizationEvidenceCollectors();
    refresh = startWindowsAuthorizationEvidenceRefresh({
      collectors,
      onSnapshot: (snapshot) => {
        emit({ kind: 'refresh', ...snapshot });
      },
    });
    emit({ kind: 'refresh_started', authorization_ready: true });
    return;
  }

  await shutdown(0);
}

try {
  await main();
} catch (error) {
  const code = error instanceof WindowsAuthorizationReadyBootstrapError
    ? error.code
    : (error && typeof error === 'object' && typeof error.code === 'string'
      ? error.code
      : 'bootstrap_failed');
  emit({
    ok: false,
    code,
    authorization_ready: false,
    mutation_authorized: false,
  });
  await shutdown(1);
}
