#!/usr/bin/env node
/**
 * Phase 10a Day-2 authorization evidence refresh (foreground).
 *
 * Assumes a persistent LocalService helper is already installed. Periodically
 * re-collects branded 9b/9c/9d evidence and recomposes Phase 9e readiness.
 * Does not elevate, install, or uninstall. Uninstall remains explicit:
 *   npm run live:windows-persistent -- uninstall
 *
 * Optional --with-operational-bridge starts/restarts the fake-vault operational
 * bridge with the latest productionAuthorizationEvidence each tick.
 *
 * Agent-readable surface non-disclosure is the exposure-test contract; this
 * loop does not claim same-user memory isolation.
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  startWindowsAuthorizationEvidenceRefresh,
  WindowsAuthorizationEvidenceRefreshError,
} from '../src/windows-authorization-evidence-refresh.mjs';
import { createLiveWindowsAuthorizationEvidenceCollectors } from '../src/windows-authorization-evidence-live-collectors.mjs';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
} from '../src/operational-bridge.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const WITH_BRIDGE = process.argv.includes('--with-operational-bridge');
const intervalArg = process.argv.find((arg) => arg.startsWith('--interval-ms='));
const intervalMs = intervalArg === undefined
  ? undefined
  : Number(intervalArg.slice('--interval-ms='.length));

function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
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

let collectors;
let refresh;
let bridge = null;
let stopping = false;

async function replaceBridge(cycle) {
  if (!WITH_BRIDGE) return;
  if (bridge !== null) {
    await bridge.close().catch(() => {});
    bridge = null;
  }
  const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
  bridge = await startOperationalBridge({
    repoRoot: root,
    bindings,
    productionAuthorizationEvidence: cycle.evidence,
  });
  emit({
    kind: 'operational_bridge',
    harness_ready: bridge.harness_ready === true,
    authorization_ready: bridge.authorization_ready === true,
    operational_authorization_wired: bridge.operational_authorization_wired === true,
    production_authorization_terminal_code: bridge.production_authorization_terminal_code,
  });
}

async function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  if (refresh !== undefined) {
    await refresh.stop().catch(() => {});
  }
  if (bridge !== null) {
    await bridge.close().catch(() => {});
    bridge = null;
  }
  if (collectors !== undefined && typeof collectors.dispose === 'function') {
    await collectors.dispose().catch(() => {});
  }
  process.exit(code);
}

process.once('SIGINT', () => {
  void shutdown(0);
});
process.once('SIGTERM', () => {
  void shutdown(0);
});

try {
  collectors = createLiveWindowsAuthorizationEvidenceCollectors();
  refresh = startWindowsAuthorizationEvidenceRefresh({
    collectors,
    intervalMs,
    async onSnapshot(snapshot, cycle) {
      emit({ kind: 'authorization_refresh', ...snapshot });
      await replaceBridge(cycle);
    },
  });
  emit({
    kind: 'authorization_refresh_started',
    with_operational_bridge: WITH_BRIDGE,
    interval_ms: refresh.intervalMs,
    note: 'Foreground Day-2 refresh; Ctrl+C to stop. Uninstall remains explicit.',
  });
} catch (error) {
  const code = error instanceof WindowsAuthorizationEvidenceRefreshError
    ? error.code
    : (error && typeof error === 'object' && typeof error.code === 'string'
      ? error.code
      : 'startup_failed');
  emit({
    ok: false,
    code,
    authorization_ready: false,
    mutation_authorized: false,
  });
  await shutdown(1);
}
