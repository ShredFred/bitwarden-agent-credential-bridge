#!/usr/bin/env node
/**
 * Foreground operational disposable/dev multi-service bridge.
 *
 * Starts the tracked sample bindings with fake vault secrets, smokes each
 * service, then waits for SIGINT/SIGTERM. authorization_ready comes only from
 * the Phase 9e wired Phase 9a evaluator (absent evidence → false).
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
  OperationalBridgeError,
} from '../src/operational-bridge.mjs';
import { absentWindowsOperationalAuthorization } from '../src/windows-operational-authorization.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const bindingsPath = process.argv[2] ?? 'samples/operational/bindings.json';

function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

let bridge;
let stopping = false;

async function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  if (bridge) {
    await bridge.close().catch(() => {});
  }
  process.exitCode = code;
  process.exit(code);
}

process.once('SIGINT', () => {
  void shutdown(0);
});
process.once('SIGTERM', () => {
  void shutdown(0);
});

try {
  const bindings = await loadOperationalBindingsFile(root, bindingsPath);
  bridge = await startOperationalBridge({
    repoRoot: root,
    bindings,
  });
  const smoke = await bridge.smoke();
  const allOk = Object.values(smoke).every(Boolean);
  emit({
    ok: allOk,
    profile: bridge.profile,
    services: bridge.services.map((s) => ({
      alias: s.alias,
      credential_class: s.credential_class,
      baseUrl: s.baseUrl,
      ...(s.replayUrl ? { replayUrl: s.replayUrl } : {}),
    })),
    smoke,
    harness_ready: bridge.harness_ready === true && allOk,
    disposable_dev_ready: false,
    authorization_ready: bridge.authorization_ready,
    production_authorization_terminal_code: bridge.production_authorization_terminal_code,
    operational_authorization_wired: bridge.operational_authorization_wired === true,
    personal_vault_forbidden: bridge.personal_vault_forbidden === true,
    company_vault_forbidden: bridge.company_vault_forbidden === true,
    helper_vault_free: bridge.helper_vault_free === true,
    note: 'Foreground operational profile; press Ctrl+C to stop. DPAPI disposable smoke is a separate live command.',
  });
  if (!allOk) {
    await shutdown(1);
  }
} catch (error) {
  const code = error instanceof OperationalBridgeError ? error.code : 'startup_failed';
  emit({
    ok: false,
    code,
    harness_ready: false,
    disposable_dev_ready: false,
    authorization_ready: absentWindowsOperationalAuthorization().authorization_ready,
  });
  await shutdown(1);
}
