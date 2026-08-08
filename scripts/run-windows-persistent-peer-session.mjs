import process from 'node:process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { publishWindowsHelperServiceBinary } from '../src/windows-helper-publish.mjs';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import { collectWindowsPersistentPeerSession } from '../src/windows-persistent-peer-session.mjs';

/**
 * Operator-facing Phase 9d collector.
 *
 * Read-only peer session (no UAC). A complete different-principal result needs
 * a running fixed LocalService and a complete Phase 9c ACL matrix. Example:
 *   npm run live:windows-persistent -- install
 *   npm run live:windows-persistent-peer-session
 *   npm run live:windows-persistent -- uninstall
 * Never sets authorization_ready=true; operational wire-up is Phase 9e.
 */

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exit(code);
}

if (process.platform !== 'win32') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
}

const published = await publishWindowsHelperServiceBinary();
const layout = buildWindowsHelperLayoutPlan(buildWindowsServiceBoundaryPlan({
  platform: 'win32',
  binarySha256: published.sha256,
  binaryByteLength: published.byteLength,
}), { layout_mode: 'persistent' });
const staging = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-peer-run-'));
const helperPath = path.join(staging, 'BitwardenAgentCredentialBridgeHelper.exe');
try {
  await fs.writeFile(helperPath, published.bytes, { flag: 'wx' });
  const { report } = await collectWindowsPersistentPeerSession(layout, {
    helperExecutablePath: helperPath,
  });
  emit({
    ok: report.peer_authorization_complete === true,
    ...report,
    peer: report.peer,
  }, report.peer_authorization_complete ? 0 : 1);
} catch (error) {
  const code = error && typeof error.code === 'string' ? error.code : 'collector_failed';
  emit({ ok: false, code, authorization_ready: false }, 1);
} finally {
  await fs.rm(staging, { recursive: true, force: true }).catch(() => {});
}
