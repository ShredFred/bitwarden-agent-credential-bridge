import process from 'node:process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { publishWindowsHelperServiceBinary } from '../src/windows-helper-publish.mjs';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { collectWindowsHandleBoundIdentityEvidence } from '../src/windows-handle-bound-identity.mjs';

/**
 * Operator-facing Phase 9b collector.
 *
 * Read-only: no elevation, install, start, or Bitwarden access.
 * For a complete identity result the fixed LocalService must already be
 * installed and running (for example after
 * `npm run live:windows-persistent -- install`). Uninstall afterward.
 * Never sets authorization_ready=true on the public report.
 */

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exit(code);
}

if (process.platform !== 'win32') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
}

const published = await publishWindowsHelperServiceBinary();
const plan = buildWindowsServiceBoundaryPlan({
  platform: 'win32',
  binarySha256: published.sha256,
  binaryByteLength: published.byteLength,
});
const staging = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-hbi-run-'));
const helperPath = path.join(staging, 'BitwardenAgentCredentialBridgeHelper.exe');
try {
  await fs.writeFile(helperPath, published.bytes, { flag: 'wx' });
  const { report } = await collectWindowsHandleBoundIdentityEvidence(plan, {
    helperExecutablePath: helperPath,
  });
  emit({
    ok: report.handle_bound_identity_complete === true,
    ...report,
  }, report.handle_bound_identity_complete ? 0 : 1);
} catch (error) {
  const code = error && typeof error.code === 'string' ? error.code : 'collector_failed';
  emit({ ok: false, code, authorization_ready: false }, 1);
} finally {
  await fs.rm(staging, { recursive: true, force: true }).catch(() => {});
}
