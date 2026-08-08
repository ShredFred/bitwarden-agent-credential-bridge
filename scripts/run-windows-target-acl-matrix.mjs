import process from 'node:process';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import { publishWindowsHelperServiceBinary } from '../src/windows-helper-publish.mjs';
import { collectWindowsTargetAclEvidence } from '../src/windows-target-acl-matrix.mjs';

/**
 * Operator-facing Phase 9c collector.
 *
 * Read-only: no UAC, install, ACL mutation, or Bitwarden access.
 * A complete matrix requires an already-present ProgramData root and a running
 * fixed LocalService (for example after
 * `npm run live:windows-persistent -- install` and a vault-free first-install
 * apply that created the five targets). Uninstall afterward.
 * Never sets authorization_ready=true.
 */

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exit(code);
}

if (process.platform !== 'win32') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
}

try {
  const published = await publishWindowsHelperServiceBinary();
  const layout = buildWindowsHelperLayoutPlan(buildWindowsServiceBoundaryPlan({
    platform: 'win32',
    binarySha256: published.sha256,
    binaryByteLength: published.byteLength,
  }), { layout_mode: 'persistent' });
  const { report } = await collectWindowsTargetAclEvidence(layout);
  emit({
    ok: report.target_acl_evidence_complete === true,
    ...report,
  }, report.target_acl_evidence_complete ? 0 : 1);
} catch (error) {
  const code = error && typeof error.code === 'string' ? error.code : 'collector_failed';
  emit({ ok: false, code, authorization_ready: false }, 1);
}
