import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsServiceLifecycleGate } from '../src/windows-service-lifecycle-gate.mjs';
import { evaluateLiveCollectorResult, brandWindowsServiceLifecycleLiveReportForHarness } from '../src/windows-service-lifecycle-live.mjs';
import { evaluateWindowsServiceInstallGate } from '../src/windows-service-install-gate.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import {
  buildWindowsPersistentServiceLifecyclePlan,
  buildWindowsPersistentServiceUninstallPlan,
  evaluateWindowsPersistentServiceLifecycleReport,
  isWindowsPersistentServiceLifecyclePlan,
  WindowsPersistentServiceLifecycleError,
} from '../src/windows-persistent-service-lifecycle.mjs';

function liveGate() {
  const gate = buildWindowsServiceLifecycleGate(buildWindowsServiceBoundaryPlan({
    platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
  }));
  const live = brandWindowsServiceLifecycleLiveReportForHarness(evaluateLiveCollectorResult(gate, {
    schema_version: 1,
    terminal_outcome: 'denial_verified',
    events: [
      ...gate.pre_mutation_steps,
      ...gate.mutation_steps,
      ...gate.always_cleanup_steps,
    ].map((step) => ({ step, status: 'verified' })),
    provenance: {
      schema_version: 1,
      elevated_token_verified: true,
      local_only_collection: true,
      retained_handle_binding_complete: true,
      path_reacquisition_absent: true,
      value_free_emission_verified: true,
      stderr_absent: true,
      gate_step_surface_matched: true,
      cleanup_finally_bound: true,
      uac_consent_observed: true,
      admin_group_present: true,
      high_integrity_reported: true,
    },
  }));
  return evaluateWindowsServiceInstallGate(gate, live, {
    schema_version: 1,
    service_present: false,
    account_local_service: false,
    demand_start: false,
    win32_own_process: false,
    service_sid_unrestricted: false,
    caller_service_control_denied: false,
    binary_binding_verified: false,
    binary_chain_reparse_free: false,
    binary_owner_trusted: false,
    caller_binary_control_denied: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  });
}

describe('Windows persistent service lifecycle', () => {
  it('plans persistent install only with an eligible install gate', () => {
    const boundary = buildWindowsServiceBoundaryPlan({
      platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
    });
    const layout = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'persistent' });
    const plan = buildWindowsPersistentServiceLifecyclePlan(layout, liveGate());
    assert.equal(isWindowsPersistentServiceLifecyclePlan(plan), true);
    assert.equal(plan.install_gate_eligible, true);
    assert.equal(plan.authorization_ready, false);
    assert.equal(plan.helper_vault_free, true);

    const installed = evaluateWindowsPersistentServiceLifecycleReport(plan, {
      schema_version: 1,
      operation: 'install',
      verified: true,
      service_present: true,
      absence_proven: false,
      collision_detected: false,
    });
    assert.equal(installed.ok, true);
    assert.equal(installed.authorization_ready, false);

    const gone = evaluateWindowsPersistentServiceLifecycleReport(plan, {
      schema_version: 1,
      operation: 'uninstall',
      verified: true,
      service_present: false,
      absence_proven: true,
      collision_detected: false,
    });
    assert.equal(gone.ok, true);

    const uninstallOnly = buildWindowsPersistentServiceUninstallPlan(layout);
    assert.equal(uninstallOnly.install_gate_eligible, false);
    assert.equal(uninstallOnly.terminal_code, 'persistent_uninstall_plan_ready');
    const collided = evaluateWindowsPersistentServiceLifecycleReport(uninstallOnly, {
      schema_version: 1,
      operation: 'uninstall',
      verified: false,
      service_present: true,
      absence_proven: false,
      collision_detected: true,
    });
    assert.equal(collided.ok, false);
    assert.equal(collided.terminal_code, 'persistent_collision_rejected');
  });

  it('rejects collisions and ineligible gates', () => {
    const boundary = buildWindowsServiceBoundaryPlan({
      platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
    });
    const disposable = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'disposable' });
    assert.throws(
      () => buildWindowsPersistentServiceLifecyclePlan(disposable, liveGate()),
      (error) => error instanceof WindowsPersistentServiceLifecycleError,
    );
  });
});
