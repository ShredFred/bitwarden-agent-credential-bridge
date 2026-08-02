import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import {
  buildWindowsHelperLayoutPlan,
  isWindowsHelperLayoutPlan,
  WindowsHelperLayoutPlanError,
} from '../src/windows-helper-layout-plan.mjs';

function boundary() {
  return buildWindowsServiceBoundaryPlan({
    platform: 'win32', binarySha256: 'c'.repeat(64), binaryByteLength: 8192,
  });
}

describe('Windows helper layout plan', () => {
  it('builds disposable and persistent ProgramData-class contracts', () => {
    const plan = boundary();
    const disposable = buildWindowsHelperLayoutPlan(plan, { layout_mode: 'disposable' });
    const persistent = buildWindowsHelperLayoutPlan(plan, { layout_mode: 'persistent' });
    assert.equal(isWindowsHelperLayoutPlan(disposable), true);
    assert.equal(isWindowsHelperLayoutPlan({ ...disposable }), false);
    assert.equal(disposable.layout_mode, 'disposable');
    assert.equal(disposable.disposable_cleanup_required, true);
    assert.equal(disposable.persistent_uninstall_proof_required, false);
    assert.equal(disposable.ordinary_user_profile_root_forbidden, true);
    assert.equal(disposable.local_app_data_root_forbidden, true);
    assert.equal(disposable.program_data_class_root_required, true);
    assert.equal(disposable.mutation_authorized, false);
    assert.equal(persistent.layout_mode, 'persistent');
    assert.equal(persistent.persistent_uninstall_proof_required, true);
    assert.equal(persistent.disposable_cleanup_required, false);
    assert.equal(persistent.binary.sha256, 'c'.repeat(64));
    assert.equal(JSON.stringify(disposable).includes('C:\\'), false);
    assert.equal(JSON.stringify(disposable).toLowerCase().includes('localappdata'), false);
  });

  it('rejects forged boundary plans and unknown layout modes', () => {
    assert.throws(
      () => buildWindowsHelperLayoutPlan({ schema_version: 1 }, { layout_mode: 'disposable' }),
      (error) => error instanceof WindowsHelperLayoutPlanError &&
        error.code === 'invalid_boundary_plan',
    );
    assert.throws(
      () => buildWindowsHelperLayoutPlan(boundary(), { layout_mode: 'user_profile' }),
      (error) => error instanceof WindowsHelperLayoutPlanError &&
        error.code === 'unsupported_layout_mode',
    );
    assert.throws(
      () => buildWindowsHelperLayoutPlan(boundary(), {
        layout_mode: 'disposable',
        path: 'C:\\Windows',
      }),
      (error) => error instanceof WindowsHelperLayoutPlanError &&
        error.code === 'invalid_input',
    );
  });
});
