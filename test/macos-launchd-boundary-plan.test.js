import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildMacosLaunchdBoundaryPlan,
  isMacosLaunchdBoundaryPlan,
  MacosLaunchdBoundaryPlanError,
} from '../src/macos-launchd-boundary-plan.mjs';

function valid(overrides = {}) {
  return {
    platform: 'darwin',
    serviceManager: 'launchd-system',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
    designatedRequirementSha256: 'b'.repeat(64),
    plistSha256: 'c'.repeat(64),
    ...overrides,
  };
}

describe('macOS launchd distinct-writer boundary plan', () => {
  it('builds a fixed value-free non-executable system-helper contract', () => {
    const plan = buildMacosLaunchdBoundaryPlan(valid());
    assert.equal(isMacosLaunchdBoundaryPlan(plan), true);
    assert.equal(plan.runtime_profile, 'launchd-system');
    assert.equal(plan.service.domain, 'system');
    assert.equal(plan.service.launch_agent_forbidden, true);
    assert.equal(plan.service.gui_domain_forbidden, true);
    assert.equal(plan.service.stable_distinct_euid_required, true);
    assert.equal(plan.service.network_access_forbidden, true);
    assert.equal(plan.service.vault_access_forbidden, true);
    assert.equal(plan.service.keychain_access_forbidden, true);
    assert.equal(plan.ipc.transport, 'macos_xpc_mach_service');
    assert.equal(plan.ipc.peer_audit_token_matches_authorizing_caller_required, true);
    assert.equal(plan.target_access.ordinary_user_home_target_forbidden, true);
    assert.equal(plan.mutation_authorized, false);
    assert.equal(plan.live_test_executed, false);
    assert.equal(plan.install_gate_eligible, false);
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.ipc), true);

    const serialized = JSON.stringify(plan);
    for (const forbidden of ['~/Library', '/Users/', 'launchctl ', 'sudo ', 'security ', 'password_value', 'credential_ref']) {
      assert.equal(serialized.includes(forbidden), false, `must not emit ${forbidden}`);
    }
  });

  it('binds the reviewed binary and designated requirement digests exactly', () => {
    const plan = buildMacosLaunchdBoundaryPlan(valid({
      binarySha256: 'c'.repeat(64),
      binaryByteLength: 64 * 1024 * 1024,
      designatedRequirementSha256: 'd'.repeat(64),
      plistSha256: 'e'.repeat(64),
    }));
    assert.equal(plan.binary.sha256, 'c'.repeat(64));
    assert.equal(plan.binary.byte_length, 64 * 1024 * 1024);
    assert.equal(plan.binary.designated_requirement_sha256, 'd'.repeat(64));
    assert.equal(plan.daemon.sha256, 'e'.repeat(64));
    assert.equal(plan.binary.installed_code_requirement_reverified_required, true);
  });

  it('fails closed for user launchd domains, other platforms, and invalid bindings', () => {
    for (const input of [
      valid({ platform: 'linux' }),
      valid({ serviceManager: 'launchd-user' }),
      valid({ serviceManager: 'launchd-gui' }),
      valid({ binarySha256: 'A'.repeat(64) }),
      valid({ designatedRequirementSha256: 'b'.repeat(63) }),
      valid({ plistSha256: 'C'.repeat(64) }),
      valid({ binaryByteLength: 0 }),
      valid({ binaryByteLength: 64 * 1024 * 1024 + 1 }),
    ]) {
      assert.throws(() => buildMacosLaunchdBoundaryPlan(input), MacosLaunchdBoundaryPlanError);
    }
  });

  it('rejects extras, missing fields, accessors, proxies, and prototype pollution', () => {
    const missing = valid();
    delete missing.serviceManager;
    const accessor = valid();
    Object.defineProperty(accessor, 'serviceManager', { enumerable: true, get: () => 'launchd-system' });
    for (const input of [
      null,
      missing,
      { ...valid(), label: 'caller.selected' },
      accessor,
      new Proxy(valid(), {}),
      Object.assign(Object.create(null), valid()),
    ]) {
      assert.throws(
        () => buildMacosLaunchdBoundaryPlan(input),
        (error) => error instanceof MacosLaunchdBoundaryPlanError && error.code === 'invalid_input',
      );
    }
  });

  it('brands only in-process plans and rejects clones as capabilities', () => {
    const plan = buildMacosLaunchdBoundaryPlan(valid());
    assert.equal(isMacosLaunchdBoundaryPlan(plan), true);
    assert.equal(isMacosLaunchdBoundaryPlan(structuredClone(plan)), false);
    assert.equal(isMacosLaunchdBoundaryPlan({ ...plan }), false);
    assert.equal(isMacosLaunchdBoundaryPlan(new Proxy(plan, {})), false);
  });
});
