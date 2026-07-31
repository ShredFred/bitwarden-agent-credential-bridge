import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildLinuxSystemdBoundaryPlan,
  isLinuxSystemdBoundaryPlan,
  LinuxSystemdBoundaryPlanError,
} from '../src/linux-systemd-boundary-plan.mjs';

function valid(overrides = {}) {
  return {
    platform: 'linux',
    serviceManager: 'systemd-system',
    binarySha256: 'a'.repeat(64),
    binaryByteLength: 4096,
    ...overrides,
  };
}

describe('Linux systemd distinct-writer boundary plan', () => {
  it('builds a fixed, value-free, non-executable system-service contract', () => {
    const plan = buildLinuxSystemdBoundaryPlan(valid());
    assert.equal(isLinuxSystemdBoundaryPlan(plan), true);
    assert.equal(plan.runtime_profile, 'systemd-system');
    assert.equal(plan.service.unit_name, 'bitwarden-agent-credential-bridge-helper.service');
    assert.equal(plan.service.account_kind, 'static_system_user');
    assert.equal(plan.service.dynamic_user_forbidden, true);
    assert.equal(plan.service.password_required, false);
    assert.equal(plan.ipc.transport, 'linux_af_unix_stream');
    assert.equal(plan.ipc.abstract_socket_forbidden, true);
    assert.equal(plan.ipc.caller_socket_replace_denied_required, true);
    assert.equal(plan.binary.parent_chain_caller_write_denied_required, true);
    assert.equal(plan.binary.retained_readonly_fd_identity_binding_required, true);
    assert.equal(plan.units.daemon_reload_then_fragment_path_reverified_required, true);
    assert.equal(plan.units.daemon_reload_then_drop_in_paths_empty_reverified_required, true);
    assert.equal(plan.sandbox.empty_capability_bounding_set_required, true);
    assert.equal(plan.service.network_access_forbidden, true);
    assert.equal(plan.sandbox.private_network_required, true);
    assert.equal(plan.sandbox.restrict_address_families_exact_af_unix_required, true);
    assert.equal(plan.sandbox.ip_address_deny_any_required, true);
    assert.equal(plan.sandbox.network_sandbox_enforcement_reverified_required, true);
    assert.equal(plan.mutation_authorized, false);
    assert.equal(plan.live_test_executed, false);
    assert.equal(plan.install_gate_eligible, false);
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.ipc), true);

    const serialized = JSON.stringify(plan);
    for (const forbidden of ['ExecStart=', '/etc/', '/run/', '/usr/', 'sudo ', 'systemctl ', 'password":']) {
      assert.equal(serialized.includes(forbidden), false, `must not emit ${forbidden}`);
    }
  });

  it('binds the reviewed binary digest and bounded byte length exactly', () => {
    const plan = buildLinuxSystemdBoundaryPlan(valid({
      binarySha256: 'b'.repeat(64), binaryByteLength: 64 * 1024 * 1024,
    }));
    assert.deepEqual(plan.binary.sha256, 'b'.repeat(64));
    assert.equal(plan.binary.byte_length, 64 * 1024 * 1024);
    for (const input of [
      valid({ binarySha256: 'A'.repeat(64) }),
      valid({ binarySha256: 'a'.repeat(63) }),
      valid({ binaryByteLength: 0 }),
      valid({ binaryByteLength: 64 * 1024 * 1024 + 1 }),
      valid({ binaryByteLength: 1.5 }),
    ]) {
      assert.throws(
        () => buildLinuxSystemdBoundaryPlan(input),
        (error) => error instanceof LinuxSystemdBoundaryPlanError &&
          error.code === 'invalid_binary_binding',
      );
    }
  });

  it('fails closed for non-systemd, user-manager, non-Linux, and ambiguous profiles', () => {
    for (const input of [
      valid({ platform: 'darwin' }),
      valid({ serviceManager: 'systemd-user' }),
      valid({ serviceManager: 'openrc' }),
      valid({ serviceManager: '' }),
    ]) {
      assert.throws(
        () => buildLinuxSystemdBoundaryPlan(input),
        (error) => error instanceof LinuxSystemdBoundaryPlanError &&
          error.code === 'unsupported_runtime_profile',
      );
    }
  });

  it('rejects extras, missing fields, accessors, proxies, and prototype pollution', () => {
    const missing = valid();
    delete missing.serviceManager;
    const accessor = valid();
    Object.defineProperty(accessor, 'serviceManager', { enumerable: true, get: () => 'systemd-system' });
    for (const input of [
      null,
      missing,
      { ...valid(), unitPath: '/tmp/untrusted' },
      accessor,
      new Proxy(valid(), {}),
      Object.assign(Object.create(null), valid()),
    ]) {
      assert.throws(
        () => buildLinuxSystemdBoundaryPlan(input),
        (error) => error instanceof LinuxSystemdBoundaryPlanError && error.code === 'invalid_input',
      );
    }

    const prior = Object.getOwnPropertyDescriptor(Object.prototype, 'serviceManager');
    let getterCalls = 0;
    Object.defineProperty(Object.prototype, 'serviceManager', {
      configurable: true, get() { getterCalls += 1; return 'systemd-user'; },
    });
    try {
      const plan = buildLinuxSystemdBoundaryPlan(valid());
      assert.equal(plan.runtime_profile, 'systemd-system');
      assert.equal(getterCalls, 0);
    } finally {
      if (prior === undefined) delete Object.prototype.serviceManager;
      else Object.defineProperty(Object.prototype, 'serviceManager', prior);
    }
  });

  it('brands only in-process plans and rejects clones as capabilities', () => {
    const plan = buildLinuxSystemdBoundaryPlan(valid());
    assert.equal(isLinuxSystemdBoundaryPlan(plan), true);
    assert.equal(isLinuxSystemdBoundaryPlan(structuredClone(plan)), false);
    assert.equal(isLinuxSystemdBoundaryPlan({ ...plan }), false);
    assert.equal(isLinuxSystemdBoundaryPlan(new Proxy(plan, {})), false);
  });
});
