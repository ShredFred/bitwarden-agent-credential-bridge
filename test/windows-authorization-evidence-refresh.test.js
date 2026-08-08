import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildCompleteOperationalAuthorizationEvidenceForHarness,
  buildIncompleteOperationalAuthorizationEvidence,
  composeWindowsOperationalAuthorization,
} from '../src/windows-operational-authorization.mjs';
import {
  clampAuthorizationRefreshIntervalMs,
  refreshWindowsAuthorizationEvidenceOnce,
  startWindowsAuthorizationEvidenceRefresh,
  WindowsAuthorizationEvidenceRefreshError,
} from '../src/windows-authorization-evidence-refresh.mjs';

function collectorsFromBundle(bundle) {
  return {
    async buildInstallGateAndLayout() {
      return {
        installGateReport: bundle.installGateReport,
        layoutPlan: bundle.layoutPlan,
      };
    },
    async collectHandleBound() {
      return bundle.handleBoundEvidence;
    },
    async collectTargetAcl() {
      return bundle.targetAclEvidence;
    },
    async collectPeer() {
      return bundle.peerEvidence;
    },
  };
}

describe('Windows authorization evidence refresh (Phase 10a)', () => {
  it('clamps interval bounds and rejects non-integers', () => {
    assert.equal(clampAuthorizationRefreshIntervalMs(undefined), 60_000);
    assert.equal(clampAuthorizationRefreshIntervalMs(1), 15_000);
    assert.equal(clampAuthorizationRefreshIntervalMs(15_000), 15_000);
    assert.equal(clampAuthorizationRefreshIntervalMs(90_000), 90_000);
    assert.equal(clampAuthorizationRefreshIntervalMs(9_999_999), 3_600_000);
    assert.throws(
      () => clampAuthorizationRefreshIntervalMs(1.5),
      (error) => error instanceof WindowsAuthorizationEvidenceRefreshError &&
        error.code === 'invalid_interval_ms',
    );
  });

  it('composes incomplete evidence to authorization_ready false', async () => {
    const cycle = await refreshWindowsAuthorizationEvidenceOnce(
      collectorsFromBundle(buildIncompleteOperationalAuthorizationEvidence()),
    );
    assert.equal(cycle.collector_error, false);
    assert.equal(cycle.report.authorization_ready, false);
    assert.equal(cycle.report.mutation_authorized, false);
    assert.equal(cycle.report.operational_bridge_unwired, false);
  });

  it('composes complete harness evidence to authorization_ready true', async () => {
    const cycle = await refreshWindowsAuthorizationEvidenceOnce(
      collectorsFromBundle(buildCompleteOperationalAuthorizationEvidenceForHarness()),
    );
    assert.equal(cycle.collector_error, false);
    assert.equal(cycle.report.authorization_ready, true);
    assert.equal(cycle.report.terminal_code, 'production_authorization_ready');
    assert.equal(cycle.report.mutation_authorized, false);
  });

  it('fails closed to incomplete when a collector throws', async () => {
    const complete = buildCompleteOperationalAuthorizationEvidenceForHarness();
    const cycle = await refreshWindowsAuthorizationEvidenceOnce({
      async buildInstallGateAndLayout() {
        return {
          installGateReport: complete.installGateReport,
          layoutPlan: complete.layoutPlan,
        };
      },
      async collectHandleBound() {
        const error = new Error('boom');
        error.code = 'probe_failed';
        throw error;
      },
      async collectTargetAcl() {
        return complete.targetAclEvidence;
      },
      async collectPeer() {
        return complete.peerEvidence;
      },
    });
    assert.equal(cycle.collector_error, true);
    assert.equal(cycle.error_code, 'probe_failed');
    assert.equal(cycle.report.authorization_ready, false);
  });

  it('rejects forged collector shapes', async () => {
    await assert.rejects(
      () => refreshWindowsAuthorizationEvidenceOnce(/** @type {any} */ ({})),
      (error) => error instanceof WindowsAuthorizationEvidenceRefreshError &&
        error.code === 'invalid_collectors',
    );
  });

  it('runs manual ticks, increments generation, and stop clears the timer', async () => {
    const complete = buildCompleteOperationalAuthorizationEvidenceForHarness();
    const incomplete = buildIncompleteOperationalAuthorizationEvidence();
    let useComplete = false;
    const timers = [];
    const snapshots = [];

    const refresh = startWindowsAuthorizationEvidenceRefresh({
      collectors: {
        async buildInstallGateAndLayout() {
          const bundle = useComplete ? complete : incomplete;
          return {
            installGateReport: bundle.installGateReport,
            layoutPlan: bundle.layoutPlan,
          };
        },
        async collectHandleBound() {
          return (useComplete ? complete : incomplete).handleBoundEvidence;
        },
        async collectTargetAcl() {
          return (useComplete ? complete : incomplete).targetAclEvidence;
        },
        async collectPeer() {
          return (useComplete ? complete : incomplete).peerEvidence;
        },
      },
      intervalMs: 15_000,
      setIntervalFn: (fn, ms) => {
        const handle = { fn, ms, cleared: false };
        timers.push(handle);
        return handle;
      },
      clearIntervalFn: (handle) => {
        handle.cleared = true;
      },
      onSnapshot: (snapshot) => {
        snapshots.push(snapshot);
      },
    });

    const first = await refresh.tick();
    assert.equal(first.authorization_ready, false);
    assert.ok(first.refresh_generation >= 1);
    assert.equal(refresh.snapshot()?.authorization_ready, false);

    useComplete = true;
    const second = await refresh.tick();
    assert.equal(second.authorization_ready, true);
    assert.equal(second.evidence_complete, true);
    assert.equal(second.collector_error, false);
    assert.equal(second.mutation_authorized, false);
    assert.equal(second.personal_vault_forbidden, true);
    assert.ok(second.refresh_generation > first.refresh_generation);
    assert.equal(composeWindowsOperationalAuthorization(
      refresh.lastCycle().evidence,
    ).authorization_ready, true);

    assert.equal(timers.length, 1);
    assert.equal(timers[0].ms, 15_000);
    await refresh.stop();
    assert.equal(timers[0].cleared, true);
    assert.ok(snapshots.length >= 2);
  });
});
