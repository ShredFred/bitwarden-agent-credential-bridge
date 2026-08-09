import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildCompleteOperationalAuthorizationEvidenceForHarness,
  buildIncompleteOperationalAuthorizationEvidence,
} from '../src/windows-operational-authorization.mjs';
import {
  startWindowsDay2OperatorSession,
  WindowsDay2OperatorSessionError,
} from '../src/windows-day2-operator-session.mjs';

function collectorsFromEvidence(evidence) {
  return {
    async buildInstallGateAndLayout() {
      return {
        installGateReport: evidence.installGateReport,
        layoutPlan: evidence.layoutPlan,
      };
    },
    async collectHandleBound() { return evidence.handleBoundEvidence; },
    async collectTargetAcl() { return evidence.targetAclEvidence; },
    async collectPeer() { return evidence.peerEvidence; },
  };
}

describe('Windows Day-2 operator session (Phase 10c)', () => {
  it('starts bridge and refresh only after branded ready', async () => {
    const evidence = buildCompleteOperationalAuthorizationEvidenceForHarness();
    const events = [];
    let bridgeStarts = 0;
    const timers = [];

    const session = await startWindowsDay2OperatorSession({
      platform: 'win32',
      repoRoot: 'F:\\fake-repo',
      collectors: collectorsFromEvidence(evidence),
      skipApply: true,
      intervalMs: 15_000,
      setIntervalFn: (fn, ms) => {
        timers.push({ fn, ms });
        return { unref() {} };
      },
      clearIntervalFn: () => {},
      async loadBindings() {
        return Object.freeze({ profile: 'test', services: [] });
      },
      async startBridge(opts) {
        bridgeStarts += 1;
        assert.equal(opts.productionAuthorizationEvidence, evidence);
        return {
          harness_ready: true,
          authorization_ready: true,
          operational_authorization_wired: true,
          production_authorization_terminal_code: 'production_authorization_ready',
          async close() {},
        };
      },
      async bootstrap() {
        return {
          authorization_ready: true,
          terminal_code: 'production_authorization_ready',
          apply_attempted: false,
          apply_succeeded: false,
          helper_vault_free: true,
          collector_error: false,
          evidence,
        };
      },
      startRefresh({ onSnapshot, collectors, intervalMs }) {
        assert.equal(intervalMs, 15_000);
        assert.equal(typeof collectors.collectHandleBound, 'function');
        let stopped = false;
        // Immediate first tick like production refresh.
        void Promise.resolve().then(async () => {
          if (stopped) return;
          await onSnapshot({
            schema_version: 1,
            platform: 'win32',
            refresh_generation: 1,
            evidence_complete: true,
            authorization_ready: true,
            terminal_code: 'production_authorization_ready',
            helper_vault_free: true,
            personal_vault_forbidden: true,
            company_vault_forbidden: true,
            mutation_authorized: false,
            operational_bridge_unwired: false,
            collector_error: false,
          }, { evidence, report: { authorization_ready: true }, collector_error: false });
        });
        return {
          intervalMs,
          snapshot: () => ({ authorization_ready: true }),
          async stop() { stopped = true; },
        };
      },
      onEvent: (event) => { events.push(event); },
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(events.some((e) => e.kind === 'bootstrap' && e.authorization_ready === true));
    assert.ok(events.some((e) => e.kind === 'operational_bridge'));
    assert.ok(events.some((e) => e.kind === 'day2_started'));
    assert.ok(bridgeStarts >= 1);
    await session.stop();
  });

  it('emits authorization_drift and replaces bridge when ready becomes false', async () => {
    const complete = buildCompleteOperationalAuthorizationEvidenceForHarness();
    const incomplete = buildIncompleteOperationalAuthorizationEvidence();
    const events = [];
    let onSnapshot = null;
    let bridgeEvidence = null;

    const session = await startWindowsDay2OperatorSession({
      platform: 'win32',
      repoRoot: 'F:\\fake-repo',
      collectors: collectorsFromEvidence(complete),
      skipApply: true,
      intervalMs: 15_000,
      setIntervalFn: () => ({ unref() {} }),
      clearIntervalFn: () => {},
      async loadBindings() {
        return Object.freeze({ profile: 'test', services: [] });
      },
      async startBridge(opts) {
        bridgeEvidence = opts.productionAuthorizationEvidence;
        const ready = bridgeEvidence === complete;
        return {
          harness_ready: true,
          authorization_ready: ready,
          operational_authorization_wired: true,
          production_authorization_terminal_code: ready
            ? 'production_authorization_ready'
            : 'production_authorization_incomplete',
          async close() {},
        };
      },
      async bootstrap() {
        return {
          authorization_ready: true,
          terminal_code: 'production_authorization_ready',
          apply_attempted: false,
          apply_succeeded: false,
          helper_vault_free: true,
          collector_error: false,
          evidence: complete,
        };
      },
      startRefresh(opts) {
        onSnapshot = opts.onSnapshot;
        return {
          intervalMs: opts.intervalMs,
          snapshot: () => ({ authorization_ready: false }),
          async stop() {},
        };
      },
      onEvent: (event) => { events.push(event); },
    });

    await onSnapshot({
      schema_version: 1,
      platform: 'win32',
      refresh_generation: 2,
      evidence_complete: false,
      authorization_ready: false,
      terminal_code: 'production_authorization_incomplete',
      helper_vault_free: true,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
      mutation_authorized: false,
      operational_bridge_unwired: false,
      collector_error: false,
    }, { evidence: incomplete, report: { authorization_ready: false }, collector_error: false });

    assert.ok(events.some((e) => e.kind === 'authorization_drift' && e.authorization_ready === false));
    assert.equal(bridgeEvidence, incomplete);
    await session.stop();
  });

  it('rejects when bootstrap is not ready', async () => {
    await assert.rejects(
      () => startWindowsDay2OperatorSession({
        platform: 'win32',
        repoRoot: 'F:\\fake-repo',
        collectors: collectorsFromEvidence(buildIncompleteOperationalAuthorizationEvidence()),
        async bootstrap() {
          return {
            authorization_ready: false,
            terminal_code: 'production_authorization_incomplete',
            apply_attempted: false,
            apply_succeeded: false,
            helper_vault_free: true,
            collector_error: false,
            evidence: buildIncompleteOperationalAuthorizationEvidence(),
          };
        },
        startRefresh() {
          throw new Error('must not start refresh');
        },
        async startBridge() {
          throw new Error('must not start bridge');
        },
        async loadBindings() {
          return {};
        },
      }),
      (error) => error instanceof WindowsDay2OperatorSessionError &&
        error.code === 'authorization_not_ready',
    );
  });

  it('rejects non-win32', async () => {
    await assert.rejects(
      () => startWindowsDay2OperatorSession({
        platform: 'darwin',
        repoRoot: '/tmp',
      }),
      (error) => error instanceof WindowsDay2OperatorSessionError &&
        error.code === 'unsupported_platform',
    );
  });
});
