import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildCompleteOperationalAuthorizationEvidenceForHarness,
  buildIncompleteOperationalAuthorizationEvidence,
  composeWindowsOperationalAuthorization,
} from '../src/windows-operational-authorization.mjs';
import {
  runWindowsAuthorizationReadyBootstrap,
  WindowsAuthorizationReadyBootstrapError,
} from '../src/windows-authorization-ready-bootstrap.mjs';

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

describe('Windows authorization-ready bootstrap (Phase 10b)', () => {
  it('returns ready only from complete branded evidence without apply', async () => {
    const evidence = buildCompleteOperationalAuthorizationEvidenceForHarness();
    let applyCalls = 0;
    const result = await runWindowsAuthorizationReadyBootstrap({
      platform: 'win32',
      collectors: collectorsFromEvidence(evidence),
      applyFirstInstall: async () => {
        applyCalls += 1;
        throw new Error('must not apply');
      },
    });
    assert.equal(result.authorization_ready, true);
    assert.equal(result.terminal_code, 'production_authorization_ready');
    assert.equal(result.apply_attempted, false);
    assert.equal(result.apply_succeeded, false);
    assert.equal(applyCalls, 0);
    assert.equal(result.mutation_authorized, false);
    assert.equal(result.personal_vault_forbidden, true);
    assert.equal(result.company_vault_forbidden, true);
    assert.equal(result.helper_vault_free, true);
  });

  it('applies once when target ACL incomplete then recomposes to ready', async () => {
    const incomplete = buildIncompleteOperationalAuthorizationEvidence();
    const complete = buildCompleteOperationalAuthorizationEvidenceForHarness();
    let phase = 0;
    let applyCalls = 0;
    const collectors = {
      async buildInstallGateAndLayout() {
        const evidence = phase === 0 ? incomplete : complete;
        return {
          installGateReport: evidence.installGateReport,
          layoutPlan: evidence.layoutPlan,
        };
      },
      async collectHandleBound() {
        return (phase === 0 ? incomplete : complete).handleBoundEvidence;
      },
      async collectTargetAcl() {
        return (phase === 0 ? incomplete : complete).targetAclEvidence;
      },
      async collectPeer() {
        return (phase === 0 ? incomplete : complete).peerEvidence;
      },
    };
    const result = await runWindowsAuthorizationReadyBootstrap({
      platform: 'win32',
      collectors,
      applyFirstInstall: async () => {
        applyCalls += 1;
        phase = 1;
        return { applied: true, paths_created: 5 };
      },
    });
    assert.equal(applyCalls, 1);
    assert.equal(result.apply_attempted, true);
    assert.equal(result.apply_succeeded, true);
    assert.equal(result.authorization_ready, true);
    assert.equal(result.terminal_code, 'production_authorization_ready');
  });

  it('skips apply when skipApply is set and stays not ready', async () => {
    const incomplete = buildIncompleteOperationalAuthorizationEvidence();
    let applyCalls = 0;
    const result = await runWindowsAuthorizationReadyBootstrap({
      platform: 'win32',
      collectors: collectorsFromEvidence(incomplete),
      skipApply: true,
      applyFirstInstall: async () => {
        applyCalls += 1;
        return { applied: true };
      },
    });
    assert.equal(applyCalls, 0);
    assert.equal(result.apply_attempted, false);
    assert.equal(result.authorization_ready, false);
  });

  it('does not hardcode ready on failed apply', async () => {
    const incomplete = buildIncompleteOperationalAuthorizationEvidence();
    const result = await runWindowsAuthorizationReadyBootstrap({
      platform: 'win32',
      collectors: collectorsFromEvidence(incomplete),
      applyFirstInstall: async () => ({ applied: false, paths_created: 0 }),
    });
    assert.equal(result.apply_attempted, true);
    assert.equal(result.apply_succeeded, false);
    assert.equal(result.authorization_ready, false);
    assert.notEqual(result.terminal_code, 'production_authorization_ready');
  });

  it('rejects non-win32 platforms', async () => {
    await assert.rejects(
      () => runWindowsAuthorizationReadyBootstrap({ platform: 'linux' }),
      (error) => error instanceof WindowsAuthorizationReadyBootstrapError &&
        error.code === 'unsupported_platform',
    );
  });

  it('copies authorization_ready only from compose', async () => {
    const evidence = buildCompleteOperationalAuthorizationEvidenceForHarness();
    const result = await runWindowsAuthorizationReadyBootstrap({
      platform: 'win32',
      collectors: collectorsFromEvidence(evidence),
      compose: (bundle) => {
        const report = composeWindowsOperationalAuthorization(bundle);
        assert.equal(report.authorization_ready, true);
        return report;
      },
      applyFirstInstall: async () => {
        throw new Error('must not apply');
      },
    });
    assert.equal(result.authorization_ready, true);
  });
});
