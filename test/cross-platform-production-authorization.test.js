import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  evaluateMacosProductionAuthorization,
  isMacosProductionAuthorizationReport,
} from '../src/macos-production-authorization.mjs';
import {
  buildCompleteMacosOperationalAuthorizationEvidenceForHarness,
  buildIncompleteMacosOperationalAuthorizationEvidence,
  composeMacosOperationalAuthorization,
} from '../src/macos-operational-authorization.mjs';
import { runMacosAuthorizationReadyBootstrap } from '../src/macos-authorization-ready-bootstrap.mjs';
import {
  evaluateLinuxProductionAuthorization,
  isLinuxProductionAuthorizationReport,
} from '../src/linux-production-authorization.mjs';
import {
  buildCompleteLinuxOperationalAuthorizationEvidenceForHarness,
  buildIncompleteLinuxOperationalAuthorizationEvidence,
  composeLinuxOperationalAuthorization,
} from '../src/linux-operational-authorization.mjs';
import { runLinuxAuthorizationReadyBootstrap } from '../src/linux-authorization-ready-bootstrap.mjs';
import {
  absentOperationalAuthorizationForPlatform,
  composeOperationalAuthorizationForPlatform,
} from '../src/platform-operational-authorization.mjs';

function collectorsFrom(evidence) {
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

describe('macOS production authorization (11e/11j/11l)', () => {
  it('sets authorization_ready true only from complete branded evidence', () => {
    const evidence = buildCompleteMacosOperationalAuthorizationEvidenceForHarness();
    const report = composeMacosOperationalAuthorization(evidence);
    assert.equal(report.platform, 'darwin');
    assert.equal(report.authorization_ready, true);
    assert.equal(report.terminal_code, 'production_authorization_ready');
    assert.equal(report.mutation_authorized, false);
    assert.equal(report.operational_bridge_unwired, false);
    assert.equal(isMacosProductionAuthorizationReport(
      evaluateMacosProductionAuthorization(
        evidence.installGateReport,
        evidence.layoutPlan,
        evidence.handleBoundEvidence,
        evidence.targetAclEvidence,
        {
          local_transport: true,
          identity_verified: true,
          different_principal: true,
          caller_write_denied: true,
          helper_write_allowed: true,
        },
      ),
    ), true);
  });

  it('keeps incomplete evidence false', () => {
    const report = composeMacosOperationalAuthorization(
      buildIncompleteMacosOperationalAuthorizationEvidence(),
    );
    assert.equal(report.authorization_ready, false);
  });

  it('bootstrap copies ready only from compose', async () => {
    const evidence = buildCompleteMacosOperationalAuthorizationEvidenceForHarness();
    const result = await runMacosAuthorizationReadyBootstrap({
      platform: 'darwin',
      collectors: collectorsFrom(evidence),
    });
    assert.equal(result.authorization_ready, true);
    assert.equal(result.terminal_code, 'production_authorization_ready');
  });
});

describe('Linux production authorization (12p/12t/12u)', () => {
  it('sets authorization_ready true only from complete branded evidence', () => {
    const evidence = buildCompleteLinuxOperationalAuthorizationEvidenceForHarness();
    const report = composeLinuxOperationalAuthorization(evidence);
    assert.equal(report.platform, 'linux');
    assert.equal(report.authorization_ready, true);
    assert.equal(report.terminal_code, 'production_authorization_ready');
    assert.equal(report.mutation_authorized, false);
    assert.equal(isLinuxProductionAuthorizationReport(
      evaluateLinuxProductionAuthorization(
        evidence.installGateReport,
        evidence.layoutPlan,
        evidence.handleBoundEvidence,
        evidence.targetAclEvidence,
        {
          local_transport: true,
          identity_verified: true,
          different_principal: true,
          caller_write_denied: true,
          helper_write_allowed: true,
        },
      ),
    ), true);
  });

  it('keeps incomplete evidence false', () => {
    const report = composeLinuxOperationalAuthorization(
      buildIncompleteLinuxOperationalAuthorizationEvidence(),
    );
    assert.equal(report.authorization_ready, false);
  });

  it('bootstrap copies ready only from compose', async () => {
    const evidence = buildCompleteLinuxOperationalAuthorizationEvidenceForHarness();
    const result = await runLinuxAuthorizationReadyBootstrap({
      platform: 'linux',
      collectors: collectorsFrom(evidence),
    });
    assert.equal(result.authorization_ready, true);
  });
});

describe('platform operational authorization dispatch', () => {
  it('keeps platform reports isolated', () => {
    assert.equal(absentOperationalAuthorizationForPlatform('win32').platform, 'win32');
    assert.equal(absentOperationalAuthorizationForPlatform('darwin').platform, 'darwin');
    assert.equal(absentOperationalAuthorizationForPlatform('linux').platform, 'linux');
    assert.equal(absentOperationalAuthorizationForPlatform('win32').authorization_ready, false);
    assert.equal(absentOperationalAuthorizationForPlatform('darwin').authorization_ready, false);
    assert.equal(absentOperationalAuthorizationForPlatform('linux').authorization_ready, false);

    const mac = buildCompleteMacosOperationalAuthorizationEvidenceForHarness();
    const linux = buildCompleteLinuxOperationalAuthorizationEvidenceForHarness();
    assert.equal(composeOperationalAuthorizationForPlatform('darwin', mac).authorization_ready, true);
    assert.equal(composeOperationalAuthorizationForPlatform('linux', linux).authorization_ready, true);
  });
});
