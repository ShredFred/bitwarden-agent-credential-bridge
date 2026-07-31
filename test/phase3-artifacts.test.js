import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  selectPlatformManifest,
  validateCompatibilityStatus,
  validateOciDigest,
  validateSha256Checksum,
  validateVersion,
} from '../src/supply-chain-audit.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function readJson(...parts) {
  return JSON.parse(await readFile(path.join(root, ...parts), 'utf8'));
}

describe('Phase 3 offline artifacts', () => {
  it('locks supplied evidence while distinguishing linked, candidate, and audit-reference Agent Access revisions', async () => {
    const lock = await readJson('upstream', 'supply-chain.lock.json');
    const linked = lock.onecli.linkedAgentAccess;
    const candidate = lock.candidateAac;
    const laterReference = lock.laterSourceAuditReference;

    assert.equal(lock.schemaVersion, 1);
    assert.equal(lock.scope, 'offline-evidence-only');
    assert.equal(validateVersion(lock.onecli.version), '1.45.0');
    assert.equal(
      lock.onecli.tagCommit,
      '84ccaf74ce6350f8925675457b48272c29f32c1a',
    );
    assert.equal(linked.crate, 'ap-client');
    assert.equal(linked.registry, 'crates.io');
    assert.equal(validateVersion(linked.version), '0.9.0');
    assert.equal(
      validateSha256Checksum(linked.checksum),
      '7c7dfbe9db85d3e17e654afa4117ae76c5ec16750cee817a80432b2e93f724a2',
    );
    assert.equal(
      linked.sourceTagCommit,
      'fc858195ccabd88737a0255a0fda60a7a02c2286',
    );

    assert.equal(validateVersion(candidate.version), '0.11.0');
    assert.equal(
      candidate.tagCommit,
      '3b000d15af71be5ddcf8893b099f3a66d386be9d',
    );
    assert.equal(
      validateSha256Checksum(
        candidate.artifacts['windows/amd64'].sha256,
      ),
      'bc72b7e3e04d0cb53d4b1117326045383974f5092588a9bff6e2484029be040c',
    );
    assert.equal(
      validateCompatibilityStatus(candidate.onecliCompatibility.status),
      'unverified',
    );
    assert.equal(
      candidate.onecliCompatibility.verificationGate,
      'approved-disposable-live-test',
    );

    assert.equal(validateVersion(laterReference.workspaceVersion), '0.12.0');
    assert.equal(
      laterReference.commit,
      '9cd303f65dc501c19d1d513fb4cf88fe5f44936a',
    );
    assert.equal(
      laterReference.relationshipToOnecli,
      'not-the-linked-onecli-dependency',
    );
    assert.notEqual(laterReference.commit, linked.sourceTagCommit);
    assert.notEqual(candidate.version, linked.version);

    for (const image of [lock.onecli.ociImage, lock.postgres.ociImage]) {
      validateOciDigest(image.indexDigest);
      selectPlatformManifest(image, { os: 'linux', architecture: 'amd64' });
      selectPlatformManifest(image, { os: 'linux', architecture: 'arm64' });
    }
  });

  it('keeps the disposable Compose example inert and strongly bounded', async () => {
    const compose = await readFile(
      path.join(root, 'deploy', 'compose.disposable.example.yaml'),
      'utf8',
    );

    assert.match(compose, /^# WARNING: NON-DEPLOYABLE PHASE 3 TEMPLATE/m);
    assert.match(compose, /DO NOT RUN/i);
    assert.doesNotMatch(compose, /sha256:[0-9a-f]{64}/);

    const imageLines = compose.match(/^\s+image:\s+.+$/gm) ?? [];
    assert.equal(imageLines.length, 2);
    assert.ok(
      imageLines.every(
        (line) =>
          line.includes('${') &&
          line.includes(':?') &&
          line.includes('@sha256:${'),
      ),
    );
    assert.doesNotMatch(compose, /\$\{[^}]+:-/);

    const postgresBlock = compose.match(
      /^  postgres:\r?\n([\s\S]*?)(?=^  onecli:)/m,
    )?.[0];
    const onecliBlock = compose.match(
      /^  onecli:\r?\n([\s\S]*?)(?=^networks:)/m,
    )?.[0];
    assert.ok(postgresBlock);
    assert.ok(onecliBlock);

    assert.doesNotMatch(postgresBlock, /^\s{4}ports:/m);
    assert.doesNotMatch(postgresBlock, /^\s{4}expose:/m);
    assert.match(postgresBlock, /disposable-data/);
    assert.match(compose, /disposable-data:\r?\n\s+internal:\s+true/);

    assert.match(onecliBlock, /"127\.0\.0\.1:10255:10255\/tcp"/);
    assert.doesNotMatch(onecliBlock, /:\s*10254(?::|\s|$)/m);
    assert.match(onecliBlock, /expose:\r?\n\s+- "10254"/);

    assert.equal(
      (compose.match(/profiles:\s+\["explicit-approval-required"\]/g) ?? [])
        .length,
      2,
    );
    for (const required of [
      'DISPOSABLE_POSTGRES_USER',
      'DISPOSABLE_POSTGRES_PASSWORD',
      'DISPOSABLE_POSTGRES_DB',
      'DISPOSABLE_ONECLI_ENCRYPTION_KEY',
      'DISPOSABLE_BITWARDEN_RELAY_URL',
    ]) {
      assert.match(compose, new RegExp(`\\$\\{${required}:\\?`));
    }
  });

  it('carries every live-test safety gate into the not-run runbook', async () => {
    const runbook = await readFile(
      path.join(root, 'docs', 'phase3-disposable-live-test.md'),
      'utf8',
    );

    assert.match(runbook, /status:\s+\*\*not run; compatibility unverified\*\*/i);
    for (const required of [
      /explicit approval/i,
      /separate OS\/runtime identity/i,
      /Docker control/i,
      /disposable Bitwarden account/i,
      /disposable item/i,
      /bc72b7e3e04d0cb53d4b1117326045383974f5092588a9bff6e2484029be040c/,
      /rendered Compose/i,
      /image digest/i,
      /pairing/i,
      /fake target API/i,
      /non-disclosure/i,
      /dashboard denial/i,
      /egress denial/i,
      /redirect/i,
      /log/i,
      /cache purge/i,
      /restart/i,
      /revocation/i,
      /cleanup/i,
      /evidence checklist/i,
    ]) {
      assert.match(runbook, required);
    }
    assert.match(runbook, /personal or company/i);
    assert.match(runbook, /stop and clean up/i);
  });
});
