import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildMacosLaunchdBoundaryPlan } from '../src/macos-launchd-boundary-plan.mjs';
import {
  inspectMacosLaunchdBoundary,
  MacosLaunchdBoundaryPreflightError,
  parseMacosLaunchdBoundaryResult,
} from '../src/macos-launchd-boundary-preflight.mjs';

const plan = buildMacosLaunchdBoundaryPlan({
  platform: 'darwin',
  serviceManager: 'launchd-system',
  binarySha256: 'a'.repeat(64),
  binaryByteLength: 4096,
  designatedRequirementSha256: 'b'.repeat(64),
  plistSha256: 'c'.repeat(64),
});
const absent = Object.freeze({
  schema_version: 1,
  service_present: false,
  account_static_helper: false,
  system_domain_plist: false,
  plist_binding_verified: false,
  demand_activation_only: false,
  mach_service_declared: false,
  binary_binding_verified: false,
  designated_requirement_path_snapshot_matches_plan: false,
  designated_requirement_verified: false,
  binary_chain_symlink_free: false,
  plist_chain_symlink_free: false,
  binary_and_plist_owner_trusted: false,
  caller_plist_and_binary_control_denied: false,
  snapshot_matches_plan: false,
  authorization_ready: false,
});

describe('macOS launchd boundary read-only preflight', () => {
  it('keeps fixed identities and limits mutation to the private code snapshot', async () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
    const source = await fs.readFile(path.join(root, 'scripts', 'macos-launchd-boundary-probe.mjs'), 'utf8');
    const rules = await fs.readFile(path.join(root, 'src', 'macos-launchd-boundary-rules.mjs'), 'utf8');
    const snapshot = await fs.readFile(path.join(root, 'src', 'macos-code-snapshot-verifier.mjs'), 'utf8');
    for (const required of [
      'de.frederikstadler.bitwarden-agent-credential-bridge.helper',
      "export const MACOS_HELPER_ACCOUNT = '_bwagentbridge'",
      '/Library/PrivilegedHelperTools/',
    ]) assert.equal(rules.includes(required), true, `missing fixed rule binding: ${required}`);
    for (const required of [
      '/Library/LaunchDaemons/',
      "'/usr/bin/plutil'",
      "'/usr/bin/dscl'",
      "'/usr/bin/codesign'",
    ]) assert.equal(source.includes(required), true, `missing fixed probe binding: ${required}`);
    assert.match(source, /binding: false,\s+requirementPathSnapshot: false,\s+requirementVerified: false,/);
    assert.match(source, /const requirementSnapshot = binding\s+\? await verifyMacosCodeSnapshot/);
    for (const forbidden of [
      'launchctl', 'security find-', 'security unlock-', 'chmod(', 'chown(',
      'writeFile(', 'appendFile(', 'mkdir(', 'unlink(', 'rename(', 'fetch(', 'http.request', 'https.request',
    ]) assert.equal(source.includes(forbidden), false, `mutation/network surface present: ${forbidden}`);
    for (const required of ['mkdtemp(', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'handle.sync()',
      "execFileAsync('/usr/bin/codesign'", 'fs.unlink(snapshotPath)', 'fs.rmdir(root)']) {
      assert.equal(snapshot.includes(required), true, `missing snapshot safeguard: ${required}`);
    }
    for (const forbidden of [
      '/Library/PrivilegedHelperTools/', '/Library/LaunchDaemons/', 'launchctl',
      'security find-', 'security unlock-', 'chmod(', 'chown(', 'writeFile(', 'appendFile(',
      'rename(', 'fetch(', 'http.request', 'https.request',
    ]) assert.equal(snapshot.includes(forbidden), false, `snapshot escape surface present: ${forbidden}`);
  });

  it('parses only the exact value-free schema and recomputes the snapshot', () => {
    assert.deepEqual(parseMacosLaunchdBoundaryResult(JSON.stringify(absent)), absent);
    const matching = Object.freeze(Object.fromEntries(Object.entries(absent).map(([key, value]) => [
      key,
      key === 'schema_version' ? value :
        key === 'authorization_ready' ? false : true,
    ])));
    assert.deepEqual(parseMacosLaunchdBoundaryResult(JSON.stringify(matching)), matching);
    const bindingFailure = Object.freeze({
      ...matching,
      binary_binding_verified: false,
      designated_requirement_verified: false,
      snapshot_matches_plan: false,
    });
    assert.deepEqual(parseMacosLaunchdBoundaryResult(JSON.stringify(bindingFailure)), bindingFailure);
    for (const invalid of [
      '',
      'not json',
      JSON.stringify({ ...absent, path: '/Library/private' }),
      JSON.stringify({ ...absent, authorization_ready: true }),
      JSON.stringify({ ...absent, designated_requirement_verified: true }),
      JSON.stringify({ ...absent, snapshot_matches_plan: true }),
      JSON.stringify({ ...absent, account_static_helper: true }),
      JSON.stringify({ ...absent, service_present: 0 }),
      JSON.stringify({ ...absent, schema_version: 2 }),
    ]) {
      assert.throws(
        () => parseMacosLaunchdBoundaryResult(invalid),
        (error) => error instanceof MacosLaunchdBoundaryPreflightError && error.code === 'invalid_output',
      );
    }
  });

  it('rejects cloned, spread, proxied, and tampered plans before host inspection', async () => {
    for (const invalid of [
      { ...plan },
      structuredClone(plan),
      new Proxy(plan, {}),
      Object.freeze({ ...plan, binary: { ...plan.binary, byte_length: 1 } }),
    ]) {
      await assert.rejects(
        inspectMacosLaunchdBoundary(invalid),
        (error) => error instanceof MacosLaunchdBoundaryPreflightError && error.code === 'invalid_plan',
      );
    }
  });

  it('runs the fixed read-only probe and returns only booleans on macOS', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const result = await inspectMacosLaunchdBoundary(plan);
    assert.deepEqual(Object.keys(result), Object.keys(absent));
    for (const [field, value] of Object.entries(result)) {
      if (field !== 'schema_version') assert.equal(typeof value, 'boolean');
    }
    assert.equal(result.authorization_ready, false);
    const serialized = JSON.stringify(result);
    for (const forbidden of ['/Library/', '/Users/', '_bwagentbridge', 'designated =>', 'launchctl']) {
      assert.equal(serialized.includes(forbidden), false);
    }
    if (!result.service_present) assert.deepEqual(result, absent);
  });
});
