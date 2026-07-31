import assert from 'node:assert/strict';
import process from 'node:process';
import { describe, it } from 'node:test';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import {
  inspectWindowsServiceBoundary,
  parseWindowsServiceBoundaryResult,
  WindowsServiceBoundaryPreflightError,
} from '../src/windows-service-boundary-preflight.mjs';

const plan = buildWindowsServiceBoundaryPlan({
  platform: 'win32', binarySha256: 'a'.repeat(64), binaryByteLength: 4096,
});
const absent = Object.freeze({
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

describe('Windows service boundary native preflight', () => {
  it('parses only the exact value-free schema and recomputes readiness', () => {
    assert.deepEqual(parseWindowsServiceBoundaryResult(JSON.stringify(absent)), absent);
    const matchingSnapshot = Object.freeze({
      ...absent,
      service_present: true,
      account_local_service: true,
      demand_start: true,
      win32_own_process: true,
      service_sid_unrestricted: true,
      caller_service_control_denied: true,
      binary_binding_verified: true,
      binary_chain_reparse_free: true,
      binary_owner_trusted: true,
      caller_binary_control_denied: true,
      snapshot_matches_plan: true,
    });
    assert.deepEqual(parseWindowsServiceBoundaryResult(JSON.stringify(matchingSnapshot)), matchingSnapshot);
    for (const invalid of [
      '', 'not json', JSON.stringify({ ...absent, path: 'C:\\secret' }),
      JSON.stringify({ ...absent, authorization_ready: true }),
      JSON.stringify({ ...absent, snapshot_matches_plan: true }),
      JSON.stringify({ ...absent, account_local_service: true }),
      JSON.stringify({ ...absent, service_present: 0 }),
    ]) {
      assert.throws(
        () => parseWindowsServiceBoundaryResult(invalid),
        (error) => error instanceof WindowsServiceBoundaryPreflightError && error.code === 'invalid_output',
      );
    }
  });

  it('rejects mutable, extended, or tampered plans before host inspection', async () => {
    for (const invalid of [
      { ...plan },
      Object.freeze({ ...plan, extra: true }),
      Object.freeze({ ...plan, binary: { ...plan.binary, byte_length: 1 } }),
    ]) {
      await assert.rejects(
        inspectWindowsServiceBoundary(invalid),
        (error) => error instanceof WindowsServiceBoundaryPreflightError && error.code === 'invalid_plan',
      );
    }
  });

  it('runs the repo-owned read-only probe and returns only booleans on Windows', {
    skip: process.platform !== 'win32',
  }, async () => {
    const result = await inspectWindowsServiceBoundary(plan);
    assert.deepEqual(Object.keys(result), [
      'schema_version', 'service_present', 'account_local_service', 'demand_start',
      'win32_own_process', 'service_sid_unrestricted', 'caller_service_control_denied', 'binary_binding_verified',
      'binary_chain_reparse_free', 'binary_owner_trusted', 'caller_binary_control_denied',
      'snapshot_matches_plan', 'authorization_ready',
    ]);
    for (const [field, value] of Object.entries(result)) {
      if (field !== 'schema_version') assert.equal(typeof value, 'boolean');
    }
    if (!result.service_present) assert.deepEqual(result, absent);
  });
});
