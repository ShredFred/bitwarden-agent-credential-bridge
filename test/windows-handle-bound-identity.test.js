import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import process from 'node:process';
import {
  absentWindowsServerIdentityFacts,
  brandWindowsHandleBoundIdentityEvidence,
  mergeWindowsHandleBoundIdentityEvidence,
  parseWindowsHandleBoundBinaryProbeResult,
  parseWindowsServerIdentityVerifierResult,
  WindowsHandleBoundIdentityError,
} from '../src/windows-handle-bound-identity.mjs';
import { isWindowsHandleBoundIdentityEvidence } from '../src/windows-production-authorization.mjs';
import {
  buildWindowsServiceBoundaryPlan,
  isWindowsServiceBoundaryPlan,
} from '../src/windows-service-boundary-plan.mjs';

function absentProbe() {
  return {
    schema_version: 1,
    service_present: false,
    binary_digest_matched_via_handle: false,
    binary_chain_reparse_free: false,
    binary_owner_trusted: false,
    caller_binary_control_denied: false,
    caller_service_control_denied: false,
    service_dacl_caller_change_denied: false,
    handle_open_used: false,
    path_hash_used: false,
    authorization_ready: false,
  };
}

function completeIdentity() {
  return {
    schema_version: 1,
    local_pipe_connected: true,
    server_pid_bound: true,
    scm_service_running: true,
    scm_server_pid_match: true,
    server_token_bound: true,
    server_token_user_local_service: true,
    service_sid_group_enabled: true,
    server_identity_verified: true,
    request_sent: false,
    authorization_denied: true,
  };
}

function completeProbe() {
  return {
    schema_version: 1,
    service_present: true,
    binary_digest_matched_via_handle: true,
    binary_chain_reparse_free: true,
    binary_owner_trusted: true,
    caller_binary_control_denied: true,
    caller_service_control_denied: true,
    service_dacl_caller_change_denied: true,
    handle_open_used: true,
    path_hash_used: false,
    authorization_ready: false,
  };
}

describe('Windows handle-bound identity (Phase 9b)', () => {
  it('merges complete verifier + handle probe into brandable evidence', () => {
    const merged = mergeWindowsHandleBoundIdentityEvidence(completeIdentity(), completeProbe());
    assert.equal(merged.path_based_preflight_only, false);
    assert.equal(merged.collector_value_free, true);
    assert.equal(merged.server_pid_handle_bound, true);
    assert.equal(merged.binary_digest_matched_via_handle, true);
    assert.equal(merged.scm_service_running_same_pid, true);
    const branded = brandWindowsHandleBoundIdentityEvidence(merged);
    assert.equal(isWindowsHandleBoundIdentityEvidence(branded), true);
    assert.equal(isWindowsHandleBoundIdentityEvidence({ ...branded }), false);
  });

  it('keeps evidence incomplete when the fixed pipe/service is absent', () => {
    const merged = mergeWindowsHandleBoundIdentityEvidence(
      absentWindowsServerIdentityFacts(),
      absentProbe(),
    );
    assert.equal(merged.pipe_local_only, false);
    assert.equal(merged.server_pid_handle_bound, false);
    assert.equal(merged.binary_digest_matched_via_handle, false);
    assert.equal(merged.path_based_preflight_only, false);
    assert.equal(merged.collector_value_free, true);
  });

  it('rejects path-hash pretenses and digest claims without handle open', () => {
    assert.throws(
      () => parseWindowsHandleBoundBinaryProbeResult(JSON.stringify({
        ...completeProbe(),
        path_hash_used: true,
      })),
      (error) => error instanceof WindowsHandleBoundIdentityError &&
        error.code === 'invalid_binary_probe',
    );
    assert.throws(
      () => parseWindowsHandleBoundBinaryProbeResult(JSON.stringify({
        ...completeProbe(),
        handle_open_used: false,
      })),
      (error) => error instanceof WindowsHandleBoundIdentityError &&
        error.code === 'invalid_binary_probe',
    );
    assert.throws(
      () => parseWindowsServerIdentityVerifierResult(JSON.stringify({
        ...completeIdentity(),
        request_sent: true,
      })),
      (error) => error instanceof WindowsHandleBoundIdentityError &&
        error.code === 'invalid_identity_verifier',
    );
  });

  it('rejects forged probe extras and authorizing probe claims', () => {
    assert.throws(
      () => parseWindowsHandleBoundBinaryProbeResult(JSON.stringify({
        ...absentProbe(),
        authorization_ready: true,
      })),
      (error) => error instanceof WindowsHandleBoundIdentityError,
    );
    assert.throws(
      () => parseWindowsHandleBoundBinaryProbeResult(JSON.stringify({
        ...absentProbe(),
        extra: true,
      })),
      (error) => error instanceof WindowsHandleBoundIdentityError,
    );
  });

  it('builds a valid boundary plan input shape for collectors', () => {
    const plan = buildWindowsServiceBoundaryPlan({
      platform: 'win32',
      binarySha256: 'a'.repeat(64),
      binaryByteLength: 4096,
    });
    assert.equal(isWindowsServiceBoundaryPlan(plan), true);
    assert.equal(plan.binary.sha256.length, 64);
    assert.equal(plan.binary.byte_length, 4096);
    assert.equal(plan.ipc.server_pid_token_binding_required, true);
  });
});

describe('Windows handle-bound identity live probe (win32)', () => {
  it('returns an absent binary probe when the fixed service is not installed', async (t) => {
    if (process.platform !== 'win32') {
      t.skip('Windows-only probe');
      return;
    }
    if (process.env.GITHUB_ACTIONS === 'true') {
      t.skip('live handle-bound probe is not part of GitHub Actions CI');
      return;
    }
    const { collectWindowsHandleBoundIdentityEvidence } = await import(
      '../src/windows-handle-bound-identity.mjs'
    );
    // Avoid a full publish: exercise merge/brand path with the live absent probe
    // by calling the exported parsers against a direct PowerShell invocation.
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const path = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const execFileAsync = promisify(execFile);
    const script = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      '..',
      'scripts',
      'windows-handle-bound-identity-probe.ps1',
    );
    const systemRoot = process.env.SystemRoot;
    const powershell = path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const { stdout, stderr } = await execFileAsync(powershell, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', script, 'a'.repeat(64), '4096',
    ], {
      windowsHide: true,
      timeout: 15000,
      maxBuffer: 4096,
      encoding: 'utf8',
      env: {
        SystemRoot: systemRoot,
        WINDIR: systemRoot,
        TEMP: process.env.TEMP,
        TMP: process.env.TMP,
      },
    });
    assert.equal(stderr, '');
    const probe = parseWindowsHandleBoundBinaryProbeResult(stdout, stderr);
    assert.equal(probe.path_hash_used, false);
    assert.equal(probe.authorization_ready, false);
    // With a fake digest the handle-bound match must stay false whether or not a
    // leftover fixed service is present from an earlier operator live run.
    assert.equal(probe.binary_digest_matched_via_handle, false);
    const merged = mergeWindowsHandleBoundIdentityEvidence(
      absentWindowsServerIdentityFacts(),
      probe,
    );
    const branded = brandWindowsHandleBoundIdentityEvidence(merged);
    assert.equal(branded.binary_digest_matched_via_handle, false);
    assert.equal(branded.path_based_preflight_only, false);
    // Full collect() publishes the helper and is reserved for operator live runs.
    assert.equal(typeof collectWindowsHandleBoundIdentityEvidence, 'function');
  });
});
