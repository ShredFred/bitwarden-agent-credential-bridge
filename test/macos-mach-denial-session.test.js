import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  MacosMachDenialSessionError,
  parseMacosMachDenialResult,
  runMacosMachDenialSession,
} from '../src/macos-mach-denial-session.mjs';

function valid(overrides = {}) {
  const euidDigest = process.platform === 'darwin'
    ? createHash('sha256').update(`euid:${process.geteuid()}`).digest('hex')
    : 'a'.repeat(64);
  return {
    schema_version: 1,
    transport_kind: 'macos_mach_message_console',
    mach_service_bound: false,
    launchd_system_service_verified: false,
    mach_peer_exchange_verified: true,
    request_audit_trailer_verified: true,
    request_sender_matches_spawned_caller: true,
    request_sender_pid_verified: true,
    request_sender_pidversion_verified: true,
    reply_audit_trailer_verified: true,
    reply_sender_matches_expected_helper: true,
    reply_sender_pid_verified: true,
    reply_sender_pidversion_verified: true,
    caller_euid_verified: true,
    helper_euid_verified: true,
    caller_euid_sha256: euidDigest,
    helper_euid_sha256: euidDigest,
    same_euid: true,
    helper_code_requirement_satisfied: false,
    manifest_request_sent: false,
    manifest_executor_absent: true,
    authorization_denied: true,
    install_gate_eligible: false,
    ...overrides,
  };
}

describe('macOS Mach audit-trailer console denial session', () => {
  it('accepts only the exact parent-bound same-EUID non-authorizing report', {
    skip: process.platform !== 'darwin',
  }, () => {
    const expected = valid();
    assert.deepEqual(parseMacosMachDenialResult(`${JSON.stringify(expected)}\n`), expected);
    for (const candidate of [
      { ...expected, extra: true },
      { ...expected, transport_kind: 'macos_mach_message_service' },
      { ...expected, mach_service_bound: true },
      { ...expected, launchd_system_service_verified: true },
      { ...expected, helper_code_requirement_satisfied: true },
      { ...expected, manifest_request_sent: true },
      { ...expected, manifest_executor_absent: false },
      { ...expected, authorization_denied: false },
      { ...expected, install_gate_eligible: true },
      { ...expected, same_euid: false },
      { ...expected, helper_euid_sha256: 'b'.repeat(64) },
      { ...expected, caller_euid_sha256: 'a'.repeat(64), helper_euid_sha256: 'a'.repeat(64) },
      { ...expected, request_audit_trailer_verified: 1 },
    ]) {
      assert.throws(
        () => parseMacosMachDenialResult(JSON.stringify(candidate)),
        (error) => error instanceof MacosMachDenialSessionError && error.code === 'invalid_output',
      );
    }
    assert.throws(() => parseMacosMachDenialResult(JSON.stringify(expected), 'noise'), MacosMachDenialSessionError);
  });

  it('uses only public Mach audit-trailer APIs and contains no credential or manifest surface', async () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
    const source = await fs.readFile(path.join(root, 'native', 'macos-mach-denial-probe.c'), 'utf8');
    for (const required of [
      'MACH_RCV_TRAILER_AUDIT', 'mach_msg_audit_trailer_t', 'audit_token_to_pidversion',
      'TASK_AUDIT_TOKEN', 'MACH_MSG_TYPE_MAKE_SEND_ONCE', 'MACH_MSG_TYPE_MOVE_SEND_ONCE',
      'MACH_RCV_TIMEOUT', 'MACH_SEND_TIMEOUT', 'bootstrap_register', 'bootstrap_look_up',
      'pipe(token_pipe)', 'poll(&descriptor', 'memcmp(&trailer->msgh_audit, &expected_caller',
      'waitpid(child, status, WNOHANG)', 'kill(child, SIGKILL)',
    ]) assert.equal(source.includes(required), true, `missing native binding: ${required}`);
    for (const forbidden of [
      'NSXPCConnection', 'xpc_connection_get_audit_token', 'task_for_pid', 'task_name_for_pid',
      'de.frederikstadler.bitwarden-agent-credential-bridge.helper', '/Library/', '/Users/',
      'Bitwarden', 'Keychain', 'manifestBytes', 'launcherBytes', 'credential', 'http://', 'https://',
    ]) assert.equal(source.includes(forbidden), false, `forbidden native surface: ${forbidden}`);
  });

  it('compiles and runs a real cross-process same-EUID denial on macOS', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const result = await runMacosMachDenialSession();
    assert.equal(result.transport_kind, 'macos_mach_message_console');
    assert.equal(result.mach_peer_exchange_verified, true);
    assert.equal(result.request_audit_trailer_verified, true);
    assert.equal(result.reply_audit_trailer_verified, true);
    assert.equal(result.same_euid, true);
    assert.equal(result.authorization_denied, true);
    assert.equal(result.mach_service_bound, false);
    assert.equal(result.helper_code_requirement_satisfied, false);
    assert.equal(result.manifest_request_sent, false);
    assert.equal(result.install_gate_eligible, false);
    const serialized = JSON.stringify(result);
    for (const forbidden of ['/Library/', '/Users/', 'designated =>', '_bwagentbridge', 'launchctl']) {
      assert.equal(serialized.includes(forbidden), false);
    }
  });
});
