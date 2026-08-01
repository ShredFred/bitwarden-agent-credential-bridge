import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  inspectMacosNativeLaunchdHelperScaffold,
  MacosNativeLaunchdHelperError,
  parseMacosNativeLaunchdHelperSelfTest,
} from '../src/macos-native-launchd-helper.mjs';

function valid(overrides = {}) {
  return {
    schema_version: 1,
    platform_darwin: true,
    fixed_account_self_check_compiled: true,
    fixed_mach_service_compiled: true,
    launchd_checkin_entrypoint_compiled: true,
    audit_trailer_request_verification_compiled: true,
    send_once_denial_reply_compiled: true,
    bounded_messages_compiled: true,
    launchd_lifecycle_live_verified: false,
    distinct_euid_live_verified: false,
    helper_code_requirement_live_verified: false,
    manifest_executor_absent: true,
    network_stack_absent: true,
    keychain_client_absent: true,
    vault_client_absent: true,
    install_gate_eligible: false,
    ...overrides,
  };
}

describe('native macOS launchd denial-only helper scaffold', () => {
  it('parses only the exact compile-time non-authorizing self-test', () => {
    const expected = valid();
    assert.deepEqual(parseMacosNativeLaunchdHelperSelfTest(`${JSON.stringify(expected)}\n`), expected);
    for (const candidate of [
      { ...expected, extra: true },
      { ...expected, platform_darwin: false },
      { ...expected, launchd_lifecycle_live_verified: true },
      { ...expected, distinct_euid_live_verified: true },
      { ...expected, helper_code_requirement_live_verified: true },
      { ...expected, manifest_executor_absent: false },
      { ...expected, network_stack_absent: false },
      { ...expected, keychain_client_absent: false },
      { ...expected, vault_client_absent: false },
      { ...expected, install_gate_eligible: true },
      { ...expected, bounded_messages_compiled: 1 },
    ]) assert.throws(
      () => parseMacosNativeLaunchdHelperSelfTest(JSON.stringify(candidate)),
      (error) => error instanceof MacosNativeLaunchdHelperError && error.code === 'invalid_output',
    );
    assert.throws(
      () => parseMacosNativeLaunchdHelperSelfTest(JSON.stringify(expected), 'noise'),
      MacosNativeLaunchdHelperError,
    );
  });

  it('contains only the fixed launchd/Mach denial surface', async () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
    const source = await fs.readFile(path.join(root, 'native', 'macos-launchd-denial-helper.c'), 'utf8');
    for (const required of [
      'bootstrap_check_in(bootstrap_port, SERVICE_NAME',
      'getpwuid(geteuid())',
      'account->pw_name == NULL',
      'account->pw_uid != geteuid()',
      'strcmp(account->pw_name, ACCOUNT_NAME)',
      'nonce_nonzero(buffer->request.nonce)',
      'MACH_RCV_TRAILER_AUDIT',
      'MACH_MSGH_BITS_COMPLEX',
      'MACH_MSG_TYPE_MOVE_SEND_ONCE',
      'audit_token_to_pidversion',
      'authorization_denied = 1u',
      'RECEIVE_TIMEOUT_MS',
      'SEND_TIMEOUT_MS',
    ]) assert.ok(source.includes(required), required);
    assert.equal(source.match(/bootstrap_check_in\(/g)?.length, 1);
    assert.equal(source.includes('bootstrap_register'), false);
    assert.equal(source.includes('bootstrap_look_up'), false);
    for (const forbidden of [
      '#include <sys/socket', '#include <net', '#include <Security',
      'SecKeychain', 'NSURLSession', 'CFHTTP', 'curl_', 'socket(', 'connect(',
      'fork(', 'exec(', 'posix_spawn', 'system(', 'popen(', 'getenv(',
      'AuthorizationExecuteWithPrivileges', 'task_for_pid', 'xpc_',
    ]) assert.equal(source.includes(forbidden), false, forbidden);
    assert.equal(/\b(open|fopen|write|unlink|mkdir|chmod|chown)\s*\(/.test(source), false);
  });

  it('builds reproducibly, self-tests, rejects ambient no-arg use, and cleans up', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const tempRoot = await fs.realpath(os.tmpdir());
    const before = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-launchd-helper-')));
    const result = await inspectMacosNativeLaunchdHelperScaffold();
    assert.deepEqual(result, {
      ...valid(),
      same_host_reproducible_build_verified: true,
      source_snapshot_bound: true,
      outside_launchd_rejected: true,
      private_temp_cleanup_required: true,
      collector_trust_verified: false,
      live_test_verified: false,
      authorization_ready: false,
    });
    const after = new Set((await fs.readdir(tempRoot)).filter((name) =>
      name.startsWith('bw-agent-launchd-helper-')));
    assert.deepEqual(after, before);
  });

  it('accepts no build paths, service names, commands, approval, or other caller input', () => {
    assert.equal(inspectMacosNativeLaunchdHelperScaffold.length, 0);
    assert.throws(
      () => parseMacosNativeLaunchdHelperSelfTest(JSON.stringify(valid({ approval: true }))),
      MacosNativeLaunchdHelperError,
    );
  });

  it('uses argument-array tooling and never exposes compiler output or recursive cleanup', async () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
    const runner = await fs.readFile(path.join(root, 'src', 'macos-native-launchd-helper.mjs'), 'utf8');
    assert.ok(runner.includes("executeSuccess('/usr/bin/clang', ["));
    assert.ok(runner.includes('fs.constants.O_NOFOLLOW'));
    assert.ok(runner.includes('fs.constants.O_EXCL'));
    assert.ok(runner.includes('await sourceHandle.sync()'));
    assert.equal(runner.includes('exec('), false);
    assert.equal(runner.includes('shell:'), false);
    assert.equal(runner.includes('fs.rm('), false);
    assert.equal(runner.includes('process.env'), false);
    assert.equal(runner.includes('error.stdout'), true);
    assert.equal(runner.includes('error.stderr'), true);
  });
});
