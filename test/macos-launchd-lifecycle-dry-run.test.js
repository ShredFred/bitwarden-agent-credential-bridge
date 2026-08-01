import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  MacosLaunchdLifecycleDryRunError,
  parseMacosLaunchdLifecycleDryRunProbe,
  runMacosLaunchdLifecycleDryRun,
} from '../src/macos-launchd-lifecycle-dry-run.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

function valid(overrides = {}) {
  return {
    schema_version: 1,
    account_name_absent: true,
    account_uniqueid_candidate_available: true,
    account_generateduid_candidate_available: true,
    plist_absent: true,
    binary_absent: true,
    launchd_label_unloaded: true,
    mach_service_unbound: true,
    parent_directories_secure: true,
    run_private_identity_selectable: true,
    mutation_performed: false,
    ...overrides,
  };
}

describe('macOS LaunchDaemon lifecycle read-only dry run', () => {
  it('parses only the exact coherent value-free probe schema', () => {
    assert.deepEqual(parseMacosLaunchdLifecycleDryRunProbe(`${JSON.stringify(valid())}\n`), valid());
    for (const value of [
      { ...valid(), extra: true },
      valid({ mutation_performed: true }),
      valid({ account_name_absent: false }),
      valid({ launchd_label_unloaded: false }),
    ]) assert.throws(
      () => parseMacosLaunchdLifecycleDryRunProbe(JSON.stringify(value)),
      (error) => error instanceof MacosLaunchdLifecycleDryRunError &&
        error.code === 'invalid_probe_output',
    );
    assert.throws(() => parseMacosLaunchdLifecycleDryRunProbe('{}', 'noise'));
    assert.throws(() => parseMacosLaunchdLifecycleDryRunProbe(`${' '.repeat(4096)}{}`));
    assert.throws(() => parseMacosLaunchdLifecycleDryRunProbe(`${JSON.stringify(valid())}\0`));
  });

  it('contains only fixed read-only host operations and no mutation or elevation path', async () => {
    const source = await fs.readFile(
      path.join(ROOT, 'scripts', 'macos-launchd-lifecycle-dry-run-probe.mjs'), 'utf8',
    );
    for (const forbidden of [
      /\bbootstrap\b/, /\bbootout\b/, /\bkickstart\b/, /\bcreate\b/i, /\bdelete\b/i,
      /\bunlink\b/, /\bchmod\b/, /\bchown\b/, /sudo/, /osascript/, /AuthorizationCreate/,
      /bootstrap_look_up/, /bootstrap_check_in/, /Keychain/, /Bitwarden/, /https?:/,
    ]) assert.equal(forbidden.test(source), false, forbidden);
    assert.match(source, /\['print', 'system'\]/);
    assert.match(source, /LABEL_ABSENT_STDERR/);
    assert.match(source, /hasExtendedAcl\(cursor\)/);
    assert.match(source, /\['\.', '-search', '\/Users'/);
    assert.match(source, /mutation_performed: false/);
    const runner = await fs.readFile(
      path.join(ROOT, 'src', 'macos-launchd-lifecycle-dry-run.mjs'), 'utf8',
    );
    assert.match(runner, /O_RDONLY \| fsConstants\.O_NOFOLLOW/);
    assert.match(runner, /\['--input-type=module', '-'\]/);
    assert.match(runner, /cwd: '\/'/);
    assert.match(runner, /child\.stdin\.end\(sourceBytes\)/);
  });

  it('accepts no input and returns only non-authorizing value-free facts on macOS', async (context) => {
    await assert.rejects(() => runMacosLaunchdLifecycleDryRun({ approval: true }),
      (error) => error instanceof MacosLaunchdLifecycleDryRunError && error.code === 'input_forbidden');
    if (process.platform !== 'darwin') {
      await assert.rejects(() => runMacosLaunchdLifecycleDryRun(),
        (error) => error instanceof MacosLaunchdLifecycleDryRunError &&
          error.code === 'unsupported_platform');
      return;
    }
    const result = await runMacosLaunchdLifecycleDryRun();
    assert.equal(result.package_binding_verified, true);
    assert.equal(result.mutation_performed, false);
    assert.equal(result.collector_trust_verified, false);
    assert.equal(result.live_test_verified, false);
    assert.equal(result.authorization_ready, false);
    assert.equal(result.install_gate_eligible, false);
    assert.ok(['dry_run_complete_untrusted', 'preflight_failed'].includes(result.terminal_code));
    const serialized = JSON.stringify(result).toLowerCase();
    for (const forbidden of ['_bwagentbridge', '/library/', 'uid', 'guid', 'launchctl', 'dscl', 'output']) {
      assert.equal(serialized.includes(forbidden), false, forbidden);
    }
  });
});
