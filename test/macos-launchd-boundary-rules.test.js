import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  digestDesignatedRequirementStdout,
  evaluateMacosLaunchdPlist,
  MACOS_HELPER_ACCOUNT,
  MACOS_HELPER_BINARY_PATH,
  MACOS_HELPER_LABEL,
} from '../src/macos-launchd-boundary-rules.mjs';

function valid(overrides = {}) {
  return {
    Label: MACOS_HELPER_LABEL,
    UserName: MACOS_HELPER_ACCOUNT,
    ProgramArguments: [MACOS_HELPER_BINARY_PATH],
    MachServices: { [MACOS_HELPER_LABEL]: true },
    ...overrides,
  };
}

describe('macOS launchd boundary pure rules', () => {
  it('accepts only the fixed helper, account, binary, and single Mach service', () => {
    assert.deepEqual(evaluateMacosLaunchdPlist(valid()), {
      system_domain_plist: true,
      demand_activation_only: true,
      mach_service_declared: true,
    });
    for (const candidate of [
      valid({ Label: 'caller.selected' }),
      valid({ UserName: 'root' }),
      valid({ ProgramArguments: ['/tmp/helper'] }),
      valid({ ProgramArguments: [MACOS_HELPER_BINARY_PATH, '--extra'] }),
      valid({ MachServices: { [MACOS_HELPER_LABEL]: true, extra: true } }),
      valid({ MachServices: { [MACOS_HELPER_LABEL]: false } }),
    ]) {
      const result = evaluateMacosLaunchdPlist(candidate);
      assert.equal(result.system_domain_plist && result.mach_service_declared, false);
    }
  });

  it('rejects every supported non-demand activation trigger', () => {
    for (const field of [
      'KeepAlive', 'RunAtLoad', 'StartInterval', 'StartCalendarInterval', 'StartOnMount',
      'QueueDirectories', 'WatchPaths', 'LaunchEvents', 'Sockets', 'PathState', 'OtherJobEnabled',
    ]) {
      assert.equal(evaluateMacosLaunchdPlist(valid({ [field]: true })).demand_activation_only, false, field);
    }
    assert.equal(evaluateMacosLaunchdPlist(valid({ KeepAlive: false })).demand_activation_only, true);
  });

  it('hashes exactly one canonical designated-requirement stdout record', () => {
    const record = 'designated => identifier "example.helper" and anchor apple generic\n';
    assert.equal(
      digestDesignatedRequirementStdout(record),
      createHash('sha256').update(Buffer.from(record, 'utf8')).digest('hex'),
    );
    const adHocRecord = '# designated => cdhash H"0123456789abcdef0123456789abcdef01234567"\n';
    assert.equal(
      digestDesignatedRequirementStdout(adHocRecord),
      createHash('sha256').update(Buffer.from(adHocRecord, 'utf8')).digest('hex'),
    );
    for (const invalid of [
      record.trimEnd(), `${record}\n`, `Executable=/private/path\n${record}`,
      'designated => one\ndesignated => two\n', 'designated => bad\0value\n',
      '# designated => identifier "not-adhoc"\n',
      '# designated => cdhash H"0123456789abcdef"\n',
      '# designated => cdhash H"0123456789ABCDEF0123456789ABCDEF01234567"\n', '', null,
    ]) assert.equal(digestDesignatedRequirementStdout(invalid), null);
  });
});
