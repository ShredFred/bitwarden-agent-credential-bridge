import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ApplyManifestError,
  buildApplyManifest,
  canonicalJson,
  verifyManifestConfirmation,
} from '../src/apply-manifest.mjs';

const absent = {
  config_dir: 'absent',
  config_file: 'absent',
  install_root: 'absent',
  bin_dir: 'absent',
  launcher: { kind: 'absent' },
};
const base = {
  platform: 'linux',
  homedir: '/home/fake',
  launcherBytes: Buffer.from('#!/bin/sh\nexit 1\n'),
  observed: absent,
};

describe('pure apply/rollback manifest', () => {
  it('builds a deterministic first-install manifest without returning content', () => {
    const first = buildApplyManifest(base);
    const second = buildApplyManifest({ ...base, launcherBytes: Buffer.from(base.launcherBytes) });
    assert.deepEqual(first, second);
    assert.equal(first.confirmation, `APPLY ${first.manifest_sha256}`);
    assert.equal(verifyManifestConfirmation(first, first.confirmation), true);
    const serialized = JSON.stringify(first);
    assert.ok(!serialized.includes('#!/bin/sh'));
    assert.ok(!serialized.includes('item_id'));
    assert.deepEqual(first.payload.forward.map((entry) => entry.kind), [
      'create_directory_exclusive',
      'create_file_exclusive',
      'create_directory_exclusive',
      'create_directory_exclusive',
      'create_file_atomic_exclusive',
    ]);
    assert.deepEqual(first.payload.rollback.map((entry) => entry.kind), [
      'remove_file_if_digest_matches',
      'remove_directory_if_empty',
      'remove_directory_if_empty',
      'remove_file_if_digest_matches',
      'remove_directory_if_empty',
    ]);
  });

  it('binds an upgrade to the managed prior digest and an absent deterministic backup', () => {
    const prior = 'a'.repeat(64);
    const manifest = buildApplyManifest({
      ...base,
      observed: {
        config_dir: 'secure_directory',
        config_file: 'secure_file',
        install_root: 'secure_directory',
        bin_dir: 'secure_directory',
        launcher: { kind: 'managed_file', sha256: prior },
      },
    });
    assert.equal(manifest.payload.forward[0].kind, 'assert_path_absent');
    assert.match(manifest.payload.forward[0].target, /\.rollback-[0-9a-f]{24}$/);
    assert.equal(manifest.payload.forward[1].expected_sha256, prior);
    assert.equal(manifest.payload.rollback[0].kind, 'restore_file_exclusive');
    assert.equal(manifest.payload.rollback[0].expected_source_sha256, prior);
  });

  it('requires full-digest confirmation and rejects any payload tampering', () => {
    const manifest = buildApplyManifest(base);
    assert.equal(verifyManifestConfirmation(manifest, `APPLY ${manifest.manifest_sha256.slice(0, 16)}`), false);
    assert.equal(verifyManifestConfirmation(manifest, `APPLY ${'0'.repeat(64)}`), false);
    const tampered = JSON.parse(JSON.stringify(manifest));
    tampered.payload.platform = 'darwin';
    assert.equal(verifyManifestConfirmation(tampered, tampered.confirmation), false);
    assert.equal(verifyManifestConfirmation({ payload: [], manifest_sha256: 'a'.repeat(64), confirmation: `APPLY ${'a'.repeat(64)}` }, `APPLY ${'a'.repeat(64)}`), false);
  });

  it('rejects unknown, accessor, incoherent, and unbounded observed inputs', () => {
    const accessor = { ...absent };
    Object.defineProperty(accessor, 'config_file', { enumerable: true, get: () => 'absent' });
    const launcherAccessor = {};
    Object.defineProperty(launcherAccessor, 'kind', { enumerable: true, get: () => 'absent' });
    for (const observed of [
      { ...absent, extra: true },
      { ...absent, config_dir: 'absent', config_file: 'secure_file' },
      { ...absent, install_root: 'absent', bin_dir: 'secure_directory' },
      { ...absent, bin_dir: 'absent', launcher: { kind: 'managed_file', sha256: 'a'.repeat(64) } },
      { ...absent, launcher: { kind: 'managed_file', sha256: 'bad' } },
      accessor,
      { ...absent, launcher: launcherAccessor },
    ]) assert.throws(() => buildApplyManifest({ ...base, observed }), ApplyManifestError);
    assert.throws(() => buildApplyManifest({ ...base, launcherBytes: Buffer.alloc(0) }), /invalid_launcher/);
    assert.throws(() => buildApplyManifest({ ...base, launcherBytes: Buffer.alloc(1024 * 1024 + 1) }), /invalid_launcher/);
  });

  it('canonicalizes key order and rejects accessors and non-canonical values', () => {
    assert.equal(canonicalJson({ z: 1, a: { d: 2, b: 1 } }), '{"a":{"b":1,"d":2},"z":1}');
    const accessor = {};
    Object.defineProperty(accessor, 'secret', { enumerable: true, get: () => 'value' });
    assert.throws(() => canonicalJson(accessor), /non_canonical_value/);
    const arrayAccessor = [];
    Object.defineProperty(arrayAccessor, '0', { enumerable: true, configurable: true, get: () => 'value' });
    arrayAccessor.length = 1;
    assert.throws(() => canonicalJson(arrayAccessor), /non_canonical_value/);
    assert.throws(() => canonicalJson({ value: 1.5 }), /non_canonical_value/);
  });

  it('supports internally derived Windows and macOS manifests only', () => {
    const win = buildApplyManifest({ ...base, platform: 'win32', homedir: 'C:\\Users\\fake', env: { LOCALAPPDATA: 'C:\\Users\\fake\\AppData\\Local' } });
    const mac = buildApplyManifest({ ...base, platform: 'darwin', homedir: '/Users/fake' });
    assert.match(win.payload.paths.launcher, /bw-agent-bridge\.cmd$/);
    assert.match(mac.payload.paths.launcher, /bw-agent-bridge$/);
    assert.ok(win.payload.forward.every((entry) => entry.permission === undefined || entry.permission === 'current_user_system_admin_write'));
  });
});
