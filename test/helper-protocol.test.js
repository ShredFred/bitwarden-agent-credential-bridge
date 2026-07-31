import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { buildApplyManifest } from '../src/apply-manifest.mjs';
import {
  authorizeHelperRequest,
  buildHelperRequest,
  encodeHelperResponse,
  HelperProtocolError,
  parseHelperRequest,
} from '../src/helper-protocol.mjs';

const launcher = Buffer.from('fake helper launcher');
const launcherSha256 = createHash('sha256').update(launcher).digest('hex');
const workspace = Object.freeze({
  platform: 'linux',
  root: '/tmp/bw-agent-bridge-disposable-test',
  nonce: 'a'.repeat(64),
  homedir: '/tmp/bw-agent-bridge-disposable-test/home',
  env: {
    XDG_CONFIG_HOME: '/tmp/bw-agent-bridge-disposable-test/home/.config',
    XDG_DATA_HOME: '/tmp/bw-agent-bridge-disposable-test/home/.local/share',
  },
});
const observed = {
  config_dir: 'absent',
  config_file: 'absent',
  install_root: 'absent',
  bin_dir: 'absent',
  launcher: { kind: 'absent' },
};
const manifest = buildApplyManifest({
  platform: workspace.platform,
  homedir: workspace.homedir,
  env: workspace.env,
  launcherBytes: launcher,
  observed,
});
const requestId = 'b'.repeat(32);
const peerEvidence = Object.freeze({
  local_transport: true,
  identity_verified: true,
  different_principal: true,
  caller_write_denied: true,
  helper_write_allowed: true,
});

function built() {
  return buildHelperRequest({
    requestId,
    workspace,
    manifest,
    launcherSha256,
    launcherByteLength: launcher.byteLength,
  });
}

function expected(overrides = {}) {
  return {
    workspace,
    manifest,
    launcherSha256,
    launcherByteLength: launcher.byteLength,
    peerEvidence,
    ...overrides,
  };
}

describe('separate-identity helper protocol', () => {
  it('builds and parses one byte-exact canonical bounded request', () => {
    const { request, bytes } = built();
    assert.deepEqual(parseHelperRequest(bytes), request);
    assert.equal(bytes.toString('utf8'), canonical(request));
    assert.equal(request.launcher.transport, 'inherited_readonly_handle');
    assert.equal('launcherBytes' in request, false);
    assert.equal(bytes.includes(launcher), false);
  });

  it('authorizes only an exact workspace, manifest, confirmation, and launcher binding', () => {
    const { bytes } = built();
    const authorized = authorizeHelperRequest(bytes, expected());
    assert.equal(authorized.request_id, requestId);
    for (const mismatch of [
      { workspace: { ...workspace, nonce: 'c'.repeat(64) } },
      { launcherSha256: 'd'.repeat(64) },
      { launcherByteLength: launcher.byteLength + 1 },
    ]) {
      assert.throws(
        () => authorizeHelperRequest(bytes, expected(mismatch)),
        (error) => error instanceof HelperProtocolError && error.code === 'request_binding_mismatch',
      );
    }
  });

  it('fails closed unless transport and distinct-writer evidence are all true', () => {
    const { bytes } = built();
    const cases = [
      ['local_transport', 'peer_identity_unverified'],
      ['identity_verified', 'peer_identity_unverified'],
      ['different_principal', 'same_principal_rejected'],
      ['caller_write_denied', 'caller_write_not_denied'],
      ['helper_write_allowed', 'helper_write_not_allowed'],
    ];
    for (const [field, code] of cases) {
      assert.throws(
        () => authorizeHelperRequest(bytes, expected({ peerEvidence: { ...peerEvidence, [field]: false } })),
        (error) => error instanceof HelperProtocolError && error.code === code,
      );
    }
    for (const value of [1, 'false', null]) {
      assert.throws(
        () => authorizeHelperRequest(bytes, expected({
          peerEvidence: { ...peerEvidence, different_principal: value },
        })),
        (error) => error instanceof HelperProtocolError && error.code === 'peer_identity_unverified',
      );
    }
    assert.throws(
      () => authorizeHelperRequest(Buffer.from('{'), expected({
        peerEvidence: { ...peerEvidence, identity_verified: false },
      })),
      (error) => error instanceof HelperProtocolError && error.code === 'peer_identity_unverified',
    );
  });

  it('rejects non-canonical, malformed, invalid UTF-8, oversized, and extended requests', () => {
    const { request, bytes } = built();
    assert.throws(() => parseHelperRequest(Buffer.from(`${bytes.toString('utf8')}\n`)), /non_canonical_request/);
    assert.throws(() => parseHelperRequest(Buffer.from('{')), /invalid_json/);
    assert.throws(() => parseHelperRequest(Uint8Array.from([0xff])), /invalid_utf8/);
    assert.throws(() => parseHelperRequest(Buffer.alloc(64 * 1024 + 1)), /request_too_large/);
    const extended = { ...request, unexpected: true };
    const extendedBytes = Buffer.from(canonical(extended));
    assert.throws(() => parseHelperRequest(extendedBytes), /invalid_request|non_canonical_request/);
  });

  it('rejects tampered manifest and caller-selected launcher transport', () => {
    const { request } = built();
    const tampered = structuredClone(request);
    tampered.manifest.payload.content.launcher_sha256 = 'e'.repeat(64);
    assert.throws(() => parseHelperRequest(Buffer.from(canonical(tampered))), /invalid_request/);
    const wrongTransport = structuredClone(request);
    wrongTransport.launcher.transport = 'path';
    assert.throws(() => parseHelperRequest(Buffer.from(canonical(wrongTransport))), /invalid_request/);
    const splitDigest = structuredClone(request);
    splitDigest.launcher.sha256 = 'f'.repeat(64);
    assert.throws(() => parseHelperRequest(Buffer.from(canonical(splitDigest))), /invalid_request/);
  });

  it('maps malformed expected bindings to stable protocol errors', () => {
    const { bytes } = built();
    for (const malformed of [null, {}, { ...expected(), workspace: null }]) {
      assert.throws(
        () => authorizeHelperRequest(bytes, malformed),
        (error) => error instanceof HelperProtocolError,
      );
    }
  });

  it('encodes only fixed value-free response fields and enforces code consistency', () => {
    const bytes = encodeHelperResponse({
      requestId,
      ok: false,
      code: 'same_principal_rejected',
      completedActions: 0,
      rollback: 'not_started',
    });
    const response = JSON.parse(bytes.toString('utf8'));
    assert.deepEqual(Object.keys(response).sort(), [
      'code', 'completed_actions', 'ok', 'protocol_version', 'request_id', 'rollback',
    ]);
    assert.equal(bytes.includes(Buffer.from(workspace.root)), false);
    assert.throws(() => encodeHelperResponse({
      requestId,
      ok: true,
      code: 'same_principal_rejected',
      completedActions: 0,
      rollback: 'not_started',
    }), /invalid_request/);
  });
});

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
