import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { canonicalJson, verifyManifestConfirmation } from './apply-manifest.mjs';

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_WORKSPACE_PATH_CHARS = 512;
const MAX_LAUNCHER_BYTES = 1024 * 1024;
const REQUEST_FIELDS = new Set([
  'protocol_version',
  'request_id',
  'operation',
  'workspace',
  'manifest',
  'confirmation',
  'launcher',
]);
const WORKSPACE_FIELDS = new Set(['platform', 'root', 'marker_nonce']);
const LAUNCHER_FIELDS = new Set(['sha256', 'byte_length', 'transport']);
const PEER_FIELDS = new Set([
  'local_transport',
  'identity_verified',
  'different_principal',
  'caller_write_denied',
  'helper_write_allowed',
]);
const EXPECTED_FIELDS = new Set([
  'workspace',
  'manifest',
  'launcherSha256',
  'launcherByteLength',
  'peerEvidence',
]);

export const HELPER_RESPONSE_CODES = Object.freeze([
  'ok',
  'request_too_large',
  'invalid_utf8',
  'invalid_json',
  'non_canonical_request',
  'invalid_request',
  'request_binding_mismatch',
  'peer_identity_unverified',
  'same_principal_rejected',
  'caller_write_not_denied',
  'helper_write_not_allowed',
]);

export class HelperProtocolError extends Error {
  constructor(code) {
    super(`helper protocol rejected: ${code}`);
    this.name = 'HelperProtocolError';
    this.code = code;
  }
}

export function buildHelperRequest(input) {
  const request = validateRequest({
    protocol_version: 1,
    request_id: input.requestId,
    operation: 'apply_disposable_manifest',
    workspace: {
      platform: input.workspace?.platform,
      root: input.workspace?.root,
      marker_nonce: input.workspace?.nonce,
    },
    manifest: input.manifest,
    confirmation: input.manifest?.confirmation,
    launcher: {
      sha256: input.launcherSha256,
      byte_length: input.launcherByteLength,
      transport: 'inherited_readonly_handle',
    },
  });
  const bytes = Buffer.from(canonicalJson(request), 'utf8');
  if (bytes.byteLength > MAX_REQUEST_BYTES) throw new HelperProtocolError('request_too_large');
  return Object.freeze({ request, bytes });
}

export function parseHelperRequest(rawBytes) {
  if (!(rawBytes instanceof Uint8Array) || rawBytes.byteLength === 0) {
    throw new HelperProtocolError('invalid_request');
  }
  if (rawBytes.byteLength > MAX_REQUEST_BYTES) throw new HelperProtocolError('request_too_large');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes);
  } catch {
    throw new HelperProtocolError('invalid_utf8');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HelperProtocolError('invalid_json');
  }
  let canonical;
  try {
    canonical = canonicalJson(parsed);
  } catch {
    throw new HelperProtocolError('invalid_request');
  }
  if (canonical !== text) throw new HelperProtocolError('non_canonical_request');
  return validateRequest(parsed);
}

export function authorizeHelperRequest(rawBytes, expected) {
  const expectedInput = exactPlainObject(expected, EXPECTED_FIELDS);
  const peer = exactPlainObject(dataProperty(expectedInput, 'peerEvidence'), PEER_FIELDS);
  if (Object.values(peer).some((value) => typeof value !== 'boolean')) {
    throw new HelperProtocolError('peer_identity_unverified');
  }
  if (!peer.local_transport || !peer.identity_verified) {
    throw new HelperProtocolError('peer_identity_unverified');
  }
  if (!peer.different_principal) throw new HelperProtocolError('same_principal_rejected');
  if (!peer.caller_write_denied) throw new HelperProtocolError('caller_write_not_denied');
  if (!peer.helper_write_allowed) throw new HelperProtocolError('helper_write_not_allowed');

  const request = parseHelperRequest(rawBytes);
  let bindingMatches = false;
  try {
    const expectedWorkspace = dataProperty(expectedInput, 'workspace');
    const expectedManifest = dataProperty(expectedInput, 'manifest');
    bindingMatches = request.workspace.platform === dataProperty(expectedWorkspace, 'platform') &&
      request.workspace.root === dataProperty(expectedWorkspace, 'root') &&
      request.workspace.marker_nonce === dataProperty(expectedWorkspace, 'nonce') &&
      canonicalJson(request.manifest) === canonicalJson(expectedManifest) &&
      request.confirmation === dataProperty(expectedManifest, 'confirmation') &&
      request.launcher.sha256 === dataProperty(expectedInput, 'launcherSha256') &&
      request.launcher.byte_length === dataProperty(expectedInput, 'launcherByteLength');
  } catch {
    throw new HelperProtocolError('request_binding_mismatch');
  }
  if (!bindingMatches) throw new HelperProtocolError('request_binding_mismatch');
  return request;
}

export function encodeHelperResponse(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      typeof input.requestId !== 'string' || !/^[0-9a-f]{32}$/.test(input.requestId) ||
      typeof input.ok !== 'boolean' || !HELPER_RESPONSE_CODES.includes(input.code) ||
      !Number.isSafeInteger(input.completedActions) || input.completedActions < 0 ||
      !['not_started', 'not_needed', 'completed', 'failed'].includes(input.rollback)) {
    throw new HelperProtocolError('invalid_request');
  }
  if (input.ok !== (input.code === 'ok')) throw new HelperProtocolError('invalid_request');
  return Buffer.from(canonicalJson({
    protocol_version: 1,
    request_id: input.requestId,
    ok: input.ok,
    code: input.code,
    completed_actions: input.completedActions,
    rollback: input.rollback,
  }), 'utf8');
}

function validateRequest(raw) {
  const request = exactPlainObject(raw, REQUEST_FIELDS);
  const workspace = exactPlainObject(request.workspace, WORKSPACE_FIELDS);
  const launcher = exactPlainObject(request.launcher, LAUNCHER_FIELDS);
  if (request.protocol_version !== 1 || request.operation !== 'apply_disposable_manifest' ||
      typeof request.request_id !== 'string' || !/^[0-9a-f]{32}$/.test(request.request_id) ||
      !['win32', 'darwin', 'linux'].includes(workspace.platform) ||
      typeof workspace.root !== 'string' || workspace.root.length === 0 ||
      workspace.root.length > MAX_WORKSPACE_PATH_CHARS || workspace.root.includes('\0') ||
      !pathFor(workspace.platform).isAbsolute(workspace.root) ||
      typeof workspace.marker_nonce !== 'string' || !/^[0-9a-f]{64}$/.test(workspace.marker_nonce) ||
      !verifyManifestConfirmation(request.manifest, request.confirmation) ||
      request.manifest?.payload?.platform !== workspace.platform ||
      typeof launcher.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(launcher.sha256) ||
      launcher.sha256 !== request.manifest?.payload?.content?.launcher_sha256 ||
      !Number.isSafeInteger(launcher.byte_length) || launcher.byte_length < 1 ||
      launcher.byte_length > MAX_LAUNCHER_BYTES ||
      launcher.transport !== 'inherited_readonly_handle') {
    throw new HelperProtocolError('invalid_request');
  }
  return deepFreeze({
    protocol_version: request.protocol_version,
    request_id: request.request_id,
    operation: request.operation,
    workspace: { ...workspace },
    manifest: request.manifest,
    confirmation: request.confirmation,
    launcher: { ...launcher },
  });
}

function exactPlainObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new HelperProtocolError('invalid_request');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new HelperProtocolError('invalid_request');
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new HelperProtocolError('invalid_request');
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}

function dataProperty(value, key) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new HelperProtocolError('invalid_request');
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !('value' in descriptor)) throw new HelperProtocolError('invalid_request');
  return descriptor.value;
}

function pathFor(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
