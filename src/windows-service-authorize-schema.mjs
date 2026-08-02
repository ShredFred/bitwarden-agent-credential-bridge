import { types as utilTypes } from 'node:util';

const ROOT_FIELDS = new Set([
  'protocol_version',
  'request_id',
  'operation',
  'workspace',
  'manifest_digest',
  'launcher',
]);
const WORKSPACE_FIELDS = new Set(['platform', 'root_digest', 'marker_nonce']);
const LAUNCHER_FIELDS = new Set(['sha256', 'byte_length']);
const OPERATIONS = new Set(['apply_disposable_manifest', 'apply_persistent_manifest']);
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_REQUEST_CHARS = 64 * 1024;

export class WindowsServiceAuthorizeSchemaError extends Error {
  constructor(code = 'invalid_authorize_request') {
    super(`Windows service authorize schema rejected: ${code}`);
    this.name = 'WindowsServiceAuthorizeSchemaError';
    this.code = code;
  }
}

/**
 * Validate a bounded helper authorize request intended for the LocalService pipe.
 * Always returns authorization denied and executor absent for this phase.
 */
export function evaluateWindowsServiceAuthorizeSchema(raw) {
  if (typeof raw === 'string') {
    if (raw.length === 0 || raw.length > MAX_REQUEST_CHARS) {
      throw new WindowsServiceAuthorizeSchemaError('request_too_large');
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new WindowsServiceAuthorizeSchemaError('invalid_json');
    }
    return evaluateWindowsServiceAuthorizeSchema(parsed);
  }

  const request = exactObject(raw, ROOT_FIELDS);
  if (request.protocol_version !== 1 || typeof request.request_id !== 'string' ||
      request.request_id.length < 8 || request.request_id.length > 128 ||
      !OPERATIONS.has(request.operation) || typeof request.manifest_digest !== 'string' ||
      !SHA256.test(request.manifest_digest)) {
    throw new WindowsServiceAuthorizeSchemaError();
  }

  const workspace = exactObject(request.workspace, WORKSPACE_FIELDS);
  if (workspace.platform !== 'win32' || typeof workspace.root_digest !== 'string' ||
      !SHA256.test(workspace.root_digest) || typeof workspace.marker_nonce !== 'string' ||
      !SHA256.test(workspace.marker_nonce)) {
    throw new WindowsServiceAuthorizeSchemaError('invalid_workspace');
  }

  const launcher = exactObject(request.launcher, LAUNCHER_FIELDS);
  if (typeof launcher.sha256 !== 'string' || !SHA256.test(launcher.sha256) ||
      !Number.isSafeInteger(launcher.byte_length) || launcher.byte_length < 1 ||
      launcher.byte_length > 1024 * 1024) {
    throw new WindowsServiceAuthorizeSchemaError('invalid_launcher');
  }

  return Object.freeze({
    schema_version: 1,
    request_schema_valid: true,
    operation_recognized: true,
    different_principal_required: true,
    target_acl_evidence_complete: false,
    manifest_executor_absent: true,
    vault_client_absent: true,
    network_stack_absent: true,
    mutation_authorized: false,
    authorization_denied: true,
    terminal_code: 'authorize_schema_valid_denied',
  });
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsServiceAuthorizeSchemaError();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsServiceAuthorizeSchemaError();
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsServiceAuthorizeSchemaError();
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
