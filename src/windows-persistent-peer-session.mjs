import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { types as utilTypes } from 'node:util';
import { isWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';
import { publishWindowsHelperServiceBinary } from './windows-helper-publish.mjs';
import { requireWindowsHelperPublishBinding } from './windows-helper-package-binding.mjs';
import {
  absentWindowsServerIdentityFacts,
  parseWindowsServerIdentityVerifierResult,
} from './windows-handle-bound-identity.mjs';
import { collectWindowsTargetAclEvidence } from './windows-target-acl-matrix.mjs';
import { isWindowsTargetAclEvidence } from './windows-production-authorization.mjs';

/**
 * Phase 9d: different-principal persistent pipe session → Phase 5h.1 five-facts.
 *
 * Composes:
 * - native `--self-test-pipe-client service-denial` against the fixed LocalService pipe;
 * - Phase 5h.13 `--verify-fixed-server-identity`;
 * - Phase 9c target-ACL evidence (collected or injected branded).
 *
 * Same-user / absent-service hosts must not invent different_principal=true.
 * Public reports keep authorization_ready=false; operational wire-up is Phase 9e.
 */

const HELPER_EXE = 'BitwardenAgentCredentialBridgeHelper.exe';

const PEER_FIELDS = new Set([
  'local_transport',
  'identity_verified',
  'different_principal',
  'caller_write_denied',
  'helper_write_allowed',
]);

const DENIAL_CLIENT_FIELDS = new Set([
  'schema_version',
  'narrow_pipe_rights',
  'create_pipe_instance_right_absent',
  'response_schema_exact',
  'different_principal',
  'authorization_denied',
]);

const BOOLEAN_DENIAL = [...DENIAL_CLIENT_FIELDS].filter((field) => field !== 'schema_version');

export class WindowsPersistentPeerSessionError extends Error {
  constructor(code = 'invalid_persistent_peer_session') {
    super(`Windows persistent peer session rejected: ${code}`);
    this.name = 'WindowsPersistentPeerSessionError';
    this.code = code;
  }
}

const VALID_PEER = new WeakSet();
const VALID_REPORTS = new WeakSet();

/**
 * Brand exact Phase 5h.1 peer five-facts for later Phase 9e wiring.
 * Clones are rejected.
 */
export function brandWindowsPeerAuthorizationEvidence(raw) {
  const evidence = exactObject(raw, PEER_FIELDS, 'invalid_peer_evidence');
  for (const field of PEER_FIELDS) {
    if (typeof evidence[field] !== 'boolean') {
      throw new WindowsPersistentPeerSessionError('invalid_peer_evidence');
    }
  }
  VALID_PEER.add(evidence);
  return evidence;
}

export function isWindowsPeerAuthorizationEvidence(value) {
  return value !== null && typeof value === 'object' && VALID_PEER.has(value);
}

export function parseWindowsServiceDenialClientReport(stdout, stderr = '') {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || stderr.trim() !== '') {
    throw new WindowsPersistentPeerSessionError('invalid_denial_client_report');
  }
  let value;
  try {
    const normalized = stdout.startsWith('\uFEFF') ? stdout.slice(1) : stdout;
    value = JSON.parse(normalized.trim());
  } catch {
    throw new WindowsPersistentPeerSessionError('invalid_denial_client_report');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsPersistentPeerSessionError('invalid_denial_client_report');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== DENIAL_CLIENT_FIELDS.size ||
      keys.some((key) => typeof key !== 'string' || !DENIAL_CLIENT_FIELDS.has(key)) ||
      value.schema_version !== 1 ||
      BOOLEAN_DENIAL.some((field) => typeof value[field] !== 'boolean')) {
    throw new WindowsPersistentPeerSessionError('invalid_denial_client_report');
  }
  if (value.authorization_denied !== true ||
      value.narrow_pipe_rights !== true ||
      value.create_pipe_instance_right_absent !== true ||
      value.response_schema_exact !== true) {
    throw new WindowsPersistentPeerSessionError('invalid_denial_client_report');
  }
  return Object.freeze({ ...value });
}

/**
 * Map denial-client + identity + target-ACL facts into Phase 5h.1 five-facts.
 * Never invents different_principal without a verified service-denial peer.
 */
export function mapWindowsPersistentPeerSessionToEvidence(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new WindowsPersistentPeerSessionError('invalid_peer_session_input');
  }
  const keys = Reflect.ownKeys(input);
  const allowed = new Set(['denialClient', 'identity', 'targetAcl', 'pipeConnected']);
  if (keys.length < 3 || keys.length > 4 ||
      keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    throw new WindowsPersistentPeerSessionError('invalid_peer_session_input');
  }

  const pipeConnected = input.pipeConnected === true;
  let denial = null;
  if (input.denialClient !== null && input.denialClient !== undefined) {
    denial = parseWindowsServiceDenialClientReport(
      `${JSON.stringify(input.denialClient)}\n`,
      '',
    );
  }

  const identity = input.identity === null || input.identity === undefined
    ? absentWindowsServerIdentityFacts()
    : parseWindowsServerIdentityVerifierResult(`${JSON.stringify(input.identity)}\n`, '');

  let acl = {
    all_targets_checked: false,
    caller_write_denied: false,
    helper_write_allowed: false,
  };
  if (input.targetAcl !== null && input.targetAcl !== undefined) {
    if (isWindowsTargetAclEvidence(input.targetAcl)) {
      acl = input.targetAcl;
    } else {
      // Accept exact unbranded Phase 9a ACL shape for pure mapping tests.
      acl = exactObject(input.targetAcl, new Set([
        'schema_version',
        'all_targets_checked',
        'caller_write_denied',
        'helper_write_allowed',
        'ownership_trusted_not_caller',
        'shared_local_service_token_user_owner_absent',
        'reparse_points_absent',
      ]), 'invalid_target_acl');
      if (acl.schema_version !== 1) {
        throw new WindowsPersistentPeerSessionError('invalid_target_acl');
      }
    }
  }

  const serviceDenialOk = pipeConnected === true &&
    denial !== null &&
    denial.different_principal === true &&
    denial.authorization_denied === true;

  const identityVerified = identity.server_identity_verified === true &&
    identity.server_token_user_local_service === true &&
    identity.service_sid_group_enabled === true &&
    identity.scm_server_pid_match === true &&
    identity.request_sent === false &&
    identity.authorization_denied === true;

  const localTransport = serviceDenialOk === true;
  const differentPrincipal = serviceDenialOk === true && identityVerified === true;
  // Console/same-user hosts must never claim different_principal from client-only bits.
  if (denial !== null && denial.different_principal === true && !identityVerified) {
    // Keep different_principal false until SCM/LocalService identity is proven.
  }

  return Object.freeze({
    local_transport: localTransport,
    identity_verified: identityVerified,
    different_principal: differentPrincipal,
    caller_write_denied: acl.all_targets_checked === true && acl.caller_write_denied === true,
    helper_write_allowed: acl.all_targets_checked === true && acl.helper_write_allowed === true,
  });
}

/**
 * Collect a live persistent peer session for a branded persistent layout plan.
 *
 * @param {object} layoutPlan branded Phase 5h.47 persistent layout
 * @param {{ helperExecutablePath?: string, targetAclEvidence?: object }} [options]
 */
export async function collectWindowsPersistentPeerSession(layoutPlan, options = {}) {
  if (process.platform !== 'win32') {
    throw new WindowsPersistentPeerSessionError('unsupported_platform');
  }
  if (!isWindowsHelperLayoutPlan(layoutPlan) || layoutPlan.layout_mode !== 'persistent') {
    throw new WindowsPersistentPeerSessionError('invalid_persistent_layout');
  }
  if (options !== null && typeof options === 'object' && utilTypes.isProxy(options)) {
    throw new WindowsPersistentPeerSessionError('invalid_options');
  }

  let helperPath = typeof options.helperExecutablePath === 'string'
    ? options.helperExecutablePath
    : null;
  let cleanupDir = null;
  if (helperPath === null) {
    const published = requireWindowsHelperPublishBinding(
      await publishWindowsHelperServiceBinary(),
    );
    if (published.sha256 !== layoutPlan.binary.sha256 ||
        published.byteLength !== layoutPlan.binary.byte_length) {
      throw new WindowsPersistentPeerSessionError('binary_binding_mismatch');
    }
    cleanupDir = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-peer-'));
    helperPath = path.join(cleanupDir, HELPER_EXE);
    await fs.writeFile(helperPath, published.bytes, { flag: 'wx' });
  }

  try {
    const denial = await runServiceDenialClient(helperPath);
    const identity = await runIdentityVerifier(helperPath);

    let targetAcl = options.targetAclEvidence;
    if (targetAcl !== undefined && targetAcl !== null) {
      if (!isWindowsTargetAclEvidence(targetAcl)) {
        throw new WindowsPersistentPeerSessionError('unbranded_target_acl');
      }
    } else {
      const aclResult = await collectWindowsTargetAclEvidence(layoutPlan);
      targetAcl = aclResult.evidence;
    }

    const peer = mapWindowsPersistentPeerSessionToEvidence({
      denialClient: denial.report,
      identity,
      targetAcl,
      pipeConnected: denial.connected,
    });
    const brandedPeer = brandWindowsPeerAuthorizationEvidence(peer);

    const complete = brandedPeer.local_transport &&
      brandedPeer.identity_verified &&
      brandedPeer.different_principal &&
      brandedPeer.caller_write_denied &&
      brandedPeer.helper_write_allowed;

    let terminalCode = 'peer_session_incomplete';
    if (complete) {
      terminalCode = 'different_principal_peer_complete';
    } else if (denial.connected && !brandedPeer.different_principal) {
      terminalCode = 'same_principal_rejected';
    } else if (brandedPeer.different_principal && !complete) {
      terminalCode = 'different_principal_denial_acl_incomplete';
    }

    const report = Object.freeze({
      schema_version: 1,
      platform: 'win32',
      collector: 'persistent_different_principal_peer_session',
      peer_authorization_complete: complete,
      pipe_connected: denial.connected,
      service_denial_verified: denial.connected && denial.report?.different_principal === true,
      helper_vault_free: true,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
      mutation_authorized: false,
      operational_bridge_unwired: true,
      authorization_ready: false,
      terminal_code: terminalCode,
      peer: brandedPeer,
    });
    VALID_REPORTS.add(report);
    return Object.freeze({ peerEvidence: brandedPeer, report });
  } finally {
    if (cleanupDir !== null) {
      await fs.rm(cleanupDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

export function isWindowsPersistentPeerSessionReport(value) {
  return value !== null && typeof value === 'object' && VALID_REPORTS.has(value);
}

async function runServiceDenialClient(helperPath) {
  const nonce = randomBytes(32).toString('hex');
  const result = await execCapture(helperPath, [
    '--self-test-pipe-client', 'service-denial', nonce,
  ], 8000, 4096);
  if (result.stderr.trim() !== '') {
    throw new WindowsPersistentPeerSessionError('denial_client_failed');
  }
  if (result.stdout.trim() === '') {
    // Exit 20 when the fixed pipe is absent, or schema mismatch against console.
    return { connected: false, report: null };
  }
  try {
    const report = parseWindowsServiceDenialClientReport(result.stdout, result.stderr);
    return { connected: true, report };
  } catch {
    return { connected: false, report: null };
  }
}

async function runIdentityVerifier(helperPath) {
  const result = await execCapture(helperPath, ['--verify-fixed-server-identity'], 8000, 4096);
  if (result.stderr.trim() !== '') {
    throw new WindowsPersistentPeerSessionError('identity_verifier_failed');
  }
  if (result.stdout.trim() === '') {
    return absentWindowsServerIdentityFacts();
  }
  return parseWindowsServerIdentityVerifierResult(result.stdout, result.stderr);
}

function execCapture(executable, args, timeoutMs, maxBuffer) {
  return new Promise((resolve, reject) => {
    execFile(executable, args, {
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer,
      encoding: 'utf8',
      env: {
        SystemRoot: process.env.SystemRoot,
        WINDIR: process.env.SystemRoot,
        TEMP: os.tmpdir(),
        TMP: os.tmpdir(),
      },
    }, (error, stdout, stderr) => {
      if (error && error.killed) {
        reject(new WindowsPersistentPeerSessionError('timeout_or_terminated'));
        return;
      }
      resolve({
        code: error && typeof error.code === 'number' ? error.code : 0,
        stdout: typeof stdout === 'string' ? stdout : '',
        stderr: typeof stderr === 'string' ? stderr : '',
      });
    });
  });
}

function exactObject(value, fields, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsPersistentPeerSessionError(code);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size ||
      keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsPersistentPeerSessionError(code);
  }
  const snapshot = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new WindowsPersistentPeerSessionError(code);
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value, enumerable: true, writable: false, configurable: false,
    });
  }
  return Object.freeze(snapshot);
}
