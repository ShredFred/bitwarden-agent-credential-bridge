import { createHash } from 'node:crypto';
import { isWindowsHelperLayoutPlan } from './windows-helper-layout-plan.mjs';
import { evaluateWindowsServiceAuthorizeSchema } from './windows-service-authorize-schema.mjs';

export class WindowsHelperDisposableApplyError extends Error {
  constructor(code) {
    super(`Windows helper disposable apply rejected: ${code}`);
    this.name = 'WindowsHelperDisposableApplyError';
    this.code = code;
  }
}

const VALID_ENVELOPES = new WeakSet();

/**
 * Build a branded authorize+execute envelope for a disposable LocalService apply
 * under a ProgramData-class disposable layout. Secrets never enter this envelope.
 */
export function buildWindowsHelperDisposableApplyEnvelope(layoutPlan, authorizeRequest) {
  if (!isWindowsHelperLayoutPlan(layoutPlan) || layoutPlan.layout_mode !== 'disposable') {
    throw new WindowsHelperDisposableApplyError('invalid_layout_plan');
  }
  const authorize = evaluateWindowsServiceAuthorizeSchema(authorizeRequest);
  if (authorizeRequest.operation !== 'apply_disposable_manifest') {
    throw new WindowsHelperDisposableApplyError('invalid_operation');
  }

  const envelope = deepFreeze({
    schema_version: 1,
    platform: 'win32',
    layout_mode: 'disposable',
    authorize,
    helper_vault_free: true,
    retained_handle_apply_required: true,
    rollback_required: true,
    mutation_authorized: false,
    live_test_executed: false,
    install_gate_eligible: false,
    authorization_ready: false,
    terminal_code: 'disposable_apply_envelope_deny_until_helper_execute',
  });
  VALID_ENVELOPES.add(envelope);
  return envelope;
}

export function isWindowsHelperDisposableApplyEnvelope(value) {
  return value !== null && typeof value === 'object' && VALID_ENVELOPES.has(value);
}

/**
 * Simulate helper-side disposable first-install of the five exclusive paths
 * under an OS-temp ProgramData-class stand-in. No vault material is accepted.
 */
export async function executeWindowsHelperDisposableApplySimulation(envelope, options) {
  if (!isWindowsHelperDisposableApplyEnvelope(envelope)) {
    throw new WindowsHelperDisposableApplyError('invalid_envelope');
  }
  const root = exactString(options?.root);
  const launcherBytes = options?.launcherBytes;
  if (!(launcherBytes instanceof Uint8Array) || launcherBytes.byteLength < 1) {
    throw new WindowsHelperDisposableApplyError('invalid_launcher_bytes');
  }
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const digest = createHash('sha256').update(launcherBytes).digest('hex');
  const configDir = path.join(root, 'config');
  const configFile = path.join(configDir, 'config.json');
  const installRoot = path.join(root, 'install');
  const binDir = path.join(root, 'bin');
  const launcher = path.join(binDir, 'launcher');
  await fs.mkdir(root, { recursive: true });
  await fs.mkdir(configDir, { recursive: false });
  await fs.mkdir(installRoot, { recursive: false });
  await fs.mkdir(binDir, { recursive: false });
  await fs.writeFile(configFile, '{"version":1,"services":{}}\n', { flag: 'wx' });
  await fs.writeFile(launcher, launcherBytes, { flag: 'wx' });
  const written = await fs.readFile(launcher);
  const writtenDigest = createHash('sha256').update(written).digest('hex');
  if (writtenDigest !== digest) {
    throw new WindowsHelperDisposableApplyError('digest_mismatch');
  }
  return Object.freeze({
    schema_version: 1,
    applied: true,
    paths_created: 5,
    rolled_back: false,
    helper_vault_free: true,
    digest_matched: true,
    mutation_authorized: false,
    authorization_ready: false,
    terminal_code: 'disposable_apply_simulated',
  });
}

function exactString(value) {
  if (typeof value !== 'string' || value.length < 3 || value.includes('\0')) {
    throw new WindowsHelperDisposableApplyError('invalid_root');
  }
  return value;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
