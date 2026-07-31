import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { verifyDisposableWorkspace } from './disposable-workspace.mjs';
import { authorizeHelperRequest, HelperProtocolError } from './helper-protocol.mjs';
import { evaluateWindowsHelperPeerEvidence } from './windows-helper-evidence.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVER_SCRIPT = path.join(ROOT, 'scripts', 'windows-helper-pipe-probe.ps1');
const MAX_PROCESS_OUTPUT_BYTES = 4096;
const FACT_FIELDS = new Set([
  'schema_version', 'transport_kind', 'remote_clients_rejected', 'client_pid_verified',
  'server_pid_verified', 'caller_token_verified', 'helper_token_verified',
  'caller_token_user_sha256', 'helper_token_user_sha256', 'caller_is_restricted',
  'caller_is_app_container', 'acl_checks_verified', 'all_targets_checked',
  'caller_effective_write_denied', 'helper_required_write_allowed',
]);
const BOOLEAN_FIELDS = [...FACT_FIELDS].filter((field) => ![
  'schema_version', 'transport_kind', 'caller_token_user_sha256', 'helper_token_user_sha256',
].includes(field));

export class WindowsHelperPipeSessionError extends Error {
  constructor(code) {
    super(`Windows helper pipe session failed: ${code}`);
    this.name = 'WindowsHelperPipeSessionError';
    this.code = code;
  }
}

/**
 * Exercise a real PIPE_REJECT_REMOTE_CLIENTS transport and live TokenUser probes.
 * Same-user execution must end in same_principal_rejected and never applies.
 */
export async function verifyWindowsHelperPipeSamePrincipal(input, options = {}) {
  if (process.platform !== 'win32') throw new WindowsHelperPipeSessionError('unsupported_platform');
  const values = exactInput(input);
  await verifyDisposableWorkspace(values.workspace);
  const timeoutMs = options.timeoutMs ?? 10000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) {
    throw new WindowsHelperPipeSessionError('invalid_timeout');
  }

  const spawnImpl = options.spawnImpl ?? spawn;
  const pipeName = `bw-agent-bridge-${randomBytes(16).toString('hex')}`;
  let server;
  try {
    server = startServer(
      spawnImpl, pipeName, process.pid, process.pid, values.workspace, options.powershellPath,
    );
  } catch (error) {
    throw error;
  }
  const client = connectCallerToPipe(pipeName, values.workspace.nonce, timeoutMs);

  let results;
  try {
    results = await withTimeout(Promise.all([client.completion, server.completion]), timeoutMs, () => {
      client.abort();
      server.abort();
    });
  } catch (error) {
    client.abort();
    server.abort();
    if (error instanceof WindowsHelperPipeSessionError) throw error;
    throw new WindowsHelperPipeSessionError('session_failed');
  }
  const [, serverResult] = results;
  if (serverResult.code !== 0 || serverResult.stderr.byteLength !== 0) {
    throw new WindowsHelperPipeSessionError('probe_failed');
  }

  const facts = parseWindowsPipeFacts(serverResult.stdout);
  const peerEvidence = evaluateWindowsHelperPeerEvidence(facts);
  let authorizationCode;
  try {
    authorizeHelperRequest(values.requestBytes, {
      workspace: values.workspace,
      manifest: values.manifest,
      launcherSha256: values.launcherSha256,
      launcherByteLength: values.launcherByteLength,
      peerEvidence,
    });
    throw new WindowsHelperPipeSessionError('unexpected_authorization');
  } catch (error) {
    if (error instanceof WindowsHelperPipeSessionError) throw error;
    if (!(error instanceof HelperProtocolError)) {
      throw new WindowsHelperPipeSessionError('authorization_failed');
    }
    authorizationCode = error.code;
  }
  if (authorizationCode !== 'same_principal_rejected') {
    throw new WindowsHelperPipeSessionError('unexpected_authorization_result');
  }
  return Object.freeze({
    local_transport: peerEvidence.local_transport,
    identity_verified: peerEvidence.identity_verified,
    different_principal: peerEvidence.different_principal,
    authorization_code: authorizationCode,
  });
}

export function parseWindowsPipeFacts(raw) {
  if (!(raw instanceof Uint8Array) || raw.byteLength === 0 || raw.byteLength > MAX_PROCESS_OUTPUT_BYTES) {
    throw new WindowsHelperPipeSessionError('invalid_probe_output');
  }
  let text;
  let normalized;
  let value;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    normalized = text.startsWith('\uFEFF') ? text.slice(1) : text;
    value = JSON.parse(normalized.trim());
  } catch {
    throw new WindowsHelperPipeSessionError('invalid_probe_output');
  }
  const keys = value !== null && typeof value === 'object' && !Array.isArray(value)
    ? Reflect.ownKeys(value) : [];
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype || keys.length !== FACT_FIELDS.size ||
      keys.some((key) => typeof key !== 'string' || !FACT_FIELDS.has(key)) ||
      value.schema_version !== 1 || value.transport_kind !== 'windows_named_pipe' ||
      BOOLEAN_FIELDS.some((field) => typeof value[field] !== 'boolean') ||
      !/^[0-9a-f]{64}$/.test(value.caller_token_user_sha256) ||
      !/^[0-9a-f]{64}$/.test(value.helper_token_user_sha256) ||
      normalized !== `${JSON.stringify(value)}\r\n` && normalized !== `${JSON.stringify(value)}\n`) {
    throw new WindowsHelperPipeSessionError('invalid_probe_output');
  }
  return Object.freeze({ ...value });
}

function startServer(spawnImpl, pipeName, clientPid, callerPid, workspace, powershellOverride) {
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== 'string' || !path.win32.isAbsolute(systemRoot)) {
    throw new WindowsHelperPipeSessionError('invalid_system_root');
  }
  const executable = powershellOverride ?? path.win32.join(
    systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  return startBoundedProcess(spawnImpl, executable, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', SERVER_SCRIPT, pipeName, String(clientPid), String(callerPid), workspace.nonce,
  ], {
    cwd: workspace.root,
    env: { SystemRoot: systemRoot, WINDIR: systemRoot, TEMP: workspace.root, TMP: workspace.root },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  }, 'probe_start_failed');
}

function connectCallerToPipe(pipeName, nonce, timeoutMs) {
  const endpoint = `\\\\.\\pipe\\${pipeName}`;
  const deadline = Date.now() + timeoutMs;
  let activeSocket;
  let settled = false;
  let retryTimer;
  let resolveCompletion;
  let rejectCompletion;
  const completion = new Promise((resolve, reject) => {
    resolveCompletion = resolve;
    rejectCompletion = reject;
  });
  attempt();
  return {
    completion,
    abort() {
      if (settled) return;
      settled = true;
      clearTimeout(retryTimer);
      activeSocket?.destroy();
      rejectCompletion(new WindowsHelperPipeSessionError('client_aborted'));
    },
  };

  function attempt() {
    if (settled) return;
    const socket = net.createConnection(endpoint);
    activeSocket = socket;
    let response = '';
    socket.setEncoding('utf8');
    socket.setTimeout(Math.min(1000, timeoutMs));
    socket.once('connect', () => socket.write(`${nonce}\n`));
    socket.on('data', (chunk) => {
      response += chunk;
      if (response.length > 16) socket.destroy();
      if (response === 'ok\n' || response === 'ok\r\n') socket.end();
    });
    socket.once('end', () => {
      if (settled) return;
      settled = true;
      if (response === 'ok\n' || response === 'ok\r\n') resolveCompletion(true);
      else rejectCompletion(new WindowsHelperPipeSessionError('client_failed'));
    });
    socket.once('timeout', () => socket.destroy());
    socket.once('error', () => {
      socket.destroy();
      if (settled) return;
      if (Date.now() >= deadline) {
        settled = true;
        rejectCompletion(new WindowsHelperPipeSessionError('client_failed'));
        return;
      }
      retryTimer = setTimeout(attempt, 25);
    });
  }
}

function startBoundedProcess(spawnImpl, executable, args, options, startCode) {
  let child;
  try { child = spawnImpl(executable, args, options); } catch {
    throw new WindowsHelperPipeSessionError(startCode);
  }
  let stdout = Buffer.alloc(0);
  let stderr = Buffer.alloc(0);
  let overflow = false;
  const completion = new Promise((resolve, reject) => {
    child.once('error', () => reject(new WindowsHelperPipeSessionError(startCode)));
    child.stdout.on('data', (chunk) => {
      if (stdout.byteLength + chunk.byteLength > MAX_PROCESS_OUTPUT_BYTES) {
        overflow = true;
        try { child.kill('SIGKILL'); } catch { /* bounded failure */ }
        return;
      }
      stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on('data', (chunk) => {
      if (stderr.byteLength + chunk.byteLength > MAX_PROCESS_OUTPUT_BYTES) {
        overflow = true;
        try { child.kill('SIGKILL'); } catch { /* bounded failure */ }
        return;
      }
      stderr = Buffer.concat([stderr, chunk]);
    });
    child.once('close', (code) => {
      if (overflow) {
        reject(new WindowsHelperPipeSessionError('process_output_too_large'));
        return;
      }
      resolve({ code, stdout, stderr });
    });
  });
  return {
    child,
    completion,
    abort() { try { child.kill('SIGKILL'); } catch { /* already closed */ } },
  };
}

function withTimeout(promise, timeoutMs, abort) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      abort();
      reject(new WindowsHelperPipeSessionError('session_timeout'));
    }, timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

function exactInput(value) {
  const fields = ['workspace', 'requestBytes', 'manifest', 'launcherSha256', 'launcherByteLength'];
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== fields.length ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !fields.includes(key))) {
    throw new WindowsHelperPipeSessionError('invalid_input');
  }
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new WindowsHelperPipeSessionError('invalid_input');
  }
  if (!(value.requestBytes instanceof Uint8Array) || !Object.isFrozen(value.workspace) ||
      !Object.isFrozen(value.manifest) ||
      typeof value.launcherSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.launcherSha256) ||
      !Number.isSafeInteger(value.launcherByteLength) || value.launcherByteLength < 1) {
    throw new WindowsHelperPipeSessionError('invalid_input');
  }
  return Object.freeze({
    workspace: value.workspace,
    requestBytes: Buffer.from(value.requestBytes),
    manifest: value.manifest,
    launcherSha256: value.launcherSha256,
    launcherByteLength: value.launcherByteLength,
  });
}
