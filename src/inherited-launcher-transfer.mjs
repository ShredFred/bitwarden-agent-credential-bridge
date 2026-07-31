import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseHelperRequest } from './helper-protocol.mjs';
import { verifyDisposableWorkspace } from './disposable-workspace.mjs';

const WORKER_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'inherited-launcher-worker.mjs',
);
const MAX_LAUNCHER_BYTES = 1024 * 1024;
const MAX_STDOUT_BYTES = 1024;
const RESULT_FIELDS = new Set([
  'protocol_version', 'code', 'request_verified', 'launcher_handle_verified',
]);

export class InheritedLauncherTransferError extends Error {
  constructor(code) {
    super(`inherited launcher transfer failed: ${code}`);
    this.name = 'InheritedLauncherTransferError';
    this.code = code;
  }
}

/**
 * Exercise an actual inherited read-only launcher handle in a short-lived child.
 * No path, bytes, digest, or process detail is returned to the caller.
 */
export async function verifyInheritedLauncherTransfer(input, options = {}) {
  const values = exactInput(input);
  await verifyDisposableWorkspace(values.workspace);
  const request = parseHelperRequest(values.requestBytes);
  if (request.workspace.platform !== values.workspace.platform ||
      request.workspace.root !== values.workspace.root ||
      request.workspace.marker_nonce !== values.workspace.nonce) {
    throw new InheritedLauncherTransferError('request_binding_mismatch');
  }
  const actualDigest = createHash('sha256').update(values.launcherBytes).digest('hex');
  if (request.launcher.sha256 !== actualDigest ||
      request.launcher.byte_length !== values.launcherBytes.byteLength) {
    throw new InheritedLauncherTransferError('request_binding_mismatch');
  }

  const spawnImpl = options.spawnImpl ?? spawn;
  const timeoutMs = options.timeoutMs ?? 5000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) {
    throw new InheritedLauncherTransferError('invalid_timeout');
  }

  const tempPath = path.join(
    values.workspace.root,
    `.launcher-transfer-${randomBytes(16).toString('hex')}`,
  );
  let writer;
  let reader;
  try {
    writer = await fs.open(tempPath, 'wx+', 0o600);
    await writer.writeFile(values.launcherBytes);
    await writer.sync();
    reader = await fs.open(tempPath, 'r');
    await fs.unlink(tempPath);
    await writer.close();
    writer = undefined;
    return await runWorker(spawnImpl, reader.fd, values.requestBytes, values.workspace.root, timeoutMs);
  } catch (error) {
    if (error instanceof InheritedLauncherTransferError) throw error;
    throw new InheritedLauncherTransferError('transfer_failed');
  } finally {
    await closeQuietly(writer);
    await closeQuietly(reader);
    await unlinkQuietly(tempPath);
  }
}

function runWorker(spawnImpl, launcherFd, requestBytes, cwd, timeoutMs) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImpl(process.execPath, [WORKER_PATH], {
        cwd,
        env: {},
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe', launcherFd],
      });
    } catch {
      reject(new InheritedLauncherTransferError('worker_start_failed'));
      return;
    }
    let stdout = Buffer.alloc(0);
    let stderrSeen = false;
    let settled = false;
    let abortCode;
    let killGraceTimer;
    const timer = setTimeout(() => {
      abortAndWait('worker_timeout');
    }, timeoutMs);
    timer.unref?.();

    child.stdout.on('data', (chunk) => {
      if (stdout.byteLength + chunk.byteLength > MAX_STDOUT_BYTES) {
        abortAndWait('invalid_worker_output');
        return;
      }
      stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on('data', () => { stderrSeen = true; });
    child.on('error', () => finishReject('worker_start_failed'));
    child.on('close', (code) => {
      if (settled) return;
      clearTimeout(timer);
      clearTimeout(killGraceTimer);
      if (abortCode !== undefined) {
        finishReject(abortCode);
        return;
      }
      if (code !== 0 || stderrSeen) {
        finishReject('worker_failed');
        return;
      }
      try {
        const result = parseWorkerResult(stdout);
        settled = true;
        resolve(result);
      } catch {
        finishReject('invalid_worker_output');
      }
    });
    child.stdin.on('error', () => abortAndWait('worker_failed'));
    child.stdin.end(requestBytes);

    function abortAndWait(code) {
      if (settled || abortCode !== undefined) return;
      abortCode = code;
      try { child.kill('SIGKILL'); } catch { /* grace timer remains authoritative */ }
      killGraceTimer = setTimeout(() => finishReject(code), 1000);
      killGraceTimer.unref?.();
    }

    function finishReject(code) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new InheritedLauncherTransferError(code));
    }
  });
}

export function parseWorkerResult(raw) {
  if (!(raw instanceof Uint8Array) || raw.byteLength === 0 || raw.byteLength > MAX_STDOUT_BYTES) {
    throw new InheritedLauncherTransferError('invalid_worker_output');
  }
  let value;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    value = JSON.parse(text);
  } catch {
    throw new InheritedLauncherTransferError('invalid_worker_output');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== RESULT_FIELDS.size ||
      Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !RESULT_FIELDS.has(key)) ||
      value.protocol_version !== 1 || value.code !== 'verified' ||
      value.request_verified !== true || value.launcher_handle_verified !== true) {
    throw new InheritedLauncherTransferError('invalid_worker_output');
  }
  if (text !== `${JSON.stringify(value)}\n`) {
    throw new InheritedLauncherTransferError('invalid_worker_output');
  }
  return Object.freeze({
    request_verified: true,
    launcher_handle_verified: true,
  });
}

function exactInput(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== 3 ||
      !Reflect.ownKeys(value).every((key) => ['workspace', 'requestBytes', 'launcherBytes'].includes(key))) {
    throw new InheritedLauncherTransferError('invalid_input');
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new InheritedLauncherTransferError('invalid_input');
    }
  }
  if (!(value.requestBytes instanceof Uint8Array) ||
      !(value.launcherBytes instanceof Uint8Array) || value.launcherBytes.byteLength === 0 ||
      value.launcherBytes.byteLength > MAX_LAUNCHER_BYTES ||
      value.workspace === null || typeof value.workspace !== 'object' ||
      !Object.isFrozen(value.workspace) || !Object.isFrozen(value.workspace.env)) {
    throw new InheritedLauncherTransferError('invalid_input');
  }
  return Object.freeze({
    workspace: value.workspace,
    requestBytes: Buffer.from(value.requestBytes),
    launcherBytes: Buffer.from(value.launcherBytes),
  });
}

async function closeQuietly(handle) {
  if (handle === undefined) return;
  try { await handle.close(); } catch { /* stable cleanup */ }
}

async function unlinkQuietly(target) {
  try { await fs.unlink(target); } catch { /* absent or already delete-pending */ }
}
