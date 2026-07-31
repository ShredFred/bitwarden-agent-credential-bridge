import { execFile } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyDisposableWorkspace } from './disposable-workspace.mjs';

const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'windows-secure-disposable-path.ps1',
);

export class DisposablePermissionError extends Error {
  constructor(code) {
    super(`disposable permission update failed: ${code}`);
    this.name = 'DisposablePermissionError';
    this.code = code;
  }
}

export function createDisposablePermissionSetter(workspace, options = {}) {
  const fsApi = options.fsApi ?? fs;
  const execFileImpl = options.execFileImpl ?? execFile;
  const timeoutMs = options.timeoutMs ?? 5000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) {
    throw new DisposablePermissionError('invalid_timeout');
  }

  return async function setDisposablePermission(target, kind) {
    await verifyDisposableWorkspace(workspace, { fsApi });
    validateTarget(workspace, target, kind);
    let stat;
    try {
      stat = await fsApi.lstat(target);
    } catch {
      throw new DisposablePermissionError('target_unreadable');
    }
    if (stat.isSymbolicLink() || (kind === 'file' && stat.nlink !== 1) ||
        (kind === 'file' && !stat.isFile()) ||
        (kind === 'directory' && !stat.isDirectory())) {
      throw new DisposablePermissionError('unsafe_target');
    }

    if (workspace.platform === 'win32') {
      await executeWindows(execFileImpl, options.powershellPath ?? 'powershell.exe', options.scriptPath ?? SCRIPT_PATH, [
        workspace.root,
        workspace.marker_path,
        workspace.nonce,
        target,
        kind,
      ], timeoutMs);
    } else {
      await securePosixHandle(fsApi, target, kind, stat);
    }
  };
}

async function securePosixHandle(fsApi, target, kind, priorStat) {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const directory = kind === 'directory' ? (fsConstants.O_DIRECTORY ?? 0) : 0;
  let handle;
  try {
    handle = await fsApi.open(target, fsConstants.O_RDONLY | noFollow | directory);
    const current = await handle.stat();
    if (current.dev !== priorStat.dev || current.ino !== priorStat.ino ||
        (kind === 'file' && (!current.isFile() || current.nlink !== 1)) ||
        (kind === 'directory' && !current.isDirectory())) {
      throw new Error('identity changed');
    }
    await handle.chmod(kind === 'directory' ? 0o700 : 0o600);
  } catch {
    throw new DisposablePermissionError('permission_update_failed');
  } finally {
    if (handle !== undefined) await handle.close().catch(() => {});
  }
}

export async function secureDisposableWorkspace(workspace, options = {}) {
  const setter = createDisposablePermissionSetter(workspace, options);
  await setter(workspace.root, 'directory');
  await setter(workspace.marker_path, 'file');
  await verifyDisposableWorkspace(workspace, { fsApi: options.fsApi ?? fs });
  return true;
}

function validateTarget(workspace, target, kind) {
  if (kind !== 'file' && kind !== 'directory') throw new DisposablePermissionError('invalid_kind');
  if (typeof target !== 'string') throw new DisposablePermissionError('invalid_target');
  const pathApi = workspace.platform === 'win32' ? path.win32 : path.posix;
  const relative = pathApi.relative(workspace.root, target);
  if (relative === '..' || relative.startsWith(`..${pathApi.sep}`) || pathApi.isAbsolute(relative)) {
    throw new DisposablePermissionError('target_outside_workspace');
  }
}

function executeWindows(execFileImpl, executable, scriptPath, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFileImpl(executable, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', scriptPath, ...args,
    ], {
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 1024,
      encoding: 'utf8',
    }, (error, stdout, stderr) => {
      if (error || stdout !== '' || stderr !== '') {
        reject(new DisposablePermissionError(error?.killed ? 'timeout_or_terminated' : 'permission_update_failed'));
        return;
      }
      resolve();
    });
  });
}
