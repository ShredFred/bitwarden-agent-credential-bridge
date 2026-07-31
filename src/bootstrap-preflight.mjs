import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';

const SHA256 = /^[0-9a-f]{64}$/;
const TARGETS = Object.freeze([
  ['config', 'configPath', 'file'],
  ['install_root', 'installRoot', 'directory'],
  ['launcher', 'launcherPath', 'file'],
]);

/**
 * Read-only metadata audit. User config contents are never opened.
 * @param {{platform: 'win32'|'darwin'|'linux', roots: {configPath:string,installRoot:string,launcherPath:string}, fsApi?: typeof fs, currentUid?: number, windowsSecurity?: (path:string)=>Promise<{reparsePoint:boolean,ownerCurrentUser:boolean,writableByOtherUsers:boolean}>, expectedLauncherSha256?: string}} input
 */
export async function auditBootstrapHost(input) {
  const checks = [];
  const fsApi = input.fsApi ?? fs;
  const expectedHash = input.expectedLauncherSha256;
  if (!['win32', 'darwin', 'linux'].includes(input.platform)) {
    return report([failed('platform', 'unsupported_platform')]);
  }
  if (expectedHash !== undefined && (typeof expectedHash !== 'string' || !SHA256.test(expectedHash))) {
    return report([failed('launcher_integrity', 'invalid_expected_digest')]);
  }

  for (const [id, rootKey, expectedType] of TARGETS) {
    const target = input.roots?.[rootKey];
    if (typeof target !== 'string' || target.length === 0) {
      checks.push(failed(id, 'invalid_target'));
      continue;
    }
    let stat;
    try {
      stat = await fsApi.lstat(target);
    } catch {
      checks.push(failed(id, 'missing_or_unreadable'));
      continue;
    }
    if (stat.isSymbolicLink()) {
      checks.push(failed(id, 'link_rejected'));
      continue;
    }
    if ((expectedType === 'file' && !stat.isFile()) || (expectedType === 'directory' && !stat.isDirectory())) {
      checks.push(failed(id, 'wrong_file_type'));
      continue;
    }

    if (input.platform === 'win32') {
      const result = await inspectWindows(target, input.windowsSecurity);
      checks.push(result.ok ? passed(id) : failed(id, result.reason));
    } else {
      const uid = input.currentUid;
      if (!Number.isInteger(uid) || stat.uid !== uid) {
        checks.push(failed(id, 'owner_mismatch'));
      } else {
        const unsafeBits = id === 'config' ? 0o077 : 0o022;
        checks.push((stat.mode & unsafeBits) === 0 ? passed(id) : failed(id, 'unsafe_permissions'));
      }
    }
  }

  if (expectedHash !== undefined && checks.some((check) => check.id === 'launcher' && check.status === 'passed')) {
    try {
      const bytes = await fsApi.readFile(input.roots.launcherPath);
      const actual = createHash('sha256').update(bytes).digest('hex');
      checks.push(actual === expectedHash ? passed('launcher_integrity') : failed('launcher_integrity', 'digest_mismatch'));
    } catch {
      checks.push(failed('launcher_integrity', 'unreadable'));
    }
  }
  return report(checks);
}

async function inspectWindows(target, adapter) {
  if (typeof adapter !== 'function') return { ok: false, reason: 'windows_security_unavailable' };
  let result;
  try {
    result = await adapter(target);
  } catch {
    return { ok: false, reason: 'windows_security_failed' };
  }
  if (
    result === null || typeof result !== 'object' || Array.isArray(result) ||
    Reflect.ownKeys(result).length !== 3 ||
    typeof result.reparsePoint !== 'boolean' ||
    typeof result.ownerCurrentUser !== 'boolean' ||
    typeof result.writableByOtherUsers !== 'boolean'
  ) return { ok: false, reason: 'windows_security_invalid' };
  if (result.reparsePoint) return { ok: false, reason: 'reparse_point_rejected' };
  if (!result.ownerCurrentUser) return { ok: false, reason: 'owner_mismatch' };
  if (result.writableByOtherUsers) return { ok: false, reason: 'unsafe_permissions' };
  return { ok: true };
}

function passed(id) {
  return Object.freeze({ id, status: 'passed' });
}

function failed(id, reason) {
  return Object.freeze({ id, status: 'failed', reason });
}

function report(checks) {
  return Object.freeze({
    ready: checks.length > 0 && checks.every((check) => check.status === 'passed'),
    checks: Object.freeze(checks),
  });
}
