/**
 * Linux same-user SM token store: owner-only file (0600) under XDG config.
 * Never logs the token. Symlinks, foreign owners, and group/other bits fail closed.
 */
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

const TOKEN_MAX_BYTES = 8192;

export class LinuxSmTokenFileError extends Error {
  constructor(code) {
    super(`Linux SM token file rejected: ${code}`);
    this.name = 'LinuxSmTokenFileError';
    this.code = code;
  }
}

/**
 * @param {{
 *   home?: string,
 *   configHome?: string,
 * }} [options]
 */
export function defaultLinuxSecretsManagerConfigDir(options = {}) {
  const home = typeof options.home === 'string' && options.home.length > 0
    ? options.home
    : os.homedir();
  const homeInjected = typeof options.home === 'string' && options.home.length > 0;
  const xdg = typeof options.configHome === 'string' && options.configHome.length > 0
    ? options.configHome
    : (!homeInjected
      && typeof process.env.XDG_CONFIG_HOME === 'string'
      && process.env.XDG_CONFIG_HOME.length > 0
      ? process.env.XDG_CONFIG_HOME
      : path.posix.join(home, '.config'));
  return path.posix.join(xdg, 'BitwardenAgentCredentialBridge');
}

/**
 * @param {{
 *   home?: string,
 *   configHome?: string,
 *   tokenPath?: string,
 * }} [options]
 */
export function defaultLinuxSecretsManagerTokenPath(options = {}) {
  if (typeof options.tokenPath === 'string' && options.tokenPath.length > 0) {
    return options.tokenPath;
  }
  return path.posix.join(defaultLinuxSecretsManagerConfigDir(options), 'sm-machine.token');
}

function noFollowFlag() {
  const flag = fsConstants.O_NOFOLLOW;
  return Number.isInteger(flag) && flag !== 0 ? flag : 0;
}

function isAbsolutePath(filePath) {
  return path.posix.isAbsolute(filePath);
}

function assertSafeTokenPath(filePath) {
  if (typeof filePath !== 'string' ||
      filePath.length < 1 ||
      filePath.length > 4096 ||
      filePath.includes('\0') ||
      !isAbsolutePath(filePath)) {
    throw new LinuxSmTokenFileError('invalid_path');
  }
}

function currentUid() {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function assertOwnerOnlyRegularFile(st) {
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new LinuxSmTokenFileError('token_store_invalid');
  }
  if ((st.mode & 0o077) !== 0) {
    throw new LinuxSmTokenFileError('token_store_insecure');
  }
  const uid = currentUid();
  if (uid !== null && typeof st.uid === 'number' && st.uid !== uid) {
    throw new LinuxSmTokenFileError('token_store_insecure');
  }
}

async function assertOwnerOnlyDirectory(dirPath) {
  let st;
  try {
    st = await fs.lstat(dirPath);
  } catch {
    throw new LinuxSmTokenFileError('token_store_invalid');
  }
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new LinuxSmTokenFileError('token_store_invalid');
  }
  if ((st.mode & 0o077) !== 0) {
    throw new LinuxSmTokenFileError('token_store_insecure');
  }
  const uid = currentUid();
  if (uid !== null && typeof st.uid === 'number' && st.uid !== uid) {
    throw new LinuxSmTokenFileError('token_store_insecure');
  }
}

function assertTokenShape(token) {
  if (typeof token !== 'string' ||
      token.length < 16 ||
      token.length > TOKEN_MAX_BYTES ||
      /[\r\n]/.test(token)) {
    throw new LinuxSmTokenFileError('invalid_token');
  }
}

/**
 * @param {string} token
 * @param {{ tokenPath?: string, home?: string, configHome?: string }} [options]
 */
export async function storeLinuxOwnerOnlyToken(token, options = {}) {
  assertTokenShape(token);
  const filePath = defaultLinuxSecretsManagerTokenPath(options);
  assertSafeTokenPath(filePath);
  try {
    const existing = await fs.lstat(filePath);
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new LinuxSmTokenFileError('token_store_invalid');
    }
  } catch (error) {
    if (error instanceof LinuxSmTokenFileError) throw error;
  }
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  let preChmod;
  try {
    preChmod = await fs.lstat(dir);
  } catch {
    throw new LinuxSmTokenFileError('token_store_invalid');
  }
  if (preChmod.isSymbolicLink() || !preChmod.isDirectory()) {
    throw new LinuxSmTokenFileError('token_store_invalid');
  }
  const uid = currentUid();
  if (uid !== null && typeof preChmod.uid === 'number' && preChmod.uid !== uid) {
    throw new LinuxSmTokenFileError('token_store_insecure');
  }
  await fs.chmod(dir, 0o700);
  await assertOwnerOnlyDirectory(dir);
  const tmp = `${filePath}.${process.pid}.tmp`;
  try {
    const stale = await fs.lstat(tmp);
    if (stale.isFile() && !stale.isSymbolicLink()) {
      await fs.unlink(tmp);
    }
  } catch {
    // absent is fine; a leftover symlink is not reused
  }
  await assertOwnerOnlyDirectory(dir);
  const flags = fsConstants.O_CREAT |
    fsConstants.O_EXCL |
    fsConstants.O_WRONLY |
    noFollowFlag();
  let handle;
  try {
    handle = await fs.open(tmp, flags, 0o600);
    await handle.writeFile(token, { encoding: 'utf8' });
    await handle.chmod(0o600);
    await handle.close();
    handle = undefined;
    await fs.rename(tmp, filePath);
    const published = await fs.open(filePath, fsConstants.O_RDWR | noFollowFlag());
    try {
      await published.chmod(0o600);
      const st = await published.stat();
      assertOwnerOnlyRegularFile(st);
    } finally {
      await published.close();
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(tmp).catch(() => {});
    if (error instanceof LinuxSmTokenFileError) throw error;
    throw new LinuxSmTokenFileError('token_store_failed');
  }
}

/**
 * @param {{ tokenPath?: string, home?: string, configHome?: string }} [options]
 * @returns {Promise<string>}
 */
export async function readLinuxOwnerOnlyToken(options = {}) {
  const filePath = defaultLinuxSecretsManagerTokenPath(options);
  assertSafeTokenPath(filePath);
  const flags = fsConstants.O_RDONLY | noFollowFlag();
  let handle;
  try {
    handle = await fs.open(filePath, flags);
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? error.code : '';
    if (code === 'ELOOP' || code === 'EPERM') {
      throw new LinuxSmTokenFileError('token_store_invalid');
    }
    throw new LinuxSmTokenFileError('token_store_absent');
  }
  try {
    const st = await handle.stat();
    assertOwnerOnlyRegularFile(st);
    if (st.size > TOKEN_MAX_BYTES) {
      throw new LinuxSmTokenFileError('invalid_token');
    }
    const raw = await handle.readFile({ encoding: 'utf8' });
    const token = typeof raw === 'string' ? raw.trim() : '';
    assertTokenShape(token);
    return token;
  } finally {
    await handle.close();
  }
}

/**
 * @param {{ tokenPath?: string, home?: string, configHome?: string }} [options]
 */
export async function deleteLinuxOwnerOnlyToken(options = {}) {
  const filePath = defaultLinuxSecretsManagerTokenPath(options);
  assertSafeTokenPath(filePath);
  try {
    const st = await fs.lstat(filePath);
    if (st.isSymbolicLink() || !st.isFile()) {
      throw new LinuxSmTokenFileError('token_store_invalid');
    }
    await fs.unlink(filePath);
  } catch (error) {
    if (error instanceof LinuxSmTokenFileError) throw error;
  }
}

/**
 * @param {{ tokenPath?: string, home?: string, configHome?: string }} [options]
 */
export async function linuxOwnerOnlyTokenPresent(options = {}) {
  const filePath = defaultLinuxSecretsManagerTokenPath(options);
  try {
    assertSafeTokenPath(filePath);
    const st = await fs.lstat(filePath);
    const uid = currentUid();
    const ownerOk = uid === null || typeof st.uid !== 'number' || st.uid === uid;
    return st.isFile() &&
      !st.isSymbolicLink() &&
      (st.mode & 0o077) === 0 &&
      ownerOk;
  } catch {
    return false;
  }
}
