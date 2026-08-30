/**
 * Linux same-user SM token store: owner-only file (0600) under XDG config.
 * Never logs the token. Group/other bits fail closed on read.
 */
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

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
  const xdg = typeof options.configHome === 'string' && options.configHome.length > 0
    ? options.configHome
    : (typeof process.env.XDG_CONFIG_HOME === 'string' && process.env.XDG_CONFIG_HOME.length > 0
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

function assertTokenShape(token) {
  if (typeof token !== 'string' ||
      token.length < 16 ||
      token.length > 8192 ||
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
  try {
    const existing = await fs.lstat(filePath);
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new LinuxSmTokenFileError('token_store_invalid');
    }
  } catch (error) {
    if (error instanceof LinuxSmTokenFileError) throw error;
    // absent is fine
  }
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700);
  const tmp = `${filePath}.${process.pid}.tmp`;
  await fs.writeFile(tmp, token, { encoding: 'utf8', mode: 0o600 });
  await fs.chmod(tmp, 0o600);
  await fs.rename(tmp, filePath);
  await fs.chmod(filePath, 0o600);
}

/**
 * @param {{ tokenPath?: string, home?: string, configHome?: string }} [options]
 * @returns {Promise<string>}
 */
export async function readLinuxOwnerOnlyToken(options = {}) {
  const filePath = defaultLinuxSecretsManagerTokenPath(options);
  let st;
  try {
    st = await fs.lstat(filePath);
  } catch {
    throw new LinuxSmTokenFileError('token_store_absent');
  }
  if (!st.isFile() || st.isSymbolicLink()) {
    throw new LinuxSmTokenFileError('token_store_invalid');
  }
  if ((st.mode & 0o077) !== 0) {
    throw new LinuxSmTokenFileError('token_store_insecure');
  }
  const raw = await fs.readFile(filePath, { encoding: 'utf8' });
  const token = typeof raw === 'string' ? raw.trim() : '';
  assertTokenShape(token);
  return token;
}

/**
 * @param {{ tokenPath?: string, home?: string, configHome?: string }} [options]
 */
export async function deleteLinuxOwnerOnlyToken(options = {}) {
  const filePath = defaultLinuxSecretsManagerTokenPath(options);
  try {
    await fs.unlink(filePath);
  } catch {
    // absent is success
  }
}

/**
 * @param {{ tokenPath?: string, home?: string, configHome?: string }} [options]
 */
export async function linuxOwnerOnlyTokenPresent(options = {}) {
  const filePath = defaultLinuxSecretsManagerTokenPath(options);
  try {
    const st = await fs.lstat(filePath);
    return st.isFile() && !st.isSymbolicLink() && (st.mode & 0o077) === 0;
  } catch {
    return false;
  }
}
