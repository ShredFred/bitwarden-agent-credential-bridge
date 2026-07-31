import { randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

const MARKER_NAME = '.bw-agent-bridge-disposable.json';
const MARKER_MAGIC = 'bitwarden-agent-credential-bridge-disposable';
const MAX_MARKER_BYTES = 512;
const WORKSPACE_FIELDS = new Set([
  'version',
  'platform',
  'root',
  'temp_root',
  'marker_path',
  'nonce',
  'homedir',
  'env',
]);

export class DisposableWorkspaceError extends Error {
  constructor(code) {
    super(`disposable workspace rejected: ${code}`);
    this.name = 'DisposableWorkspaceError';
    this.code = code;
  }
}

/** Create a marked test-only root. This is the only mutation in this module. */
export async function createDisposableWorkspace(options = {}) {
  const platform = options.platform ?? process.platform;
  if (platform !== process.platform) {
    throw new DisposableWorkspaceError('platform_host_mismatch');
  }
  const fsApi = options.fsApi ?? fs;
  const pathApi = pathFor(platform);
  const requestedTemp = options.tempRoot ?? os.tmpdir();
  if (typeof requestedTemp !== 'string' || !pathApi.isAbsolute(requestedTemp)) {
    throw new DisposableWorkspaceError('invalid_temp_root');
  }
  const tempRoot = await verifiedRealDirectory(fsApi, requestedTemp, 'invalid_temp_root');
  const root = await fsApi.mkdtemp(pathApi.join(tempRoot, 'bw-agent-bridge-disposable-'));
  const realRoot = await verifiedRealDirectory(fsApi, root, 'workspace_creation_failed');
  assertDescendant(pathApi, tempRoot, realRoot);

  const markerPath = pathApi.join(realRoot, MARKER_NAME);
  const nonce = randomBytes(32).toString('hex');
  const layout = syntheticLayout(platform, realRoot);
  const workspace = {
    version: 1,
    platform,
    root: realRoot,
    temp_root: tempRoot,
    marker_path: markerPath,
    nonce,
    homedir: layout.homedir,
    env: layout.env,
  };
  await fsApi.writeFile(markerPath, markerBytes(workspace), {
    flag: 'wx',
    mode: 0o600,
  });
  if (platform !== 'win32') {
    await fsApi.chmod(realRoot, 0o700);
    await fsApi.chmod(markerPath, 0o600);
  }
  return deepFreeze(workspace);
}

/** Verify the exact root and marker before any later disposable operation. */
export async function verifyDisposableWorkspace(raw, options = {}) {
  const workspace = exactWorkspace(raw);
  const fsApi = options.fsApi ?? fs;
  const pathApi = pathFor(workspace.platform);
  const tempRoot = await verifiedRealDirectory(fsApi, workspace.temp_root, 'temp_root_changed');
  const root = await verifiedRealDirectory(fsApi, workspace.root, 'workspace_root_changed');
  if (!samePath(workspace.platform, tempRoot, workspace.temp_root) ||
      !samePath(workspace.platform, root, workspace.root)) {
    throw new DisposableWorkspaceError('canonical_path_changed');
  }
  assertDescendant(pathApi, tempRoot, root);
  if (!samePath(workspace.platform, workspace.marker_path, pathApi.join(root, MARKER_NAME))) {
    throw new DisposableWorkspaceError('invalid_marker_path');
  }

  let stat;
  let actual;
  try {
    stat = await fsApi.lstat(workspace.marker_path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
      throw new DisposableWorkspaceError('invalid_marker_file');
    }
    actual = await fsApi.readFile(workspace.marker_path);
  } catch (error) {
    if (error instanceof DisposableWorkspaceError) throw error;
    throw new DisposableWorkspaceError('marker_unreadable');
  }
  const expected = markerBytes(workspace);
  if (actual.length === 0 || actual.length > MAX_MARKER_BYTES ||
      actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new DisposableWorkspaceError('marker_mismatch');
  }

  const expectedLayout = syntheticLayout(workspace.platform, root);
  if (!samePath(workspace.platform, workspace.homedir, expectedLayout.homedir) ||
      canonicalEnv(workspace.env) !== canonicalEnv(expectedLayout.env)) {
    throw new DisposableWorkspaceError('layout_mismatch');
  }
  for (const value of [workspace.marker_path, workspace.homedir, ...Object.values(workspace.env)]) {
    assertDescendant(pathApi, root, value);
  }
  return true;
}

function markerBytes(workspace) {
  return Buffer.from(`${JSON.stringify({
    magic: MARKER_MAGIC,
    version: 1,
    platform: workspace.platform,
    nonce: workspace.nonce,
  })}\n`, 'utf8');
}

function syntheticLayout(platform, root) {
  const pathApi = pathFor(platform);
  const homedir = pathApi.join(root, 'home');
  if (platform === 'win32') {
    return { homedir, env: { LOCALAPPDATA: pathApi.join(root, 'local') } };
  }
  if (platform === 'linux') {
    return {
      homedir,
      env: {
        XDG_CONFIG_HOME: pathApi.join(root, 'config'),
        XDG_DATA_HOME: pathApi.join(root, 'data'),
      },
    };
  }
  return { homedir, env: {} };
}

function exactWorkspace(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new DisposableWorkspaceError('invalid_workspace');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== WORKSPACE_FIELDS.size || keys.some((key) => typeof key !== 'string' || !WORKSPACE_FIELDS.has(key))) {
    throw new DisposableWorkspaceError('invalid_workspace');
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new DisposableWorkspaceError('invalid_workspace');
  }
  pathFor(value.platform);
  if (value.platform !== process.platform) {
    throw new DisposableWorkspaceError('platform_host_mismatch');
  }
  if (value.version !== 1 || typeof value.root !== 'string' || typeof value.temp_root !== 'string' ||
      typeof value.marker_path !== 'string' || typeof value.homedir !== 'string' ||
      typeof value.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(value.nonce) ||
      value.env === null || typeof value.env !== 'object' || Array.isArray(value.env) || Object.getPrototypeOf(value.env) !== Object.prototype) {
    throw new DisposableWorkspaceError('invalid_workspace');
  }
  for (const key of Reflect.ownKeys(value.env)) {
    const descriptor = Object.getOwnPropertyDescriptor(value.env, key);
    if (typeof key !== 'string' || descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'string') {
      throw new DisposableWorkspaceError('invalid_workspace');
    }
  }
  return value;
}

async function verifiedRealDirectory(fsApi, target, code) {
  try {
    const stat = await fsApi.lstat(target);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('unsafe');
    const real = await fsApi.realpath(target);
    const realStat = await fsApi.lstat(real);
    if (!realStat.isDirectory() || realStat.isSymbolicLink()) throw new Error('unsafe');
    return real;
  } catch {
    throw new DisposableWorkspaceError(code);
  }
}

function pathFor(platform) {
  if (platform === 'win32') return path.win32;
  if (platform === 'linux' || platform === 'darwin') return path.posix;
  throw new DisposableWorkspaceError('unsupported_platform');
}

function assertDescendant(pathApi, parent, child) {
  const relative = pathApi.relative(parent, child);
  if (relative === '' || relative === '..' || relative.startsWith(`..${pathApi.sep}`) || pathApi.isAbsolute(relative)) {
    throw new DisposableWorkspaceError('path_escape');
  }
}

function samePath(platform, left, right) {
  const normalize = (value) => platform === 'win32'
    ? value.replace(/^\\\\\?\\/, '').toLowerCase()
    : value;
  return normalize(left) === normalize(right);
}

function canonicalEnv(env) {
  return JSON.stringify(Object.fromEntries(Object.entries(env).sort(([a], [b]) => a.localeCompare(b))));
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
