import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  buildApplyManifest,
  canonicalJson,
  verifyManifestConfirmation,
} from './apply-manifest.mjs';
import {
  createDisposablePermissionSetter,
  secureDisposableWorkspace,
} from './disposable-permissions.mjs';
import { verifyDisposableWorkspace } from './disposable-workspace.mjs';
import { createWindowsSecurityAdapter } from './windows-security-adapter.mjs';

const EMPTY_CONFIG = Buffer.from('{"version":1,"services":{}}\n', 'utf8');
const MAX_MANAGED_FILE_BYTES = 1024 * 1024;

export class DisposableApplyError extends Error {
  constructor(code, rollback = 'not_started') {
    super(`disposable apply failed: ${code}`);
    this.name = 'DisposableApplyError';
    this.code = code;
    this.rollback = rollback;
  }
}

/** Create only synthetic OS roots expected to pre-exist on a real host. */
export async function prepareDisposableScaffold(workspace, options = {}) {
  const fsApi = options.fsApi ?? fs;
  await verifyDisposableWorkspace(workspace, { fsApi });
  await secureDisposableWorkspace(workspace, options);
  const pathApi = workspace.platform === 'win32' ? path.win32 : path.posix;
  const dirs = workspace.platform === 'win32'
    ? [workspace.homedir, workspace.env.LOCALAPPDATA, pathApi.join(workspace.env.LOCALAPPDATA, 'Programs')]
    : workspace.platform === 'linux'
      ? [workspace.homedir, workspace.env.XDG_CONFIG_HOME, workspace.env.XDG_DATA_HOME]
      : [workspace.homedir, pathApi.join(workspace.homedir, 'Library'), pathApi.join(workspace.homedir, 'Library', 'Application Support')];
  const setter = createDisposablePermissionSetter(workspace, options);
  for (const target of dirs) {
    assertInside(workspace, target, false);
    try {
      await fsApi.mkdir(target, { recursive: false, mode: 0o700 });
    } catch {
      throw new DisposableApplyError('scaffold_failed');
    }
    await setter(target, 'directory');
  }
  return true;
}

export async function observeDisposableState(workspace, manifest, options = {}) {
  const fsApi = options.fsApi ?? fs;
  await verifyDisposableWorkspace(workspace, { fsApi });
  validateManifestWorkspace(workspace, manifest);
  const paths = manifest.payload.paths;
  const configDir = await observePath(workspace, paths.config_dir, 'directory', fsApi, options);
  const configFile = await observePath(workspace, paths.config_file, 'file', fsApi, options, false);
  const installRoot = await observePath(workspace, paths.install_root, 'directory', fsApi, options);
  const binDir = await observePath(workspace, paths.bin_dir, 'directory', fsApi, options);
  const launcher = await observePath(workspace, paths.launcher, 'file', fsApi, options, true);
  return {
    config_dir: configDir.exists ? 'secure_directory' : 'absent',
    config_file: configFile.exists ? 'secure_file' : 'absent',
    install_root: installRoot.exists ? 'secure_directory' : 'absent',
    bin_dir: binDir.exists ? 'secure_directory' : 'absent',
    launcher: launcher.exists
      ? { kind: 'managed_file', sha256: launcher.sha256 }
      : { kind: 'absent' },
  };
}

export async function executeDisposableManifest(input) {
  const { workspace, manifest, confirmation, launcherBytes } = input;
  const options = input.options ?? {};
  const fsApi = options.fsApi ?? fs;
  if (!verifyManifestConfirmation(manifest, confirmation)) {
    throw new DisposableApplyError('confirmation_rejected');
  }
  await verifyDisposableWorkspace(workspace, { fsApi });
  await verifyWorkspacePermissions(workspace, options);
  const rebuilt = buildApplyManifest({
    platform: workspace.platform,
    homedir: workspace.homedir,
    env: workspace.env,
    launcherBytes,
    observed: manifest.payload.observed,
  });
  if (rebuilt.manifest_sha256 !== manifest.manifest_sha256 || canonicalJson(rebuilt) !== canonicalJson(manifest)) {
    throw new DisposableApplyError('manifest_workspace_mismatch');
  }
  const current = await observeDisposableState(workspace, manifest, options);
  if (canonicalJson(current) !== canonicalJson(manifest.payload.observed)) {
    throw new DisposableApplyError('observed_state_changed');
  }

  const setter = createDisposablePermissionSetter(workspace, options);
  const rollbackStack = [];
  let completed = 0;
  try {
    for (const action of manifest.payload.forward) {
      await verifyDisposableWorkspace(workspace, { fsApi });
      await verifyParentChain(workspace, action.target, fsApi, options);
      if (typeof action.destination === 'string') {
        await verifyParentChain(workspace, action.destination, fsApi, options);
      }
      if (action.kind === 'commit_remove_backup_if_digest_matches') {
        await verifyFinalState(workspace, manifest, options);
      }
      const rollback = rollbackFor(action, manifest.payload.rollback);
      let rollbackActivated = false;
      const onMutation = () => {
        if (rollback !== undefined && !rollbackActivated) {
          rollbackStack.unshift(rollback);
          rollbackActivated = true;
        }
      };
      await executeForward(action, {
        workspace,
        manifest,
        launcherBytes: Buffer.from(launcherBytes),
        fsApi,
        setter,
        onMutation,
      });
      completed += 1;
      if (action.kind === 'commit_remove_backup_if_digest_matches') rollbackStack.length = 0;
      if (action.kind === 'commit_remove_backup_if_digest_matches') {
        return Object.freeze({ status: 'applied', completed_actions: completed, rollback: 'not_needed' });
      }
      if (options.failAfterSequence === action.sequence) throw new DisposableApplyError('injected_failure');
    }
    await verifyFinalState(workspace, manifest, options);
    return Object.freeze({ status: 'applied', completed_actions: completed, rollback: 'not_needed' });
  } catch (error) {
    try {
      for (const rollback of rollbackStack) {
        await verifyDisposableWorkspace(workspace, { fsApi });
        await verifyParentChain(workspace, rollback.target, fsApi, options);
        if (typeof rollback.destination === 'string') {
          await verifyParentChain(workspace, rollback.destination, fsApi, options);
        }
        await executeRollback(rollback, { workspace, fsApi });
      }
    } catch {
      throw new DisposableApplyError('rollback_failed', 'failed');
    }
    throw new DisposableApplyError(
      error instanceof DisposableApplyError ? error.code : 'action_failed',
      'completed',
    );
  }
}

async function executeForward(action, ctx) {
  assertInside(ctx.workspace, action.target, true);
  switch (action.kind) {
    case 'create_directory_exclusive':
      await ctx.fsApi.mkdir(action.target, { recursive: false, mode: 0o700 });
      ctx.onMutation();
      await ctx.setter(action.target, 'directory');
      await verifySecureExisting(ctx.workspace, action.target, 'directory', ctx.fsApi, ctx);
      break;
    case 'create_file_exclusive':
      await writeExclusive(ctx.fsApi, action.target, EMPTY_CONFIG, 0o600);
      ctx.onMutation();
      await ctx.setter(action.target, 'file');
      await verifyDigestFile(ctx.workspace, action.target, action.content_sha256, ctx.fsApi, ctx);
      break;
    case 'create_file_atomic_exclusive':
      await publishAtomic(ctx, action.target, ctx.launcherBytes, action.content_sha256);
      break;
    case 'assert_path_absent':
      await assertAbsent(ctx.fsApi, action.target);
      break;
    case 'move_file_exclusive':
      await moveExclusive(ctx, action.target, action.destination, action.expected_sha256);
      break;
    case 'commit_remove_backup_if_digest_matches':
      await verifyDigestFile(ctx.workspace, action.target, action.expected_sha256, ctx.fsApi, ctx);
      await ctx.fsApi.unlink(action.target);
      break;
    default:
      throw new DisposableApplyError('unsupported_action');
  }
}

async function executeRollback(action, ctx) {
  assertInside(ctx.workspace, action.target, true);
  switch (action.kind) {
    case 'remove_file_if_digest_matches':
      await verifyDigestFile(ctx.workspace, action.target, action.expected_sha256, ctx.fsApi, ctx);
      await ctx.fsApi.unlink(action.target);
      await assertAbsent(ctx.fsApi, action.target);
      break;
    case 'remove_directory_if_empty':
      await verifySecureExisting(ctx.workspace, action.target, 'directory', ctx.fsApi, ctx);
      await ctx.fsApi.rmdir(action.target);
      await assertAbsent(ctx.fsApi, action.target);
      break;
    case 'restore_file_exclusive': {
      await verifyDigestFile(ctx.workspace, action.target, action.expected_source_sha256, ctx.fsApi, ctx);
      const destination = await optionalFileDigest(ctx.fsApi, action.destination);
      if (destination !== null) {
        if (destination !== action.expected_destination_sha256) throw new DisposableApplyError('rollback_state_changed');
        await ctx.fsApi.unlink(action.destination);
      } else if (!action.destination_may_be_absent) {
        throw new DisposableApplyError('rollback_state_changed');
      }
      await ctx.fsApi.link(action.target, action.destination);
      await ctx.fsApi.unlink(action.target);
      await verifyDigestFile(ctx.workspace, action.destination, action.expected_source_sha256, ctx.fsApi, ctx);
      break;
    }
    default:
      throw new DisposableApplyError('unsupported_rollback');
  }
}

async function publishAtomic(ctx, target, bytes, expectedSha256) {
  const pathApi = ctx.workspace.platform === 'win32' ? path.win32 : path.posix;
  const temp = pathApi.join(pathApi.dirname(target), `.${pathApi.basename(target)}.tmp-${ctx.manifest.manifest_sha256.slice(0, 24)}`);
  assertInside(ctx.workspace, temp, false);
  await assertAbsent(ctx.fsApi, temp);
  try {
    const handle = await ctx.fsApi.open(temp, 'wx', 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await ctx.setter(temp, 'file');
    await verifyDigestFile(ctx.workspace, temp, expectedSha256, ctx.fsApi, ctx);
    await ctx.fsApi.link(temp, target);
    await ctx.fsApi.unlink(temp);
    ctx.onMutation();
    await ctx.setter(target, 'file');
    await verifyDigestFile(ctx.workspace, target, expectedSha256, ctx.fsApi, ctx);
  } catch (error) {
    await removeTempIfOwned(ctx, temp, expectedSha256);
    throw error;
  }
}

async function moveExclusive(ctx, source, destination, expectedSha256) {
  assertInside(ctx.workspace, destination, false);
  await assertAbsent(ctx.fsApi, destination);
  await verifyDigestFile(ctx.workspace, source, expectedSha256, ctx.fsApi, ctx);
  await ctx.fsApi.link(source, destination);
  await ctx.fsApi.unlink(source);
  ctx.onMutation();
  await verifyDigestFile(ctx.workspace, destination, expectedSha256, ctx.fsApi, ctx);
}

function rollbackFor(forward, rollbackActions) {
  let match;
  if (forward.kind === 'create_directory_exclusive') {
    match = rollbackActions.find((item) => item.kind === 'remove_directory_if_empty' && item.target === forward.target);
  } else if (forward.kind === 'create_file_exclusive' || forward.kind === 'create_file_atomic_exclusive') {
    match = rollbackActions.find((item) => item.kind === 'remove_file_if_digest_matches' && item.target === forward.target);
  } else if (forward.kind === 'move_file_exclusive') {
    match = rollbackActions.find((item) => item.kind === 'restore_file_exclusive' && item.target === forward.destination);
  }
  return match;
}

async function observePath(workspace, target, kind, fsApi, options, includeDigest = false) {
  assertInside(workspace, target, true);
  let stat;
  try {
    stat = await fsApi.lstat(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return { exists: false };
    throw new DisposableApplyError('state_unreadable');
  }
  if (stat.isSymbolicLink() || (kind === 'file' && (!stat.isFile() || stat.nlink !== 1)) ||
      (kind === 'directory' && !stat.isDirectory())) throw new DisposableApplyError('unsafe_existing_state');
  await verifySecureExisting(workspace, target, kind, fsApi, options);
  return includeDigest ? { exists: true, sha256: await digestFile(fsApi, target) } : { exists: true };
}

async function verifyWorkspacePermissions(workspace, options) {
  await verifySecureExisting(workspace, workspace.root, 'directory', options.fsApi ?? fs, options);
  await verifySecureExisting(workspace, workspace.marker_path, 'file', options.fsApi ?? fs, options);
}

async function verifySecureExisting(workspace, target, kind, fsApi, options) {
  const stat = await fsApi.lstat(target);
  if (stat.isSymbolicLink() || (kind === 'file' && (!stat.isFile() || stat.nlink !== 1)) ||
      (kind === 'directory' && !stat.isDirectory())) throw new DisposableApplyError('unsafe_existing_state');
  if (workspace.platform === 'win32') {
    const inspect = options.windowsSecurity ?? createWindowsSecurityAdapter();
    const result = await inspect(target);
    if (result.reparsePoint || !result.ownerCurrentUser || result.writableByOtherUsers) {
      throw new DisposableApplyError('unsafe_permissions');
    }
  } else {
    const unsafe = kind === 'directory' ? 0o077 : 0o077;
    if ((stat.mode & unsafe) !== 0) throw new DisposableApplyError('unsafe_permissions');
  }
}

async function verifyDigestFile(workspace, target, expected, fsApi, options) {
  await verifySecureExisting(workspace, target, 'file', fsApi, options);
  if (await digestFile(fsApi, target) !== expected) throw new DisposableApplyError('digest_mismatch');
}

async function digestFile(fsApi, target) {
  const stat = await fsApi.lstat(target);
  if (stat.size < 0 || stat.size > MAX_MANAGED_FILE_BYTES) {
    throw new DisposableApplyError('managed_file_too_large');
  }
  const bytes = await fsApi.readFile(target);
  if (bytes.length !== stat.size) throw new DisposableApplyError('managed_file_changed');
  return createHash('sha256').update(bytes).digest('hex');
}

async function optionalFileDigest(fsApi, target) {
  try {
    const stat = await fsApi.lstat(target);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new DisposableApplyError('rollback_state_changed');
    return digestFile(fsApi, target);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function writeExclusive(fsApi, target, bytes, mode) {
  const handle = await fsApi.open(target, 'wx', mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function assertAbsent(fsApi, target) {
  try {
    await fsApi.lstat(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw new DisposableApplyError('state_unreadable');
  }
  throw new DisposableApplyError('target_exists');
}

async function removeTempIfOwned(ctx, temp, expectedSha256) {
  try {
    if (await optionalFileDigest(ctx.fsApi, temp) === expectedSha256) await ctx.fsApi.unlink(temp);
  } catch {
    // Deliberately leave unexpected temp state for manual inspection.
  }
}

function validateManifestWorkspace(workspace, manifest) {
  if (manifest?.payload?.platform !== workspace.platform) throw new DisposableApplyError('manifest_workspace_mismatch');
  for (const target of Object.values(manifest.payload.paths ?? {})) assertInside(workspace, target, false);
}

async function verifyFinalState(workspace, manifest, options) {
  const finalState = await observeDisposableState(workspace, manifest, options);
  if (finalState.launcher.kind !== 'managed_file' ||
      finalState.launcher.sha256 !== manifest.payload.content.launcher_sha256 ||
      finalState.config_file !== 'secure_file') {
    throw new DisposableApplyError('post_state_invalid');
  }
}

async function verifyParentChain(workspace, target, fsApi, options) {
  const pathApi = workspace.platform === 'win32' ? path.win32 : path.posix;
  let cursor = pathApi.dirname(target);
  while (true) {
    assertInside(workspace, cursor, true);
    await verifySecureExisting(workspace, cursor, 'directory', fsApi, options);
    if (samePath(workspace.platform, cursor, workspace.root)) return;
    const parent = pathApi.dirname(cursor);
    if (parent === cursor) throw new DisposableApplyError('parent_chain_escape');
    cursor = parent;
  }
}

function samePath(platform, left, right) {
  const normalize = (value) => platform === 'win32'
    ? value.replace(/^\\\\\?\\/, '').toLowerCase()
    : value;
  return normalize(left) === normalize(right);
}

function assertInside(workspace, target, allowExistingRoot) {
  if (typeof target !== 'string') throw new DisposableApplyError('target_outside_workspace');
  const pathApi = workspace.platform === 'win32' ? path.win32 : path.posix;
  const relative = pathApi.relative(workspace.root, target);
  if ((!allowExistingRoot && relative === '') || relative === '..' || relative.startsWith(`..${pathApi.sep}`) || pathApi.isAbsolute(relative)) {
    throw new DisposableApplyError('target_outside_workspace');
  }
}
