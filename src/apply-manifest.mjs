import { createHash } from 'node:crypto';
import path from 'node:path';
import { deriveUserRoots } from './bootstrap-plan.mjs';

const MAX_LAUNCHER_BYTES = 1024 * 1024;
const MAX_PATH_CHARS = 240;
const EMPTY_CONFIG = Buffer.from('{"version":1,"services":{}}\n', 'utf8');
const EMPTY_CONFIG_SHA256 = sha256(EMPTY_CONFIG);
const STATE_FIELDS = new Set([
  'config_dir',
  'config_file',
  'install_root',
  'bin_dir',
  'launcher',
]);
const DIRECTORY_STATES = new Set(['absent', 'secure_directory']);
const CONFIG_STATES = new Set(['absent', 'secure_file']);

export class ApplyManifestError extends Error {
  constructor(code) {
    super(`apply manifest rejected: ${code}`);
    this.name = 'ApplyManifestError';
    this.code = code;
  }
}

/**
 * Build a deterministic description of a future install. Performs no I/O.
 * @param {{platform:string,homedir:string,env?:Record<string,string|undefined>,launcherBytes:Uint8Array,observed:unknown}} input
 */
export function buildApplyManifest(input) {
  const roots = deriveUserRoots(input.platform, input.homedir, input.env ?? {});
  const observed = validateObservedState(input.observed);
  const launcherBytes = copyLauncherBytes(input.launcherBytes);
  const launcherSha256 = sha256(launcherBytes);
  const pathApi = input.platform === 'win32' ? path.win32 : path.posix;
  const configDir = pathApi.dirname(roots.configPath);
  const binDir = pathApi.dirname(roots.launcherPath);
  const paths = {
    config_dir: configDir,
    config_file: roots.configPath,
    install_root: roots.installRoot,
    bin_dir: binDir,
    launcher: roots.launcherPath,
  };
  validatePaths(input.platform, paths);

  const seed = sha256(Buffer.from(canonicalJson({
    schema_version: 1,
    platform: input.platform,
    paths,
    launcher_sha256: launcherSha256,
    observed,
  }), 'utf8'));
  const backup = observed.launcher.kind === 'managed_file'
    ? `${paths.launcher}.rollback-${seed.slice(0, 24)}`
    : null;
  if (backup !== null && backup.length > MAX_PATH_CHARS) {
    throw new ApplyManifestError('path_too_long');
  }

  const forward = [];
  const rollback = [];
  const permission = input.platform === 'win32'
    ? 'current_user_system_admin_write'
    : 'owner_only';

  if (observed.config_dir === 'absent') {
    add(forward, 'create_directory_exclusive', paths.config_dir, { permission });
    rollback.unshift(action('remove_directory_if_empty', paths.config_dir));
  }
  if (observed.config_file === 'absent') {
    add(forward, 'create_file_exclusive', paths.config_file, {
      content_sha256: EMPTY_CONFIG_SHA256,
      permission,
    });
    rollback.unshift(action('remove_file_if_digest_matches', paths.config_file, {
      expected_sha256: EMPTY_CONFIG_SHA256,
    }));
  }
  if (observed.install_root === 'absent') {
    add(forward, 'create_directory_exclusive', paths.install_root, { permission });
    rollback.unshift(action('remove_directory_if_empty', paths.install_root));
  }
  if (observed.bin_dir === 'absent') {
    add(forward, 'create_directory_exclusive', paths.bin_dir, { permission });
    rollback.unshift(action('remove_directory_if_empty', paths.bin_dir));
  }

  if (observed.launcher.kind === 'absent') {
    add(forward, 'create_file_atomic_exclusive', paths.launcher, {
      content_sha256: launcherSha256,
      permission,
    });
    rollback.unshift(action('remove_file_if_digest_matches', paths.launcher, {
      expected_sha256: launcherSha256,
    }));
  } else {
    add(forward, 'assert_path_absent', backup);
    add(forward, 'move_file_exclusive', paths.launcher, {
      destination: backup,
      expected_sha256: observed.launcher.sha256,
    });
    add(forward, 'create_file_atomic_exclusive', paths.launcher, {
      content_sha256: launcherSha256,
      permission,
    });
    rollback.unshift(
      action('restore_file_exclusive', backup, {
        destination: paths.launcher,
        expected_source_sha256: observed.launcher.sha256,
        expected_destination_sha256: launcherSha256,
      }),
    );
  }

  const payload = deepFreeze({
    schema_version: 1,
    plan_id: seed,
    platform: input.platform,
    paths,
    observed,
    content: {
      empty_config_sha256: EMPTY_CONFIG_SHA256,
      launcher_sha256: launcherSha256,
    },
    preconditions: {
      revalidate_immediately_before_apply: true,
      reject_links_reparse_and_hardlinks: true,
      validate_every_parent_segment: true,
      backup_path_must_be_absent: backup !== null,
    },
    forward: forward.map((entry, index) => ({ sequence: index + 1, ...entry })),
    rollback: rollback.map((entry, index) => ({ sequence: index + 1, ...entry })),
  });
  const manifestSha256 = sha256(Buffer.from(canonicalJson(payload), 'utf8'));
  return deepFreeze({
    payload,
    manifest_sha256: manifestSha256,
    confirmation: `APPLY ${manifestSha256}`,
  });
}

export function verifyManifestConfirmation(manifest, confirmation) {
  try {
    const obj = exactPlainObject(manifest, new Set(['payload', 'manifest_sha256', 'confirmation']), 'manifest');
    if (typeof obj.manifest_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(obj.manifest_sha256)) return false;
    const actual = sha256(Buffer.from(canonicalJson(obj.payload), 'utf8'));
    return actual === obj.manifest_sha256 &&
      obj.confirmation === `APPLY ${actual}` &&
      confirmation === `APPLY ${actual}`;
  } catch {
    return false;
  }
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (Array.isArray(value)) {
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (lengthDescriptor === undefined || !('value' in lengthDescriptor)) {
      throw new ApplyManifestError('non_canonical_value');
    }
    const length = lengthDescriptor.value;
    const keys = Reflect.ownKeys(value).filter((key) => key !== 'length');
    if (keys.length !== length) throw new ApplyManifestError('non_canonical_value');
    const out = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !('value' in descriptor)) {
        throw new ApplyManifestError('non_canonical_value');
      }
      out.push(canonicalize(descriptor.value));
    }
    return out;
  }
  if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ApplyManifestError('non_canonical_value');
  }
  const out = {};
  for (const key of Reflect.ownKeys(value).sort()) {
    if (typeof key !== 'string') throw new ApplyManifestError('non_canonical_value');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new ApplyManifestError('non_canonical_value');
    out[key] = canonicalize(descriptor.value);
  }
  return out;
}

function validateObservedState(raw) {
  const obj = exactPlainObject(raw, STATE_FIELDS, 'observed');
  if (!DIRECTORY_STATES.has(obj.config_dir) || !CONFIG_STATES.has(obj.config_file) ||
      !DIRECTORY_STATES.has(obj.install_root) || !DIRECTORY_STATES.has(obj.bin_dir)) {
    throw new ApplyManifestError('invalid_observed_state');
  }
  const launcherValue = Object.getOwnPropertyDescriptor(obj, 'launcher').value;
  const launcherKind = dataPropertyValue(launcherValue, 'kind', 'launcher');
  const launcher = exactPlainObject(launcherValue, launcherKind === 'managed_file'
    ? new Set(['kind', 'sha256'])
    : new Set(['kind']), 'launcher');
  if (launcher.kind !== 'absent' && launcher.kind !== 'managed_file') {
    throw new ApplyManifestError('invalid_observed_state');
  }
  if (launcher.kind === 'managed_file' && (typeof launcher.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(launcher.sha256))) {
    throw new ApplyManifestError('invalid_observed_state');
  }
  if ((obj.config_dir === 'absent' && obj.config_file !== 'absent') ||
      (obj.install_root === 'absent' && (obj.bin_dir !== 'absent' || launcher.kind !== 'absent')) ||
      (obj.bin_dir === 'absent' && launcher.kind !== 'absent')) {
    throw new ApplyManifestError('incoherent_observed_state');
  }
  return deepFreeze({
    config_dir: obj.config_dir,
    config_file: obj.config_file,
    install_root: obj.install_root,
    bin_dir: obj.bin_dir,
    launcher: { ...launcher },
  });
}

function validatePaths(platform, paths) {
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  for (const value of Object.values(paths)) {
    if (!pathApi.isAbsolute(value) || value.length > MAX_PATH_CHARS || value.includes('\0')) {
      throw new ApplyManifestError('invalid_path');
    }
  }
  assertDescendant(pathApi, paths.config_dir, paths.config_file);
  assertDescendant(pathApi, paths.install_root, paths.bin_dir);
  assertDescendant(pathApi, paths.install_root, paths.launcher);
  assertDescendant(pathApi, paths.bin_dir, paths.launcher);
}

function assertDescendant(pathApi, parent, child) {
  const relative = pathApi.relative(parent, child);
  if (relative === '' || relative === '..' || relative.startsWith(`..${pathApi.sep}`) || pathApi.isAbsolute(relative)) {
    throw new ApplyManifestError('path_escape');
  }
}

function copyLauncherBytes(value) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > MAX_LAUNCHER_BYTES) {
    throw new ApplyManifestError('invalid_launcher');
  }
  return Buffer.from(value);
}

function action(kind, target, extra = {}) {
  return { kind, target, ...extra };
}

function add(actions, kind, target, extra = {}) {
  actions.push(action(kind, target, extra));
}

function exactPlainObject(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ApplyManifestError(`invalid_${label}`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size || keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new ApplyManifestError(`invalid_${label}`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new ApplyManifestError(`invalid_${label}`);
  }
  return value;
}

function dataPropertyValue(value, key, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ApplyManifestError(`invalid_${label}`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !('value' in descriptor)) {
    throw new ApplyManifestError(`invalid_${label}`);
  }
  return descriptor.value;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
