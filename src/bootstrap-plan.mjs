import path from 'node:path';

const PROJECT_FIELDS = new Set(['version', 'services']);
const PROJECT_SERVICE_FIELDS = new Set(['alias']);
const USER_FIELDS = new Set(['version', 'services']);
const USER_SERVICE_COMMON_FIELDS = new Set([
  'credential_class',
  'item_id',
  'secret_field',
  'username_field',
  'password_field',
]);
const ALIAS_PATTERN = /^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FIELD_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9_. -]{0,62}[A-Za-z0-9])?$/;
const CLASSES = new Set(['http_bearer', 'http_api_key_header', 'http_basic']);

export class BootstrapPlanError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BootstrapPlanError';
    this.code = code;
  }
}

/**
 * Build a deterministic, value-free plan without reading host state.
 * @param {{platform: string, homedir: string, env?: Record<string,string|undefined>, project: unknown, user: unknown}} input
 */
export function planBootstrap(input) {
  const roots = deriveUserRoots(input.platform, input.homedir, input.env ?? {});
  const project = validateProjectConfig(input.project);
  const user = validateUserConfig(input.user);
  const enabled = new Set(Object.keys(user.services));
  for (const alias of project.services) {
    if (!enabled.has(alias)) {
      throw new BootstrapPlanError(
        'service_not_enabled',
        `project service alias is not enabled in user configuration: ${alias}`,
      );
    }
  }

  return Object.freeze({
    version: 1,
    platform: normalizePlatform(input.platform),
    config_path: roots.configPath,
    install_root: roots.installRoot,
    launcher_path: roots.launcherPath,
    selected_services: Object.freeze([...project.services]),
    actions: Object.freeze([
      Object.freeze({ kind: 'verify_user_config', target: roots.configPath }),
      Object.freeze({ kind: 'verify_install_root', target: roots.installRoot }),
      Object.freeze({ kind: 'verify_launcher', target: roots.launcherPath }),
    ]),
  });
}

export function validateProjectConfig(raw) {
  const obj = exactObject(raw, PROJECT_FIELDS, 'project');
  if (obj.version !== 1 || !Array.isArray(obj.services)) {
    throw new BootstrapPlanError('invalid_project', 'project version/services are invalid');
  }
  const aliases = obj.services.map((entry) => {
    const service = exactObject(entry, PROJECT_SERVICE_FIELDS, 'project service');
    return validateAlias(service.alias);
  });
  if (aliases.length === 0 || new Set(aliases).size !== aliases.length) {
    throw new BootstrapPlanError('invalid_project', 'project services must be non-empty and unique');
  }
  return Object.freeze({ version: 1, services: Object.freeze(aliases) });
}

export function validateUserConfig(raw) {
  const obj = exactObject(raw, USER_FIELDS, 'user');
  if (obj.version !== 1 || !isPlainObject(obj.services)) {
    throw new BootstrapPlanError('invalid_user', 'user version/services are invalid');
  }
  const services = Object.create(null);
  for (const [rawAlias, rawService] of Object.entries(obj.services)) {
    const alias = validateAlias(rawAlias);
    const service = allowedObject(rawService, USER_SERVICE_COMMON_FIELDS, 'user service');
    if (!CLASSES.has(service.credential_class) || !UUID_PATTERN.test(service.item_id)) {
      throw new BootstrapPlanError('invalid_user', 'user service class or item reference is invalid');
    }
    const expected = service.credential_class === 'http_basic'
      ? new Set(['credential_class', 'item_id', 'username_field', 'password_field'])
      : new Set(['credential_class', 'item_id', 'secret_field']);
    assertExactKeys(service, expected, 'user service');
    if (service.credential_class === 'http_basic') {
      validateFieldReference(service.username_field);
      validateFieldReference(service.password_field);
    } else {
      validateFieldReference(service.secret_field);
    }
    services[alias] = Object.freeze({ ...service });
  }
  if (Object.keys(services).length === 0) {
    throw new BootstrapPlanError('invalid_user', 'user services must be non-empty');
  }
  return Object.freeze({ version: 1, services: Object.freeze(services) });
}

export function deriveUserRoots(platform, homedir, env = {}) {
  const normalized = normalizePlatform(platform);
  const pathApi = normalized === 'win32' ? path.win32 : path.posix;
  if (typeof homedir !== 'string' || !pathApi.isAbsolute(homedir)) {
    throw new BootstrapPlanError('invalid_home', 'homedir must be an absolute path');
  }
  let configRoot;
  let dataRoot;
  if (normalized === 'win32') {
    configRoot = requireAbsolute(env.LOCALAPPDATA, 'LOCALAPPDATA');
    dataRoot = path.win32.join(configRoot, 'Programs');
  } else if (normalized === 'darwin') {
    configRoot = path.posix.join(homedir, 'Library', 'Application Support');
    dataRoot = configRoot;
  } else {
    configRoot = env.XDG_CONFIG_HOME
      ? requireAbsolute(env.XDG_CONFIG_HOME, 'XDG_CONFIG_HOME')
      : path.posix.join(homedir, '.config');
    dataRoot = env.XDG_DATA_HOME
      ? requireAbsolute(env.XDG_DATA_HOME, 'XDG_DATA_HOME')
      : path.posix.join(homedir, '.local', 'share');
  }
  const appName = normalized === 'linux'
    ? 'bitwarden-agent-credential-bridge'
    : 'BitwardenAgentCredentialBridge';
  const configDir = joinFor(normalized, configRoot, appName);
  const installRoot = joinFor(normalized, dataRoot, appName);
  return Object.freeze({
    configPath: joinFor(normalized, configDir, 'config.json'),
    installRoot,
    launcherPath: joinFor(normalized, installRoot, 'bin', normalized === 'win32' ? 'bw-agent-bridge.cmd' : 'bw-agent-bridge'),
  });
}

function normalizePlatform(platform) {
  if (!['win32', 'darwin', 'linux'].includes(platform)) {
    throw new BootstrapPlanError('unsupported_platform', 'platform must be win32, darwin, or linux');
  }
  return platform;
}

function validateAlias(value) {
  if (typeof value !== 'string' || !ALIAS_PATTERN.test(value)) {
    throw new BootstrapPlanError('invalid_alias', 'service alias must use 1..64 lowercase ASCII identifier characters');
  }
  return value;
}

function validateFieldReference(value) {
  if (typeof value !== 'string' || !FIELD_PATTERN.test(value)) {
    throw new BootstrapPlanError('invalid_field_reference', 'credential field reference is invalid');
  }
}

function exactObject(value, allowed, label) {
  if (!isPlainObject(value)) {
    throw new BootstrapPlanError('invalid_schema', `${label} must be a plain object`);
  }
  assertExactKeys(value, allowed, label);
  assertDataProperties(value, label);
  return value;
}

function allowedObject(value, allowed, label) {
  if (!isPlainObject(value)) {
    throw new BootstrapPlanError('invalid_schema', `${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    throw new BootstrapPlanError('invalid_schema', `${label} fields are invalid`);
  }
  assertDataProperties(value, label);
  return value;
}

function assertExactKeys(value, allowed, label) {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string') || keys.length !== allowed.size || keys.some((key) => !allowed.has(key))) {
    throw new BootstrapPlanError('invalid_schema', `${label} fields are invalid`);
  }
}

function assertDataProperties(value, label) {
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new BootstrapPlanError('invalid_schema', `${label} fields must be explicit data values`);
    }
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function requireAbsolute(value, name) {
  if (typeof value !== 'string' || value.length === 0 || !(path.win32.isAbsolute(value) || path.posix.isAbsolute(value))) {
    throw new BootstrapPlanError('invalid_environment', `${name} must be an absolute path`);
  }
  return value;
}

function joinFor(platform, ...parts) {
  return platform === 'win32' ? path.win32.join(...parts) : path.posix.join(...parts);
}
