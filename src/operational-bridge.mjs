import { readFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { startBroker } from './broker.js';
import { startBrowserSessionBroker } from './browser-session-broker.mjs';
import { startSshSessionBroker } from './ssh-session-broker.mjs';
import { startFtpSessionBroker } from './ftp-session-broker.mjs';
import {
  HTTP_INJECTION_CREDENTIAL_CLASSES,
  isRejectedCredentialClass,
  isSupportedCredentialClass,
} from './credential-classes.js';
import { resolveFakeVaultSecrets, selectFakeVaultSecret } from './fake-vault-resolver.mjs';
import { startFakeApi } from './fake-api.js';
import { startFakeLoginSite } from './fake-login-site.mjs';
import { startFakeSshServer } from './fake-ssh-server.mjs';
import { startFakeFtpServer } from './fake-ftp-server.mjs';
import {
  loadPolicy,
  validatePolicy,
  withBind,
  withLoginOrigin,
  withSessionTarget,
  withUpstream,
} from './policy.js';
import {
  absentOperationalAuthorizationForPlatform,
  composeOperationalAuthorizationForPlatform,
  PlatformOperationalAuthorizationError,
} from './platform-operational-authorization.mjs';
import process from 'node:process';

export class OperationalBridgeError extends Error {
  /**
   * @param {string} code
   */
  constructor(code) {
    super(`Operational bridge rejected: ${code}`);
    this.name = 'OperationalBridgeError';
    this.code = code;
  }
}

const ALIAS_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SECRET_KEY = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;
const OPERATIONAL_CLASSES = new Set([
  ...HTTP_INJECTION_CREDENTIAL_CLASSES,
  'browser_form_login',
  'ssh',
  'ftp',
]);

/** Loopback discovery so agents can re-read service ports after losing stdout. */
export const OPERATIONAL_DISCOVERY_BIND = 'http://127.0.0.1:18791';

/**
 * @typedef {{
 *   alias: string,
 *   policy: string,
 *   credential_class: string,
 *   sm_project_id?: string,
 *   sm_secret_key?: string,
 *   sm_secret_key_password?: string,
 * }} OperationalBinding
 */

/**
 * Validate a tracked operational binding table (no secrets, no vault refs).
 * Supports `operational_disposable_dev` (fake vault) and
 * `operational_sm_same_user` (Secrets Manager keys only).
 * @param {unknown} raw
 * @returns {{ version: 1, profile: string, bindings: OperationalBinding[] }}
 */
export function validateOperationalBindings(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new OperationalBridgeError('invalid_bindings');
  }
  const obj = /** @type {Record<string, unknown>} */ (raw);
  const keys = Reflect.ownKeys(obj);
  if (
    keys.length !== 3 ||
    !keys.includes('version') ||
    !keys.includes('profile') ||
    !keys.includes('bindings')
  ) {
    throw new OperationalBridgeError('invalid_bindings');
  }
  if (obj.version !== 1) {
    throw new OperationalBridgeError('invalid_bindings');
  }
  if (obj.profile === 'operational_sm_same_user') {
    return validateSmOperationalBindings(obj);
  }
  if (obj.profile !== 'operational_disposable_dev') {
    throw new OperationalBridgeError('invalid_bindings');
  }
  if (!Array.isArray(obj.bindings) || obj.bindings.length < 1 || obj.bindings.length > 16) {
    throw new OperationalBridgeError('invalid_bindings');
  }

  /** @type {OperationalBinding[]} */
  const bindings = [];
  const aliases = new Set();
  for (const entry of obj.bindings) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new OperationalBridgeError('invalid_binding');
    }
    const e = /** @type {Record<string, unknown>} */ (entry);
    const entryKeys = Reflect.ownKeys(e);
    if (
      entryKeys.length !== 3 ||
      !entryKeys.includes('alias') ||
      !entryKeys.includes('policy') ||
      !entryKeys.includes('credential_class')
    ) {
      throw new OperationalBridgeError('invalid_binding');
    }
    if (typeof e.alias !== 'string' || !ALIAS_PATTERN.test(e.alias)) {
      throw new OperationalBridgeError('invalid_alias');
    }
    if (aliases.has(e.alias)) {
      throw new OperationalBridgeError('duplicate_alias');
    }
    aliases.add(e.alias);
    if (typeof e.policy !== 'string' || !e.policy.startsWith('policies/') ||
        e.policy.includes('..') || e.policy.includes('\\') || !e.policy.endsWith('.json')) {
      throw new OperationalBridgeError('invalid_policy_path');
    }
    if (isRejectedCredentialClass(e.credential_class)) {
      throw new OperationalBridgeError('rejected_credential_class');
    }
    if (!isSupportedCredentialClass(e.credential_class) ||
        !OPERATIONAL_CLASSES.has(e.credential_class)) {
      throw new OperationalBridgeError('unsupported_credential_class');
    }
    bindings.push({
      alias: e.alias,
      policy: e.policy,
      credential_class: e.credential_class,
    });
  }
  return {
    version: 1,
    profile: 'operational_disposable_dev',
    bindings,
  };
}

/**
 * @param {Record<string, unknown>} obj
 */
function validateSmOperationalBindings(obj) {
  if (!Array.isArray(obj.bindings) || obj.bindings.length < 1 || obj.bindings.length > 16) {
    throw new OperationalBridgeError('invalid_bindings');
  }
  /** @type {OperationalBinding[]} */
  const bindings = [];
  const aliases = new Set();
  for (const entry of obj.bindings) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new OperationalBridgeError('invalid_binding');
    }
    const e = /** @type {Record<string, unknown>} */ (entry);
    const entryKeys = Reflect.ownKeys(e);
    const required = ['alias', 'policy', 'credential_class', 'sm_project_id', 'sm_secret_key'];
    for (const key of required) {
      if (!entryKeys.includes(key)) {
        throw new OperationalBridgeError('invalid_binding');
      }
    }
    for (const key of entryKeys) {
      if (typeof key !== 'string' ||
          ![...required, 'sm_secret_key_password'].includes(key)) {
        throw new OperationalBridgeError('invalid_binding');
      }
    }
    if (typeof e.alias !== 'string' || !ALIAS_PATTERN.test(e.alias)) {
      throw new OperationalBridgeError('invalid_alias');
    }
    if (aliases.has(e.alias)) {
      throw new OperationalBridgeError('duplicate_alias');
    }
    aliases.add(e.alias);
    if (typeof e.policy !== 'string' || !e.policy.startsWith('policies/') ||
        e.policy.includes('..') || e.policy.includes('\\') || !e.policy.endsWith('.json')) {
      throw new OperationalBridgeError('invalid_policy_path');
    }
    if (isRejectedCredentialClass(e.credential_class)) {
      throw new OperationalBridgeError('rejected_credential_class');
    }
    if (!isSupportedCredentialClass(e.credential_class) ||
        !OPERATIONAL_CLASSES.has(e.credential_class)) {
      throw new OperationalBridgeError('unsupported_credential_class');
    }
    if (typeof e.sm_project_id !== 'string' || !UUID.test(e.sm_project_id)) {
      throw new OperationalBridgeError('invalid_sm_project_id');
    }
    if (typeof e.sm_secret_key !== 'string' || !SECRET_KEY.test(e.sm_secret_key)) {
      throw new OperationalBridgeError('invalid_sm_secret_key');
    }
    const needsPassword = e.credential_class === 'http_basic' ||
      e.credential_class === 'browser_form_login' ||
      e.credential_class === 'ssh' ||
      e.credential_class === 'ftp';
    /** @type {OperationalBinding} */
    const binding = {
      alias: e.alias,
      policy: e.policy,
      credential_class: e.credential_class,
      sm_project_id: e.sm_project_id.toLowerCase(),
      sm_secret_key: e.sm_secret_key,
    };
    if (needsPassword) {
      if (typeof e.sm_secret_key_password !== 'string' ||
          !SECRET_KEY.test(e.sm_secret_key_password)) {
        throw new OperationalBridgeError('invalid_sm_secret_key_password');
      }
      binding.sm_secret_key_password = e.sm_secret_key_password;
    } else if (e.sm_secret_key_password !== undefined) {
      throw new OperationalBridgeError('invalid_binding');
    }
    bindings.push(binding);
  }
  return {
    version: 1,
    profile: 'operational_sm_same_user',
    bindings,
  };
}

/**
 * Start an in-process multi-service operational bridge using fake vault secrets.
 * Foreground only: caller must retain the handle and call close(). No PID files.
 *
 * authorization_ready is taken only from the platform-scoped production
 * authorization compiler (Windows 9e / macOS 11j / Linux 12t) — never a
 * hardcoded true. Omitting productionAuthorizationEvidence uses the incomplete
 * branded evidence path for the selected platform (default: process.platform).
 *
 * @param {{
 *   repoRoot: string,
 *   bindings: unknown,
 *   fetchImpl?: typeof fetch,
 *   platform?: 'win32' | 'darwin' | 'linux',
 *   resolveSecret?: (binding: OperationalBinding) => Promise<{
 *     credential_class: string,
 *     credential?: string,
 *     username?: string,
 *     password?: string,
 *   }>,
 *   productionAuthorizationEvidence?: {
 *     installGateReport: object,
 *     layoutPlan: object,
 *     handleBoundEvidence: object,
 *     targetAclEvidence: object,
 *     peerEvidence: object,
 *   } | null,
 *   discoveryBind?: string,
 * }} options
 */
export async function startOperationalBridge(options) {
  if (typeof options.repoRoot !== 'string' || options.repoRoot.length < 1) {
    throw new OperationalBridgeError('invalid_repo_root');
  }
  const table = validateOperationalBindings(options.bindings);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const platform = options.platform ?? process.platform;
  const smMode = table.profile === 'operational_sm_same_user';
  if (smMode && typeof options.resolveSecret !== 'function') {
    throw new OperationalBridgeError('sm_resolver_required');
  }

  let authorizationReport;
  try {
    authorizationReport =
      options.productionAuthorizationEvidence === undefined ||
      options.productionAuthorizationEvidence === null
        ? absentOperationalAuthorizationForPlatform(platform)
        : composeOperationalAuthorizationForPlatform(
          platform,
          options.productionAuthorizationEvidence,
        );
  } catch (error) {
    if (error instanceof PlatformOperationalAuthorizationError) {
      throw new OperationalBridgeError(error.code);
    }
    if (error && typeof error === 'object' && typeof error.code === 'string') {
      throw new OperationalBridgeError(error.code);
    }
    throw error;
  }

  /** @type {Array<{ kind: string, close: () => Promise<void> }>} */
  const resources = [];
  /** @type {Array<{
   *   alias: string,
   *   credential_class: string,
   *   runtime: string,
   *   baseUrl: string,
   *   replayUrl?: string,
   * }>} */
  const services = [];

  const aliasMap = Object.create(null);
  for (const binding of table.bindings) {
    aliasMap[binding.alias] = { credential_class: binding.credential_class };
  }
  const secrets = smMode ? null : resolveFakeVaultSecrets(aliasMap);

  let cleaning = false;
  const cleanup = async () => {
    if (cleaning) return;
    cleaning = true;
    for (const resource of [...resources].reverse()) {
      try {
        await resource.close();
      } catch {
        // Continue reverse cleanup after individual failures.
      }
    }
    resources.length = 0;
  };

  try {
    for (const binding of table.bindings) {
      const policyPath = path.join(options.repoRoot, binding.policy);
      const rawPolicy = await loadPolicy(policyPath);
      const policy = validatePolicy(rawPolicy);
      if (policy.credential_class !== binding.credential_class) {
        throw new OperationalBridgeError('binding_class_mismatch');
      }
      const selected = smMode
        ? await options.resolveSecret(binding)
        : selectFakeVaultSecret(secrets, binding.alias);
      if (selected.credential_class !== binding.credential_class) {
        throw new OperationalBridgeError('secret_class_mismatch');
      }

      if (binding.credential_class === 'browser_form_login') {
        const site = await startFakeLoginSite({
          credentials: {
            username: selected.username,
            password: selected.password,
          },
          hiddenFields: Object.fromEntries(
            policy.hidden_fields.map((name) => [name, `token-${binding.alias}`]),
          ),
        });
        resources.push({ kind: 'login_site', close: () => site.close() });
        const broker = await startBrowserSessionBroker({
          policy: withBind(
            withLoginOrigin(policy, site.baseUrl),
            'http://127.0.0.1:0',
          ),
          credentials: {
            username: selected.username,
            password: selected.password,
          },
          fetchImpl,
        });
        resources.push({ kind: 'browser_broker', close: () => broker.close() });
        services.push({
          alias: binding.alias,
          credential_class: binding.credential_class,
          runtime: 'browser_session',
          baseUrl: broker.baseUrl,
          replayUrl: broker.replayUrl,
        });
        continue;
      }

      if (binding.credential_class === 'ssh') {
        const fake = await startFakeSshServer({
          credentials: {
            username: selected.username,
            password: selected.password,
          },
          allowedCommands: [...policy.allowed_commands],
        });
        resources.push({ kind: 'ssh_server', close: () => fake.close() });
        const broker = await startSshSessionBroker({
          policy: withSessionTarget(
            withBind(policy, 'http://127.0.0.1:0'),
            { host: fake.host, port: fake.port },
          ),
          credentials: {
            username: selected.username,
            password: selected.password,
          },
        });
        resources.push({ kind: 'ssh_broker', close: () => broker.close() });
        services.push({
          alias: binding.alias,
          credential_class: binding.credential_class,
          runtime: 'ssh_session',
          baseUrl: broker.baseUrl,
          replayUrl: broker.replayUrl,
        });
        continue;
      }

      if (binding.credential_class === 'ftp') {
        const fake = await startFakeFtpServer({
          credentials: {
            username: selected.username,
            password: selected.password,
          },
        });
        resources.push({ kind: 'ftp_server', close: () => fake.close() });
        const broker = await startFtpSessionBroker({
          policy: withSessionTarget(
            withBind(policy, 'http://127.0.0.1:0'),
            { host: fake.host, port: fake.port },
          ),
          credentials: {
            username: selected.username,
            password: selected.password,
          },
        });
        resources.push({ kind: 'ftp_broker', close: () => broker.close() });
        services.push({
          alias: binding.alias,
          credential_class: binding.credential_class,
          runtime: 'ftp_session',
          baseUrl: broker.baseUrl,
          replayUrl: broker.replayUrl,
        });
        continue;
      }

      /** @type {Awaited<ReturnType<typeof startFakeApi>>} */
      let api;
      if (binding.credential_class === 'http_basic') {
        api = await startFakeApi({
          credentials: {
            username: selected.username,
            password: selected.password,
          },
          path: policy.path,
          method: policy.method,
          credentialClass: 'http_basic',
        });
      } else if (binding.credential_class === 'http_api_key_header') {
        api = await startFakeApi({
          sentinel: selected.credential,
          path: policy.path,
          method: policy.method,
          credentialClass: 'http_api_key_header',
          headerName: policy.header_name,
        });
      } else if (binding.credential_class === 'http_api_key_query') {
        api = await startFakeApi({
          sentinel: selected.credential,
          path: policy.path,
          method: policy.method,
          credentialClass: 'http_api_key_query',
          queryName: policy.query_name,
        });
      } else {
        api = await startFakeApi({
          sentinel: selected.credential,
          path: policy.path,
          method: policy.method,
          credentialClass: 'http_bearer',
        });
      }
      resources.push({ kind: 'fake_api', close: () => api.close() });

      const brokerPolicy = withUpstream(
        withBind(policy, 'http://127.0.0.1:0'),
        api.baseUrl,
      );
      const broker = binding.credential_class === 'http_basic'
        ? await startBroker({
          policy: brokerPolicy,
          credentials: {
            username: selected.username,
            password: selected.password,
          },
          fetchImpl,
        })
        : await startBroker({
          policy: brokerPolicy,
          sentinel: selected.credential,
          fetchImpl,
        });
      resources.push({ kind: 'http_broker', close: () => broker.close() });
      services.push({
        alias: binding.alias,
        credential_class: binding.credential_class,
        runtime: 'http_broker',
        baseUrl: broker.baseUrl,
      });
    }
  } catch (error) {
    await cleanup();
    if (error instanceof OperationalBridgeError) {
      throw error;
    }
    throw new OperationalBridgeError('startup_failed');
  }

  const discoveryBind = options.discoveryBind ?? OPERATIONAL_DISCOVERY_BIND;
  let discoveryUrl;
  try {
    discoveryUrl = await startOperationalDiscovery({
      bind: discoveryBind,
      services,
      profile: table.profile,
      authorizationReady: authorizationReport.authorization_ready === true,
      helperVaultFree: authorizationReport.helper_vault_free === true,
      secretsManagerMode: smMode,
    });
  } catch {
    await cleanup();
    throw new OperationalBridgeError('discovery_bind_failed');
  }
  resources.push({
    kind: 'discovery',
    close: () => closeHttp(discoveryUrl.server),
  });

  return Object.freeze({
    profile: table.profile,
    services: Object.freeze(services.map((s) => Object.freeze({ ...s }))),
    discoveryUrl: discoveryUrl.baseUrl,
    harness_ready: true,
    disposable_dev_ready: false,
    secrets_manager_mode: smMode,
    // Copied from the wired Phase 9a/9e report only — never a literal true.
    authorization_ready: authorizationReport.authorization_ready,
    production_authorization_terminal_code: authorizationReport.terminal_code,
    operational_authorization_wired:
      authorizationReport.operational_bridge_unwired === false,
    personal_vault_forbidden: authorizationReport.personal_vault_forbidden === true,
    company_vault_forbidden: authorizationReport.company_vault_forbidden === true,
    helper_vault_free: authorizationReport.helper_vault_free === true,
    async close() {
      await cleanup();
    },
    async smoke() {
      /** @type {Record<string, boolean>} */
      const results = {};
      for (const service of services) {
        const url = service.replayUrl ??
          `${service.baseUrl}${await pathForAlias(options.repoRoot, table, service.alias)}`;
        const response = await fetchImpl(url);
        results[service.alias] = response.status === 200;
        await response.arrayBuffer().catch(() => {});
      }
      return Object.freeze(results);
    },
  });
}

/**
 * @param {string} repoRoot
 * @param {{ bindings: OperationalBinding[] }} table
 * @param {string} alias
 */
async function pathForAlias(repoRoot, table, alias) {
  const binding = table.bindings.find((b) => b.alias === alias);
  if (!binding) {
    throw new OperationalBridgeError('unknown_alias');
  }
  const policy = await loadPolicy(path.join(repoRoot, binding.policy));
  return policy.path;
}

/**
 * Load bindings JSON from a tracked repo-relative path.
 * @param {string} repoRoot
 * @param {string} relativePath
 */
export async function loadOperationalBindingsFile(repoRoot, relativePath) {
  if (!relativePath.startsWith('samples/') && !relativePath.startsWith('policies/')) {
    throw new OperationalBridgeError('invalid_bindings_path');
  }
  if (relativePath.includes('..') || relativePath.includes('\\')) {
    throw new OperationalBridgeError('invalid_bindings_path');
  }
  let text;
  try {
    text = await readFile(path.join(repoRoot, relativePath), 'utf8');
  } catch {
    throw new OperationalBridgeError('bindings_unreadable');
  }
  return validateOperationalBindings(JSON.parse(text));
}

/**
 * @param {{
 *   bind: string,
 *   services: Array<{ alias: string, credential_class: string, runtime: string, baseUrl: string, replayUrl?: string }>,
 *   profile: string,
 *   authorizationReady: boolean,
 *   helperVaultFree: boolean,
 *   secretsManagerMode: boolean,
 * }} options
 */
function startOperationalDiscovery(options) {
  const bindUrl = new URL(options.bind);
  if (bindUrl.protocol !== 'http:' ||
      (bindUrl.hostname !== '127.0.0.1' && bindUrl.hostname !== 'localhost')) {
    return Promise.reject(new OperationalBridgeError('discovery_bind_failed'));
  }
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/status') {
      writeDiscoveryJson(res, {
        ok: true,
        profile: options.profile,
        harness_ready: true,
        secrets_manager_mode: options.secretsManagerMode,
        authorization_ready: options.authorizationReady,
        helper_vault_free: options.helperVaultFree,
        cookie_export_forbidden: true,
      });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/services') {
      writeDiscoveryJson(res, {
        ok: true,
        profile: options.profile,
        authorization_ready: options.authorizationReady,
        helper_vault_free: options.helperVaultFree,
        cookie_export_forbidden: true,
        services: options.services.map((service) => ({
          alias: service.alias,
          credential_class: service.credential_class,
          runtime: service.runtime,
          baseUrl: service.baseUrl,
          ...(service.replayUrl ? { replayUrl: service.replayUrl } : {}),
        })),
      });
      return;
    }
    res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'command_forbidden' }));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number(bindUrl.port), bindUrl.hostname, () => {
      server.off('error', reject);
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close(() => reject(new OperationalBridgeError('discovery_bind_failed')));
        return;
      }
      resolve({
        server,
        baseUrl: `http://${bindUrl.hostname}:${address.port}`,
      });
    });
  });
}

function writeDiscoveryJson(res, payload) {
  const body = JSON.stringify(payload);
  if (/"set-cookie"/i.test(body) || /cookie=/i.test(body)) {
    res.writeHead(502, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'sensitive_response_blocked' }));
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

function closeHttp(server) {
  return new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}
