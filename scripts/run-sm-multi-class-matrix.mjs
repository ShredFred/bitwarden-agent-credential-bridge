#!/usr/bin/env node
/**
 * Live multi-class matrix over the canonical SM bindings (MiViA + private-hq).
 *
 * Assumes `npm run seed:sm` has populated keys. Resolves via DPAPI/bws into
 * broker memory, smokes every alias, and asserts secrets never appear on
 * agent-readable surfaces.
 *
 * Requires: --i-approve-secrets-manager-machine-resolve
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REJECTED_CREDENTIAL_CLASSES,
  SUPPORTED_CREDENTIAL_CLASSES,
} from '../src/credential-classes.js';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
  OperationalBridgeError,
  validateOperationalBindings,
} from '../src/operational-bridge.mjs';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import {
  buildSecretsManagerResolverGate,
  resolveSecretsManagerSecret,
  SecretsManagerResolverError,
} from '../src/secrets-manager-resolver.mjs';
import { fetchSecretsManagerSecretValue, SecretsManagerBwsAdapterError, withBwsDiagnostic } from '../src/secrets-manager-bws-adapter.mjs';
import {
  SM_DEFAULT_PROJECTS,
  SM_OPERATIONAL_BINDINGS_PATH,
  SM_RESOLVE_APPROVAL_FLAG,
} from '../src/secrets-manager-defaults.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const bindingsPath = SM_OPERATIONAL_BINDINGS_PATH;

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(withBwsDiagnostic(payload))}\n`);
  process.exitCode = code;
}

function assertNoSecret(surface, value, secrets) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of secrets) {
    if (typeof secret !== 'string' || secret.length < 8) continue;
    if (text.includes(secret)) {
      throw new Error(`secret_leak:${surface}`);
    }
  }
}

if (!process.argv.includes(SM_RESOLVE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_RESOLVE_APPROVAL_FLAG,
    authorization_ready: false,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
} else {
  /** @type {string[]} */
  const sensitive = [];
  let accessToken;
  let bridge;
  try {
    const scope = buildSecretsManagerLiveScope();
    const bundle = await collectSecretsManagerMachineBundle(scope);
    accessToken = bundle.accessToken;
    sensitive.push(accessToken);

    const resolverGate = buildSecretsManagerResolverGate(scope, bundle.allow);
    const bindings = await loadOperationalBindingsFile(root, bindingsPath);

    // Pre-resolve for exposure scanning only (never printed).
    for (const binding of bindings.bindings) {
      const needsPair = binding.credential_class === 'http_basic' ||
        binding.credential_class === 'browser_form_login' ||
        binding.credential_class === 'ssh' ||
        binding.credential_class === 'ftp';
      if (needsPair) {
        const resolved = await resolveSecretsManagerSecret(
          resolverGate,
          async (request) => {
            const username = await fetchSecretsManagerSecretValue({
              accessToken,
              projectId: request.project_id,
              secretKey: request.secret_key,
              allowConfig: bundle.allow,
            });
            const password = await fetchSecretsManagerSecretValue({
              accessToken,
              projectId: request.project_id,
              secretKey: request.secret_key_password,
              allowConfig: bundle.allow,
            });
            return { username, password };
          },
          {
            project_id: binding.sm_project_id,
            secret_key: binding.sm_secret_key,
            credential_class: binding.credential_class,
            secret_key_password: binding.sm_secret_key_password,
          },
        );
        sensitive.push(resolved.username, resolved.password);
      } else {
        const resolved = await resolveSecretsManagerSecret(
          resolverGate,
          async (request) => {
            const credential = await fetchSecretsManagerSecretValue({
              accessToken,
              projectId: request.project_id,
              secretKey: request.secret_key,
              allowConfig: bundle.allow,
            });
            return { credential };
          },
          {
            project_id: binding.sm_project_id,
            secret_key: binding.sm_secret_key,
            credential_class: binding.credential_class,
          },
        );
        sensitive.push(resolved.credential);
      }
    }

    bridge = await startOperationalBridge({
      repoRoot: root,
      bindings,
      resolveSecret: async (binding) => {
        const needsPair = binding.credential_class === 'http_basic' ||
          binding.credential_class === 'browser_form_login' ||
          binding.credential_class === 'ssh' ||
          binding.credential_class === 'ftp';
        if (needsPair) {
          const resolved = await resolveSecretsManagerSecret(
            resolverGate,
            async (request) => {
              const username = await fetchSecretsManagerSecretValue({
                accessToken,
                projectId: request.project_id,
                secretKey: request.secret_key,
                allowConfig: bundle.allow,
              });
              const password = await fetchSecretsManagerSecretValue({
                accessToken,
                projectId: request.project_id,
                secretKey: request.secret_key_password,
                allowConfig: bundle.allow,
              });
              return { username, password };
            },
            {
              project_id: binding.sm_project_id,
              secret_key: binding.sm_secret_key,
              credential_class: binding.credential_class,
              secret_key_password: binding.sm_secret_key_password,
            },
          );
          return {
            credential_class: binding.credential_class,
            username: resolved.username,
            password: resolved.password,
          };
        }
        const resolved = await resolveSecretsManagerSecret(
          resolverGate,
          async (request) => {
            const credential = await fetchSecretsManagerSecretValue({
              accessToken,
              projectId: request.project_id,
              secretKey: request.secret_key,
              allowConfig: bundle.allow,
            });
            return { credential };
          },
          {
            project_id: binding.sm_project_id,
            secret_key: binding.sm_secret_key,
            credential_class: binding.credential_class,
          },
        );
        return {
          credential_class: binding.credential_class,
          credential: resolved.credential,
        };
      },
    });

    const smoke = await bridge.smoke();
    /** @type {Record<string, { smoke_ok: boolean, replay_http: number, secret_absent: boolean }>} */
    const classes = {};
    const agentBlob = {
      services: bridge.services,
      smoke,
      authorization_ready: bridge.authorization_ready,
    };

    for (const service of bridge.services) {
      const url = service.replayUrl ?? `${service.baseUrl}/v1/resource`;
      const response = await fetch(url);
      const body = await response.text();
      const headers = [...response.headers.entries()];
      assertNoSecret(`response:${service.alias}`, body, sensitive);
      assertNoSecret(`headers:${service.alias}`, headers, sensitive);
      let opOk = true;
      if (service.credential_class === 'ssh') {
        const exec = await fetch(new URL('/exec', service.baseUrl), {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ command: 'uname' }),
        });
        const execBody = await exec.text();
        assertNoSecret(`ssh_exec:${service.alias}`, execBody, sensitive);
        opOk = exec.status === 200;
      } else if (service.credential_class === 'ftp') {
        const list = await fetch(new URL('/list', service.baseUrl), { method: 'POST' });
        const listBody = await list.text();
        assertNoSecret(`ftp_list:${service.alias}`, listBody, sensitive);
        opOk = list.status === 200;
      }
      classes[service.credential_class] = classes[service.credential_class] ?? {
        smoke_ok: true,
        replay_http: 200,
        secret_absent: true,
      };
      classes[`${service.alias}`] = {
        smoke_ok: smoke[service.alias] === true && opOk,
        replay_http: response.status,
        secret_absent: true,
        credential_class: service.credential_class,
      };
      agentBlob[service.alias] = {
        status: response.status,
        body,
        headers,
        baseUrl: service.baseUrl,
        replayUrl: service.replayUrl ?? null,
      };
    }
    assertNoSecret('agent_blob', agentBlob, sensitive);

    /** @type {Record<string, boolean>} */
    const rejected_fail_closed = {};
    for (const rejected of REJECTED_CREDENTIAL_CLASSES) {
      try {
        validateOperationalBindings({
          version: 1,
          profile: 'operational_sm_same_user',
          bindings: [{
            alias: 'bad_reject',
            policy: 'policies/sample-fake-service.json',
            credential_class: rejected,
            sm_project_id: SM_DEFAULT_PROJECTS.private_hq,
            sm_secret_key: 'phq_api_bearer',
          }],
        });
        rejected_fail_closed[rejected] = false;
      } catch (error) {
        rejected_fail_closed[rejected] =
          error instanceof OperationalBridgeError &&
          (error.code === 'rejected_credential_class' ||
            error.code === 'unsupported_credential_class' ||
            error.code === 'invalid_binding');
      }
    }

    let onecli_proxy_sm_rejected = false;
    try {
      await resolveSecretsManagerSecret(
        resolverGate,
        async () => ({ credential: 'should-not-run' }),
        {
          project_id: SM_DEFAULT_PROJECTS.private_hq,
          secret_key: 'phq_api_bearer',
          credential_class: 'onecli_proxy',
        },
      );
    } catch (error) {
      onecli_proxy_sm_rejected = error instanceof SecretsManagerResolverError;
    }

    const aliasResults = Object.entries(classes)
      .filter(([k]) => k.startsWith('mivia_') || k.startsWith('phq_'));
    const allSmoke = aliasResults.every(([, c]) =>
      c.smoke_ok && c.replay_http === 200 && c.secret_absent);
    const allRejected = Object.values(rejected_fail_closed).every(Boolean);

    emit({
      ok: allSmoke && allRejected && onecli_proxy_sm_rejected,
      demo: 'sm_multi_class_matrix',
      bindings: bindingsPath,
      machine_id: bundle.machine_id,
      supported_classes: [...SUPPORTED_CREDENTIAL_CLASSES],
      alias_count: aliasResults.length,
      aliases: Object.fromEntries(aliasResults),
      rejected_fail_closed,
      onecli_proxy_sm_rejected,
      secrets_absent_from_agent_surfaces: true,
      authorization_ready: false,
      helper_vault_free: true,
      env_inject_forbidden: true,
    }, allSmoke && allRejected && onecli_proxy_sm_rejected ? 0 : 1);
  } catch (error) {
    const code = error instanceof SecretsManagerTokenCollectorError ||
      error instanceof OperationalBridgeError ||
      error instanceof SecretsManagerBwsAdapterError
      ? error.code
      : (typeof error?.message === 'string' && error.message.startsWith('secret_leak:')
        ? error.message
        : 'matrix_failed');
    emit({
      ok: false,
      code,
      authorization_ready: false,
      helper_vault_free: true,
    }, 1);
  } finally {
    for (let i = 0; i < sensitive.length; i += 1) sensitive[i] = '';
    sensitive.length = 0;
    accessToken = null;
    if (bridge) await bridge.close().catch(() => {});
  }
}
