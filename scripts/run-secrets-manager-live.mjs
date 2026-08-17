#!/usr/bin/env node
/**
 * Operator-approved Secrets Manager machine live smoke (Phase 14).
 *
 * Loads machine allowlist + access token, resolves one bound SM secret through
 * bws (or fails closed), and smokes a loopback broker. Never prints tokens or
 * secret values. authorization_ready stays false. Helper stays vault-free.
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startBroker } from '../src/broker.js';
import { FAKE_API_CONSTANT_BODY } from '../src/constants.js';
import { startFakeApi } from '../src/fake-api.js';
import { loadPolicy, withUpstream } from '../src/policy.js';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import {
  buildSecretsManagerResolverGate,
  resolveSecretsManagerSecret,
} from '../src/secrets-manager-resolver.mjs';
import { fetchSecretsManagerSecretValue, SecretsManagerBwsAdapterError, withBwsDiagnostic } from '../src/secrets-manager-bws-adapter.mjs';
import { loadOperationalBindingsFile } from '../src/operational-bridge.mjs';

const APPROVAL_FLAG = '--i-approve-secrets-manager-machine-resolve';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const bindingsPath = 'samples/operational/bindings-sm.json';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(withBwsDiagnostic(payload))}\n`);
  process.exitCode = code;
}

function assertNoSecret(surface, value, secrets) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of secrets) {
    if (typeof secret !== 'string' || secret.length < 1) continue;
    if (text.includes(secret)) {
      throw new Error(`secret_leak:${surface}`);
    }
  }
}

if (!process.argv.includes(APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: APPROVAL_FLAG,
    authorization_ready: false,
    helper_vault_free: true,
    env_inject_forbidden: true,
    secrets_manager_allowed: true,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin') {
  emit({
    ok: false,
    code: 'unsupported_platform',
    authorization_ready: false,
    helper_vault_free: true,
  }, 1);
} else {
  const scope = buildSecretsManagerLiveScope();
  let bundle;
  try {
    bundle = await collectSecretsManagerMachineBundle(scope);
  } catch (error) {
    const code = error instanceof SecretsManagerTokenCollectorError
      ? error.code
      : 'sm_machine_unavailable';
    emit({
      ok: false,
      code,
      live_secret_resolved: false,
      authorization_ready: false,
      helper_vault_free: true,
      secrets_manager_allowed: true,
    }, 1);
    bundle = null;
  }

  if (bundle) {
    const { allow, accessToken, evidence, machine_id } = bundle;
    const table = await loadOperationalBindingsFile(root, bindingsPath);
    const aliasFlagIdx = process.argv.indexOf('--alias');
    const wantedAlias = aliasFlagIdx >= 0 ? process.argv[aliasFlagIdx + 1] : null;
    const binding = wantedAlias
      ? table.bindings.find((b) => b.alias === wantedAlias)
      : table.bindings.find((b) => b.alias === 'privatehq_demo_bearer')
        || table.bindings[0];
    if (!binding) {
      emit({
        ok: false,
        code: 'binding_alias_absent',
        live_secret_resolved: false,
        authorization_ready: false,
        helper_vault_free: true,
        machine_id,
      }, 1);
    } else {
    const resolverGate = buildSecretsManagerResolverGate(scope, allow);
    let resolved;
    try {
      resolved = await resolveSecretsManagerSecret(
        resolverGate,
        async (request) => {
          const credential = await fetchSecretsManagerSecretValue({
            accessToken,
            projectId: request.project_id,
            secretKey: request.secret_key,
            allowConfig: allow,
          });
          return { credential };
        },
        {
          project_id: binding.sm_project_id,
          secret_key: binding.sm_secret_key,
          credential_class: binding.credential_class,
        },
      );
    } catch (error) {
      const code = error instanceof SecretsManagerBwsAdapterError
        ? error.code
        : 'sm_resolve_failed';
      emit({
        ok: false,
        code,
        live_secret_resolved: false,
        authorization_ready: false,
        helper_vault_free: true,
        machine_id,
      }, 1);
      resolved = null;
    }

    if (resolved) {
      const secrets = [accessToken, resolved.credential];
      assertNoSecret('resolved', { ok: true }, secrets);
      const basePolicy = await loadPolicy(path.join(root, binding.policy));
      const api = await startFakeApi({
        sentinel: resolved.credential,
        path: basePolicy.path,
        method: basePolicy.method,
        credentialClass: 'http_bearer',
      });
      let broker;
      try {
        const logs = [];
        broker = await startBroker({
          policy: withUpstream(basePolicy, api.baseUrl),
          sentinel: resolved.credential,
          log: (entry) => {
            assertNoSecret('log', entry, secrets);
            logs.push({ level: entry.level, message: entry.message });
          },
        });
        const response = await fetch(new URL(basePolicy.path, broker.baseUrl), {
          method: basePolicy.method,
        });
        const body = await response.json();
        assertNoSecret('response', body, secrets);
        assertNoSecret('logs', logs, secrets);
        const ok = response.status === 200 &&
          body.ok === FAKE_API_CONSTANT_BODY.ok &&
          evidence.sm_preflight_passed === true;
        emit({
          ok,
          mode: 'secrets_manager_machine',
          live_secret_resolved: true,
          broker_smoke_ok: ok,
          sm_preflight_passed: evidence.sm_preflight_passed,
          machine_id,
          alias: binding.alias,
          allowed_project_count: allow.allowed_project_ids.length,
          authorization_ready: false,
          helper_vault_free: true,
          env_inject_forbidden: true,
          secrets_manager_allowed: true,
          localservice_vault_forbidden: true,
        }, ok ? 0 : 1);
      } catch {
        emit({
          ok: false,
          code: 'broker_smoke_failed',
          live_secret_resolved: true,
          authorization_ready: false,
          helper_vault_free: true,
          machine_id,
        }, 1);
      } finally {
        if (broker) await broker.close().catch(() => {});
        await api.close().catch(() => {});
      }
    }
    }
  }
}
