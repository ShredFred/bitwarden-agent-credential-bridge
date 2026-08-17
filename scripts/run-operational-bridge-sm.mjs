#!/usr/bin/env node
/**
 * Foreground operational SM same-user bridge (Phase 14).
 *
 * Requires --i-approve-secrets-manager-machine-resolve. Resolves secrets from
 * Bitwarden Secrets Manager via bws into broker memory only. Never prints
 * tokens/secrets. authorization_ready stays evidence-driven (default false).
 * LocalService is not required.
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
  OperationalBridgeError,
} from '../src/operational-bridge.mjs';
import { absentOperationalAuthorizationForPlatform } from '../src/platform-operational-authorization.mjs';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import {
  buildSecretsManagerResolverGate,
  resolveSecretsManagerSecret,
} from '../src/secrets-manager-resolver.mjs';
import {
  fetchSecretsManagerSecretValue,
  SecretsManagerBwsAdapterError,
  withBwsDiagnostic,
} from '../src/secrets-manager-bws-adapter.mjs';
import { checkBwsAvailable } from '../src/secrets-manager-local-lifecycle.mjs';

const APPROVAL_FLAG = '--i-approve-secrets-manager-machine-resolve';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const bindingsPath = process.argv.find((a) => a.startsWith('samples/')) ??
  'samples/operational/bindings-sm.json';

function emit(payload) {
  process.stdout.write(`${JSON.stringify(withBwsDiagnostic(payload))}\n`);
}

let bridge;
let stopping = false;

async function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  if (bridge) {
    await bridge.close().catch(() => {});
  }
  process.exitCode = code;
  process.exit(code);
}

process.once('SIGINT', () => {
  void shutdown(0);
});
process.once('SIGTERM', () => {
  void shutdown(0);
});

if (!process.argv.includes(APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: APPROVAL_FLAG,
    authorization_ready: false,
    helper_vault_free: true,
    secrets_manager_mode: true,
  });
  await shutdown(1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin') {
  emit({
    ok: false,
    code: 'unsupported_platform',
    authorization_ready: false,
    helper_vault_free: true,
  });
  await shutdown(1);
} else {
  const bws = await checkBwsAvailable();
  if (!bws.bws_available) {
    emit({
      ok: false,
      code: 'bws_missing',
      harness_ready: false,
      secrets_manager_mode: true,
      authorization_ready: false,
      helper_vault_free: true,
    });
    await shutdown(1);
  } else {
    try {
    const scope = buildSecretsManagerLiveScope();
    const bundle = await collectSecretsManagerMachineBundle(scope);
    const resolverGate = buildSecretsManagerResolverGate(scope, bundle.allow);
    const bindings = await loadOperationalBindingsFile(root, bindingsPath);
    if (bindings.profile !== 'operational_sm_same_user') {
      throw new OperationalBridgeError('invalid_bindings');
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
                accessToken: bundle.accessToken,
                projectId: request.project_id,
                secretKey: request.secret_key,
                allowConfig: bundle.allow,
              });
              const password = await fetchSecretsManagerSecretValue({
                accessToken: bundle.accessToken,
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
              accessToken: bundle.accessToken,
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
    const allOk = Object.values(smoke).every(Boolean);
    emit({
      ok: allOk,
      profile: bridge.profile,
      services: bridge.services.map((s) => ({
        alias: s.alias,
        credential_class: s.credential_class,
        runtime: s.runtime,
        baseUrl: s.baseUrl,
        ...(s.replayUrl ? { replayUrl: s.replayUrl } : {}),
      })),
      discoveryUrl: bridge.discoveryUrl,
      smoke,
      harness_ready: bridge.harness_ready === true && allOk,
      secrets_manager_mode: true,
      machine_id: bundle.machine_id,
      disposable_dev_ready: false,
      authorization_ready: bridge.authorization_ready,
      production_authorization_terminal_code: bridge.production_authorization_terminal_code,
      operational_authorization_wired: bridge.operational_authorization_wired === true,
      helper_vault_free: true,
      env_inject_forbidden: true,
      localservice_vault_forbidden: true,
      note: 'Same-user SM operational profile; press Ctrl+C to stop. LocalService not required.',
    });
    if (!allOk) {
      await shutdown(1);
    }
  } catch (error) {
    const code = error instanceof SecretsManagerTokenCollectorError ||
      error instanceof OperationalBridgeError ||
      error instanceof SecretsManagerBwsAdapterError
      ? error.code
      : 'startup_failed';
    emit({
      ok: false,
      code,
      harness_ready: false,
      secrets_manager_mode: true,
      authorization_ready:
        absentOperationalAuthorizationForPlatform(process.platform).authorization_ready,
      helper_vault_free: true,
    });
    await shutdown(1);
  }
  }
}
