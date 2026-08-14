#!/usr/bin/env node
/**
 * Foreground Bridge-owned browser for one Secrets Manager browser_form_login
 * alias. Agent is the eyes (indices); Bridge injects secrets.
 *
 * Requires:
 *   --i-approve-secrets-manager-machine-resolve
 *   --i-approve-bridge-owned-browser
 *   --alias <binding>
 * Optional: --driver fetch|playwright (default fetch)
 *
 * Emits one value-free JSON handle. Never prints tokens or passwords.
 * authorization_ready stays evidence-driven (default false).
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BRIDGE_OWNED_BROWSER_CLI_BIND,
  parseBridgeOwnedBrowserCli,
} from '../src/bridge-owned-browser-cli.mjs';
import { startBridgeOwnedBrowserForBinding } from '../src/bridge-owned-browser-session.mjs';
import {
  BridgeOwnedBrowserError,
} from '../src/bridge-owned-browser.mjs';
import {
  loadOperationalBindingsFile,
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

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const bindingsPath = process.argv.find((a) => a.startsWith('samples/')) ??
  'samples/operational/bindings-sm.json';

function emit(payload) {
  process.stdout.write(`${JSON.stringify(withBwsDiagnostic(payload))}\n`);
}

let session;
let stopping = false;

async function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  if (session) {
    await session.close().catch(() => {});
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

const parsed = parseBridgeOwnedBrowserCli(process.argv);
if (!parsed.ok) {
  emit({
    ok: false,
    code: parsed.code,
    ...(parsed.required_flags ? { required_flags: parsed.required_flags } : {}),
    authorization_ready: false,
    helper_vault_free: true,
    cookie_export_forbidden: true,
    agent_cdp_absent: true,
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

      session = await startBridgeOwnedBrowserForBinding({
        repoRoot: root,
        bindings,
        alias: parsed.alias,
        driver: parsed.driver,
        bind: BRIDGE_OWNED_BROWSER_CLI_BIND,
        resolveSecret: async (binding) => {
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
        },
      });

      emit({
        ok: true,
        alias: session.alias,
        driver: session.driver,
        runtime: session.runtime,
        baseUrl: session.session.baseUrl,
        contract_url: `${session.session.baseUrl}/contract`,
        origin_bound: true,
        agent_cdp_absent: true,
        cookie_export_forbidden: true,
        secrets_manager_mode: true,
        authorization_ready: session.session.authorization_ready,
        helper_vault_free: true,
        env_inject_forbidden: true,
        note: 'Bridge-owned browser; agent uses /contract /snapshot /select_targets /inject_login. Ctrl+C to stop.',
      });
    } catch (error) {
      const code = error instanceof SecretsManagerTokenCollectorError ||
        error instanceof OperationalBridgeError ||
        error instanceof SecretsManagerBwsAdapterError ||
        error instanceof BridgeOwnedBrowserError
        ? error.code
        : 'startup_failed';
      emit({
        ok: false,
        code,
        authorization_ready:
          absentOperationalAuthorizationForPlatform(process.platform).authorization_ready,
        helper_vault_free: true,
        cookie_export_forbidden: true,
        agent_cdp_absent: true,
      });
      await shutdown(1);
    }
  }
}
