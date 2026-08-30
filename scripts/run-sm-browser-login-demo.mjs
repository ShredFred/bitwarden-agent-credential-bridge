#!/usr/bin/env node
/**
 * Live demo: SM DPAPI → browser form login via Bridge.
 *
 * Creates short-lived fake username/password in private-hq, logs in through
 * the session broker, proves agent-readable surfaces do not contain the
 * password, then exits. Never prints credentials or tokens.
 *
 * Requires: --i-approve-secrets-manager-machine-resolve
 */
import crypto from 'node:crypto';
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
  OperationalBridgeError,
} from '../src/operational-bridge.mjs';
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
  upsertSecretsManagerSecret,
  SecretsManagerBwsAdapterError,
  withBwsDiagnostic,
} from '../src/secrets-manager-bws-adapter.mjs';

const APPROVAL_FLAG = '--i-approve-secrets-manager-machine-resolve';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const bindingsPath = 'samples/operational/bindings-sm-browser-demo.json';
const PROJECT = '1d9a72dc-75aa-4bf3-a528-b49800ebbf68';
const USER_KEY = 'privatehq_demo_login_user';
const PASS_KEY = 'privatehq_demo_login_pass';

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

function fakeUsername() {
  return `user_${crypto.randomBytes(4).toString('hex')}`;
}

function fakePassword() {
  return `SM-FAKE-LOGIN-PASS-${crypto.randomBytes(8).toString('hex')}`;
}

if (!process.argv.includes(APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: APPROVAL_FLAG,
    authorization_ready: false,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin' && process.platform !== 'linux') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
} else {
  let username = fakeUsername();
  let password = fakePassword();
  let accessToken;
  let bridge;
  try {
    const scope = buildSecretsManagerLiveScope();
    const bundle = await collectSecretsManagerMachineBundle(scope);
    accessToken = bundle.accessToken;
    await upsertSecretsManagerSecret({
      accessToken,
      projectId: PROJECT,
      secretKey: USER_KEY,
      secretValue: username,
      allowConfig: bundle.allow,
    });
    await upsertSecretsManagerSecret({
      accessToken,
      projectId: PROJECT,
      secretKey: PASS_KEY,
      secretValue: password,
      allowConfig: bundle.allow,
    });

    const secrets = [username, password, accessToken];
    const resolverGate = buildSecretsManagerResolverGate(scope, bundle.allow);
    const bindings = await loadOperationalBindingsFile(root, bindingsPath);

    bridge = await startOperationalBridge({
      repoRoot: root,
      bindings,
      resolveSecret: async (binding) => {
        const resolved = await resolveSecretsManagerSecret(
          resolverGate,
          async (request) => {
            const user = await fetchSecretsManagerSecretValue({
              accessToken,
              projectId: request.project_id,
              secretKey: request.secret_key,
              allowConfig: bundle.allow,
            });
            const pass = await fetchSecretsManagerSecretValue({
              accessToken,
              projectId: request.project_id,
              secretKey: request.secret_key_password,
              allowConfig: bundle.allow,
            });
            return { username: user, password: pass };
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

    const service = bridge.services[0];
    const smoke = await bridge.smoke();
    const loginOk = smoke[service.alias] === true;

    const statusRes = await fetch(new URL('/status', service.baseUrl)).catch(() => null);
    const statusBody = statusRes ? await statusRes.text() : '';
    const replayRes = await fetch(service.replayUrl);
    const replayBody = await replayRes.text();
    const agentSurface = {
      emit_preview: {
        ok: true,
        logged_in: loginOk,
        alias: service.alias,
        credential_class: service.credential_class,
        baseUrl: service.baseUrl,
        replayUrl: service.replayUrl,
        authorization_ready: bridge.authorization_ready,
      },
      status_http: statusRes?.status ?? null,
      status_body: statusBody,
      replay_http: replayRes.status,
      replay_body: replayBody,
      replay_headers: [...replayRes.headers.entries()],
    };
    assertNoSecret('agent_surface', agentSurface, secrets);
    assertNoSecret('status', statusBody, secrets);
    assertNoSecret('replay', replayBody, secrets);

    emit({
      ok: loginOk && replayRes.status === 200,
      demo: 'sm_browser_form_login',
      project: 'private-hq',
      alias: service.alias,
      logged_in: loginOk,
      replay_ok: replayRes.status === 200,
      password_absent_from_agent_surfaces: true,
      username_absent_from_agent_surfaces: true,
      token_absent_from_agent_surfaces: true,
      machine_id: bundle.machine_id,
      authorization_ready: false,
      helper_vault_free: true,
      env_inject_forbidden: true,
      note: 'Login succeeded via Bridge; credentials stayed in SM/broker memory only.',
    }, loginOk && replayRes.status === 200 ? 0 : 1);
  } catch (error) {
    const code = error instanceof SecretsManagerTokenCollectorError ||
      error instanceof OperationalBridgeError ||
      error instanceof SecretsManagerBwsAdapterError
      ? error.code
      : (typeof error?.message === 'string' && error.message.startsWith('secret_leak:')
        ? error.message
        : 'demo_failed');
    emit({
      ok: false,
      code,
      logged_in: false,
      password_absent_from_agent_surfaces: false,
      authorization_ready: false,
      helper_vault_free: true,
    }, 1);
  } finally {
    username = null;
    password = null;
    accessToken = null;
    if (bridge) await bridge.close().catch(() => {});
  }
}
