#!/usr/bin/env node
/**
 * Agent-blind Secrets Manager write (create/update).
 *
 * Reads secret value from stdin (one line). Never prints the value or token.
 * Returns only { ok, action }. Requires machine setup + write approval flag.
 *
 * Usage:
 *   echo value| npm run live:sm-write -- --i-approve-secrets-manager-machine-write \
 *     --project mivia --key my_secret_key
 */
import process from 'node:process';
import {
  SM_DEFAULT_PROJECTS,
  SM_WRITE_APPROVAL_FLAG,
} from '../src/secrets-manager-defaults.mjs';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import {
  upsertSecretsManagerSecret,
  SecretsManagerBwsAdapterError,
  withBwsDiagnostic,
} from '../src/secrets-manager-bws-adapter.mjs';
import { isProjectAllowed } from '../src/secrets-manager-allow-config.mjs';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(withBwsDiagnostic(payload))}\n`);
  process.exitCode = code;
}

function argValue(name) {
  const idx = process.argv.indexOf(name);
  if (idx < 0 || idx + 1 >= process.argv.length) return null;
  return process.argv[idx + 1];
}

function readStdinLine() {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => {
      reject(new Error('stdin_timeout'));
    }, 30000);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => {
      clearTimeout(timer);
      resolve(data.replace(/\r?\n$/, ''));
    });
    process.stdin.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function resolveProjectId(raw) {
  if (raw === 'mivia') return SM_DEFAULT_PROJECTS.mivia;
  if (raw === 'private-hq' || raw === 'private_hq' || raw === 'privatehq') {
    return SM_DEFAULT_PROJECTS.private_hq;
  }
  return raw;
}

if (!process.argv.includes(SM_WRITE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_WRITE_APPROVAL_FLAG,
    authorization_ready: false,
    helper_vault_free: true,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin' && process.platform !== 'linux') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
} else {
  const projectArg = argValue('--project');
  const key = argValue('--key');
  if (typeof projectArg !== 'string' || typeof key !== 'string') {
    emit({
      ok: false,
      code: 'usage',
      hint: 'Provide --project mivia|private-hq|<uuid> and --key <secret_key>; value on stdin',
      authorization_ready: false,
    }, 1);
  } else {
    try {
      const projectId = resolveProjectId(projectArg);
      const secretValue = await readStdinLine();
      const scope = buildSecretsManagerLiveScope();
      const bundle = await collectSecretsManagerMachineBundle(scope);
      if (!isProjectAllowed(bundle.allow, projectId)) {
        emit({
          ok: false,
          code: 'project_not_allowed',
          authorization_ready: false,
          helper_vault_free: true,
        }, 1);
      } else {
        const result = await upsertSecretsManagerSecret({
          accessToken: bundle.accessToken,
          projectId,
          secretKey: key,
          secretValue,
          allowConfig: bundle.allow,
        });
        emit({
          ok: true,
          action: result.action,
          project: projectArg,
          key,
          live_secret_written: true,
          authorization_ready: false,
          helper_vault_free: true,
          env_inject_forbidden: true,
          agent_secret_visible: false,
        });
      }
    } catch (error) {
      const code =
        error instanceof SecretsManagerTokenCollectorError ||
        error instanceof SecretsManagerBwsAdapterError
          ? error.code
          : 'write_failed';
      emit({
        ok: false,
        code,
        authorization_ready: false,
        helper_vault_free: true,
        agent_secret_visible: false,
      }, 1);
    }
  }
}
