#!/usr/bin/env node
/**
 * Value-free SM secret presence check for agents.
 *
 * Reports whether a key exists in an allowlisted project. Never returns values.
 *
 * Usage:
 *   node scripts/run-sm-secret-exists.mjs --i-approve-secrets-manager-machine-resolve \
 *     --project mivia --key mivia_klicktipp_api_user
 *
 *   node scripts/run-sm-secret-exists.mjs --i-approve-secrets-manager-machine-resolve \
 *     --project mivia --prefix mivia_klicktipp_
 */
import process from 'node:process';
import {
  SM_DEFAULT_PROJECTS,
  SM_RESOLVE_APPROVAL_FLAG,
} from '../src/secrets-manager-defaults.mjs';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import {
  listSecretsManagerSecretKeys,
  SecretsManagerBwsAdapterError,
} from '../src/secrets-manager-bws-adapter.mjs';
import { isProjectAllowed } from '../src/secrets-manager-allow-config.mjs';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function argValue(name) {
  const idx = process.argv.indexOf(name);
  if (idx < 0 || idx + 1 >= process.argv.length) return null;
  return process.argv[idx + 1];
}

function resolveProjectId(raw) {
  if (raw === 'mivia') return SM_DEFAULT_PROJECTS.mivia;
  if (raw === 'private-hq' || raw === 'private_hq' || raw === 'privatehq') {
    return SM_DEFAULT_PROJECTS.private_hq;
  }
  return raw;
}

const KEY_RE = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;
const PREFIX_RE = /^[a-zA-Z][a-zA-Z0-9_.-]{0,120}_$/;

if (!process.argv.includes(SM_RESOLVE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_RESOLVE_APPROVAL_FLAG,
    authorization_ready: false,
    helper_vault_free: true,
    agent_secret_visible: false,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
} else {
  const projectArg = argValue('--project');
  const key = argValue('--key');
  const prefix = argValue('--prefix');
  if (typeof projectArg !== 'string') {
    emit({
      ok: false,
      code: 'usage',
      hint: 'Provide --project and either --key or --prefix',
      authorization_ready: false,
      helper_vault_free: true,
      agent_secret_visible: false,
    }, 1);
  } else if ((key && prefix) || (!key && !prefix)) {
    emit({
      ok: false,
      code: 'usage',
      hint: 'Provide exactly one of --key or --prefix',
      authorization_ready: false,
      helper_vault_free: true,
      agent_secret_visible: false,
    }, 1);
  } else if (key && !KEY_RE.test(key)) {
    emit({ ok: false, code: 'invalid_key', authorization_ready: false }, 1);
  } else if (prefix && !PREFIX_RE.test(prefix)) {
    emit({ ok: false, code: 'invalid_prefix', authorization_ready: false }, 1);
  } else {
    try {
      const projectId = resolveProjectId(projectArg);
      const scope = buildSecretsManagerLiveScope();
      const bundle = await collectSecretsManagerMachineBundle(scope);
      if (!isProjectAllowed(bundle.allow, projectId)) {
        emit({
          ok: false,
          code: 'project_not_allowed',
          authorization_ready: false,
          helper_vault_free: true,
          agent_secret_visible: false,
        }, 1);
      } else {
        const listed = await listSecretsManagerSecretKeys({
          accessToken: bundle.accessToken,
          projectId,
          allowConfig: bundle.allow,
        });
        const keys = listed.map((row) => row.key).sort();
        if (key) {
          emit({
            ok: true,
            project: projectArg,
            key,
            exists: keys.includes(key),
            authorization_ready: false,
            helper_vault_free: true,
            agent_secret_visible: false,
            env_inject_forbidden: true,
          });
        } else {
          const matches = keys.filter((k) => k.startsWith(prefix));
          emit({
            ok: true,
            project: projectArg,
            prefix,
            exists: matches.length > 0,
            matching_keys: matches,
            matching_count: matches.length,
            authorization_ready: false,
            helper_vault_free: true,
            agent_secret_visible: false,
            env_inject_forbidden: true,
          });
        }
      }
    } catch (error) {
      const code =
        error instanceof SecretsManagerTokenCollectorError ||
        error instanceof SecretsManagerBwsAdapterError
          ? error.code
          : 'exists_check_failed';
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
