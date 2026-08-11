#!/usr/bin/env node
/**
 * Agent-blind Secrets Manager resolve for HQ tooling.
 *
 * Writes ONLY the secret value to stdout (no JSON wrapping). Callers must never
 * log stdout. Stderr/exit codes stay value-free.
 *
 *   node scripts/resolve-sm-secret.mjs \
 *     --i-approve-secrets-manager-machine-resolve \
 *     --project mivia|private-hq \
 *     --key mivia_firecrawl_api_key
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
  fetchSecretsManagerSecretValue,
  SecretsManagerBwsAdapterError,
} from '../src/secrets-manager-bws-adapter.mjs';
import { isProjectAllowed } from '../src/secrets-manager-allow-config.mjs';

function fail(code, exit = 1) {
  process.stderr.write(`${code}\n`);
  process.exit(exit);
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

if (!process.argv.includes(SM_RESOLVE_APPROVAL_FLAG)) {
  fail('approval_flag_required');
}

const projectArg = argValue('--project');
const key = argValue('--key');
if (typeof projectArg !== 'string' || typeof key !== 'string') {
  fail('usage');
}

try {
  const projectId = resolveProjectId(projectArg);
  const scope = buildSecretsManagerLiveScope();
  const bundle = await collectSecretsManagerMachineBundle(scope);
  if (!isProjectAllowed(bundle.allow, projectId)) {
    fail('project_not_allowed');
  }
  const value = await fetchSecretsManagerSecretValue({
    accessToken: bundle.accessToken,
    projectId,
    secretKey: key,
    allowConfig: bundle.allow,
  });
  process.stdout.write(value);
  process.exit(0);
} catch (error) {
  const code =
    error instanceof SecretsManagerTokenCollectorError ||
    error instanceof SecretsManagerBwsAdapterError
      ? error.code
      : 'resolve_failed';
  fail(code);
}
