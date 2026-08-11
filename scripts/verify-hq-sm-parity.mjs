#!/usr/bin/env node
/**
 * Value-free parity check: every import-manifest entry must match its local
 * source (DPAPI / .env) by SHA-256 digest. Never prints secret values.
 *
 *   node scripts/verify-hq-sm-parity.mjs --i-approve-secrets-manager-machine-resolve \
 *     --env-root "F:\\Github Repos\\personal-hq"
 */
import { createHash } from 'node:crypto';
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  extractLocalSecretValue,
  loadLocalToSmImportManifest,
  LocalSecretToSmError,
} from '../src/local-secret-to-sm.mjs';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import {
  fetchSecretsManagerSecretValue,
  SecretsManagerBwsAdapterError,
} from '../src/secrets-manager-bws-adapter.mjs';
import { SM_RESOLVE_APPROVAL_FLAG } from '../src/secrets-manager-defaults.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_MANIFEST = path.join(
  root,
  'samples',
  'operational',
  'local-to-sm-import-manifest.json',
);

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function argValue(name) {
  const idx = process.argv.indexOf(name);
  if (idx < 0 || idx + 1 >= process.argv.length) return null;
  return process.argv[idx + 1];
}

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

if (!process.argv.includes(SM_RESOLVE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_RESOLVE_APPROVAL_FLAG,
  }, 1);
} else {
  const envRoot = argValue('--env-root');
  const projectFilter = argValue('--project'); // optional: mivia | private-hq
  try {
    const manifest = await loadLocalToSmImportManifest(
      argValue('--manifest') ?? DEFAULT_MANIFEST,
    );
    const scope = buildSecretsManagerLiveScope();
    const bundle = await collectSecretsManagerMachineBundle(scope);
    const results = [];
    let matched = 0;
    let failed = 0;

    for (const entry of manifest.entries) {
      if (projectFilter && entry.project !== projectFilter) continue;
      const row = {
        id: entry.id,
        project: entry.project,
        sm_secret_key: entry.sm_secret_key,
        source_kind: entry.source.kind,
        digest_match: false,
        code: 'ok',
      };
      try {
        const local = await extractLocalSecretValue(entry, { envRoot });
        const remote = await fetchSecretsManagerSecretValue({
          accessToken: bundle.accessToken,
          projectId: entry.project_id,
          secretKey: entry.sm_secret_key,
          allowConfig: bundle.allow,
        });
        row.digest_match = sha256Hex(local) === sha256Hex(remote);
        if (row.digest_match) matched += 1;
        else {
          row.code = 'digest_mismatch';
          failed += 1;
        }
      } catch (error) {
        row.code =
          error instanceof LocalSecretToSmError ||
          error instanceof SecretsManagerBwsAdapterError
            ? error.code
            : 'parity_failed';
        failed += 1;
      }
      results.push(Object.freeze(row));
    }

    emit({
      ok: failed === 0,
      mode: 'hq_sm_parity',
      checked: results.length,
      matched,
      failed,
      env_root: envRoot ?? null,
      project_filter: projectFilter ?? null,
      authorization_ready: false,
      helper_vault_free: true,
      agent_secret_visible: false,
      results,
    }, failed === 0 ? 0 : 1);
  } catch (error) {
    const code =
      error instanceof LocalSecretToSmError ||
      error instanceof SecretsManagerTokenCollectorError
        ? error.code
        : 'parity_failed';
    emit({ ok: false, code, agent_secret_visible: false }, 1);
  }
}
