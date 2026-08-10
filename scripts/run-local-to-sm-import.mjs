#!/usr/bin/env node
/**
 * Import local DPAPI / ConvertFrom-SecureString / .env secrets into SM.
 *
 * Default: dry-run (extractability only, no SM write, no local delete).
 *
 * Apply:
 *   npm run import:local-to-sm -- --apply --i-approve-secrets-manager-machine-write
 *
 * Never prints secret values. Local purge is disabled in this slice.
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadLocalToSmImportManifest,
  runLocalToSmImport,
  LocalSecretToSmError,
} from '../src/local-secret-to-sm.mjs';
import { buildSecretsManagerLiveScope } from '../src/secrets-manager-live-gate.mjs';
import {
  collectSecretsManagerMachineBundle,
  SecretsManagerTokenCollectorError,
} from '../src/secrets-manager-token-collector.mjs';
import { SM_WRITE_APPROVAL_FLAG } from '../src/secrets-manager-defaults.mjs';

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

const apply = process.argv.includes('--apply');
const purgeRequested = process.argv.includes('--purge-local');
const manifestPath = argValue('--manifest') ?? DEFAULT_MANIFEST;

if (purgeRequested) {
  emit({
    ok: false,
    code: 'purge_disabled',
    note: 'Local delete is disabled until digest-verified apply is proven; re-run without --purge-local.',
    authorization_ready: false,
    helper_vault_free: true,
    agent_secret_visible: false,
  }, 1);
} else if (apply && !process.argv.includes(SM_WRITE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_WRITE_APPROVAL_FLAG,
    authorization_ready: false,
    helper_vault_free: true,
  }, 1);
} else if (process.platform !== 'win32' && apply) {
  // Dry-run of env_file can work elsewhere; DPAPI apply is Windows-first.
  emit({
    ok: false,
    code: 'unsupported_platform',
    authorization_ready: false,
  }, 1);
} else {
  try {
    const manifest = await loadLocalToSmImportManifest(manifestPath);
    if (!apply) {
      const report = await runLocalToSmImport({
        manifest,
        mode: 'dry_run',
      });
      emit({
        ...report,
        manifest: path.relative(root, manifestPath).replaceAll('\\', '/'),
        note: 'Dry-run only: local sources checked; SM not written; local files not deleted.',
      }, report.ok ? 0 : 1);
    } else {
      const scope = buildSecretsManagerLiveScope();
      const bundle = await collectSecretsManagerMachineBundle(scope);
      const report = await runLocalToSmImport({
        manifest,
        mode: 'apply',
        accessToken: bundle.accessToken,
        allowConfig: bundle.allow,
      });
      emit({
        ...report,
        manifest: path.relative(root, manifestPath).replaceAll('\\', '/'),
        machine_id: bundle.allow?.machine_id ?? null,
        note: 'Apply complete: values never printed; local DPAPI files kept (purge disabled).',
      }, report.ok ? 0 : 1);
    }
  } catch (error) {
    const code =
      error instanceof LocalSecretToSmError ||
      error instanceof SecretsManagerTokenCollectorError
        ? error.code
        : 'import_failed';
    emit({
      ok: false,
      code,
      authorization_ready: false,
      helper_vault_free: true,
      agent_secret_visible: false,
    }, 1);
  }
}
