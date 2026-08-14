#!/usr/bin/env node
/**
 * Idempotent operational SM seed for MiViA + private-hq.
 *
 * Reads the canonical bindings table, upserts every required SM key with
 * generated fake values (never printed), optionally prunes unknown keys in
 * those projects, then optionally smokes the operational bridge.
 *
 * Requires:
 *   --i-approve-secrets-manager-machine-write
 * Optional:
 *   --prune   delete non-canonical keys in allowlisted projects
 *   --smoke   start bridge smoke after seed (also needs resolve approval)
 *   --i-approve-secrets-manager-machine-resolve  (with --smoke)
 */
import crypto from 'node:crypto';
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BASIC_USERNAME_MIN_LENGTH,
} from '../src/basic-credentials.js';
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
  deleteSecretsManagerSecret,
  fetchSecretsManagerSecretValue,
  listSecretsManagerSecretKeys,
  upsertSecretsManagerSecret,
  SecretsManagerBwsAdapterError,
  withBwsDiagnostic,
} from '../src/secrets-manager-bws-adapter.mjs';
import {
  SM_RESOLVE_APPROVAL_FLAG,
  SM_WRITE_APPROVAL_FLAG,
} from '../src/secrets-manager-defaults.mjs';
import { isProjectAllowed } from '../src/secrets-manager-allow-config.mjs';
import { loadLocalToSmImportManifest } from '../src/local-secret-to-sm.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const BINDINGS_PATH = 'samples/operational/bindings-sm.json';
const IMPORT_MANIFEST_PATH = path.join(
  root,
  'samples',
  'operational',
  'local-to-sm-import-manifest.json',
);

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(withBwsDiagnostic(payload))}\n`);
  process.exitCode = code;
}

function fakeUsername(alias) {
  const base = `user_${alias}`.replace(/[^a-z0-9_]/gi, '_').toLowerCase();
  if (base.length >= BASIC_USERNAME_MIN_LENGTH) return base.slice(0, 64);
  return `${base}${crypto.randomBytes(4).toString('hex')}`.slice(0, 64);
}

function fakeSecret(kind) {
  return `SM-OP-${kind}-${crypto.randomBytes(16).toString('hex')}`;
}

/**
 * @param {import('../src/operational-bridge.mjs').OperationalBinding[]} bindings
 */
function requiredKeysByProject(bindings) {
  /** @type {Map<string, Set<string>>} */
  const map = new Map();
  for (const binding of bindings) {
    const projectId = binding.sm_project_id;
    if (!map.has(projectId)) map.set(projectId, new Set());
    const set = map.get(projectId);
    set.add(binding.sm_secret_key);
    if (binding.sm_secret_key_password) {
      set.add(binding.sm_secret_key_password);
    }
  }
  return map;
}

if (!process.argv.includes(SM_WRITE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_WRITE_APPROVAL_FLAG,
    authorization_ready: false,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
} else {
  const doPrune = process.argv.includes('--prune');
  const doSmoke = process.argv.includes('--smoke');
  let bridge;
  try {
    const scope = buildSecretsManagerLiveScope();
    const bundle = await collectSecretsManagerMachineBundle(scope);
    const table = await loadOperationalBindingsFile(root, BINDINGS_PATH);
    const byProject = requiredKeysByProject(table.bindings);
    // Preserve real local→SM inventory keys when pruning class-slot seeds.
    try {
      const importManifest = await loadLocalToSmImportManifest(IMPORT_MANIFEST_PATH);
      for (const entry of importManifest.entries) {
        if (!byProject.has(entry.project_id)) {
          byProject.set(entry.project_id, new Set());
        }
        byProject.get(entry.project_id).add(entry.sm_secret_key);
      }
    } catch {
      // Manifest optional for older checkouts; prune then only keeps bindings.
    }

    /** @type {Record<string, string>} */
    const values = Object.create(null);
    let upserted = 0;
    for (const binding of table.bindings) {
      if (!isProjectAllowed(bundle.allow, binding.sm_project_id)) {
        throw new Error('project_not_allowed');
      }
      const needsPair = Boolean(binding.sm_secret_key_password);
      if (needsPair) {
        if (!values[binding.sm_secret_key]) {
          values[binding.sm_secret_key] = fakeUsername(binding.alias);
        }
        if (!values[binding.sm_secret_key_password]) {
          values[binding.sm_secret_key_password] = fakeSecret('PASS');
        }
      } else if (!values[binding.sm_secret_key]) {
        values[binding.sm_secret_key] = fakeSecret('SENTINEL');
      }
    }

    for (const [projectId, keys] of byProject.entries()) {
      for (const key of keys) {
        const secretValue = values[key];
        // Manifest-only inventory keys stay in byProject for prune keep-sets;
        // they are never seeded with harness fakes.
        if (typeof secretValue !== 'string') continue;
        await upsertSecretsManagerSecret({
          accessToken: bundle.accessToken,
          projectId,
          secretKey: key,
          secretValue,
          allowConfig: bundle.allow,
          note: 'bridge-operational-seed',
        });
        upserted += 1;
      }
    }

    let pruned = 0;
    if (doPrune) {
      for (const [projectId, keep] of byProject.entries()) {
        const listed = await listSecretsManagerSecretKeys({
          accessToken: bundle.accessToken,
          projectId,
          allowConfig: bundle.allow,
        });
        for (const entry of listed) {
          if (keep.has(entry.key)) continue;
          await deleteSecretsManagerSecret({
            accessToken: bundle.accessToken,
            secretId: entry.id,
            allowConfig: bundle.allow,
          });
          pruned += 1;
        }
      }
    }

    let smoke = null;
    if (doSmoke) {
      if (!process.argv.includes(SM_RESOLVE_APPROVAL_FLAG)) {
        emit({
          ok: false,
          code: 'resolve_approval_required_for_smoke',
          required_flag: SM_RESOLVE_APPROVAL_FLAG,
          seeded: true,
          upserted,
          pruned,
          authorization_ready: false,
        }, 1);
      } else {
        const resolverGate = buildSecretsManagerResolverGate(scope, bundle.allow);
        bridge = await startOperationalBridge({
          repoRoot: root,
          bindings: table,
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
        smoke = await bridge.smoke();
      }
    }

    const smokeOk = smoke
      ? Object.values(smoke).every(Boolean) &&
        Object.keys(smoke).length === table.bindings.length
      : null;

    emit({
      ok: smokeOk === null ? true : smokeOk,
      mode: 'sm_operational_seed',
      bindings: BINDINGS_PATH,
      machine_id: bundle.machine_id,
      project_count: byProject.size,
      binding_count: table.bindings.length,
      upserted,
      pruned,
      prune: doPrune,
      smoke,
      smoke_ok: smokeOk,
      authorization_ready: false,
      helper_vault_free: true,
      env_inject_forbidden: true,
      note: 'Canonical MiViA+private-hq secrets seeded; values never printed.',
    }, smokeOk === false ? 1 : 0);
  } catch (error) {
    const code = error instanceof SecretsManagerTokenCollectorError ||
      error instanceof OperationalBridgeError ||
      error instanceof SecretsManagerBwsAdapterError
      ? error.code
      : 'seed_failed';
    emit({
      ok: false,
      code,
      authorization_ready: false,
      helper_vault_free: true,
    }, 1);
  } finally {
    if (bridge) await bridge.close().catch(() => {});
  }
}
