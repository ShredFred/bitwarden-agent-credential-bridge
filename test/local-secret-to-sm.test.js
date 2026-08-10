import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  loadLocalToSmImportManifest,
  runLocalToSmImport,
  validateLocalToSmImportManifest,
  LocalSecretToSmError,
} from '../src/local-secret-to-sm.mjs';

const MANIFEST = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'samples',
  'operational',
  'local-to-sm-import-manifest.json',
);

test('canonical local→SM manifest validates', async () => {
  const manifest = await loadLocalToSmImportManifest(MANIFEST);
  assert.equal(manifest.version, 1);
  assert.ok(manifest.entries.length >= 40);
  const projects = new Set(manifest.entries.map((e) => e.project));
  assert.ok(projects.has('mivia'));
  assert.ok(projects.has('private-hq'));
});

test('rejects duplicate sm keys and purge', () => {
  assert.throws(
    () => validateLocalToSmImportManifest({
      version: 1,
      entries: [
        {
          id: 'a_one',
          project: 'mivia',
          sm_secret_key: 'mivia_same',
          source: {
            kind: 'clixml',
            basename: 'a.credential.xml',
            extract: 'top_password',
          },
        },
        {
          id: 'a_two',
          project: 'mivia',
          sm_secret_key: 'mivia_same',
          source: {
            kind: 'clixml',
            basename: 'b.credential.xml',
            extract: 'top_password',
          },
        },
      ],
    }),
    (error) => error instanceof LocalSecretToSmError && error.code === 'entry_sm_key_duplicate',
  );
});

test('dry-run and apply stay value-free with injected extractors', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'local-to-sm-'));
  try {
    const envPath = path.join(dir, '.env');
    await writeFile(envPath, 'DEMO_KEY=super-secret-value-never-emit\n', 'utf8');
    const manifest = validateLocalToSmImportManifest({
      version: 1,
      entries: [
        {
          id: 'demo_env_key',
          project: 'mivia',
          sm_secret_key: 'mivia_demo_env_key',
          source: {
            kind: 'env_file',
            path: envPath,
            extract: 'env_var',
            var: 'DEMO_KEY',
          },
        },
      ],
    });

    const dry = await runLocalToSmImport({ manifest, mode: 'dry_run' });
    assert.equal(dry.ok, true);
    assert.equal(dry.ready, 1);
    assert.equal(dry.written, 0);
    const dryJson = JSON.stringify(dry);
    assert.equal(dryJson.includes('super-secret-value-never-emit'), false);

    let stored;
    const apply = await runLocalToSmImport({
      manifest,
      mode: 'apply',
      accessToken: 'x'.repeat(32),
      allowConfig: {
        schema_version: 1,
        machine_id: 'test',
        allowed_project_ids: ['e186495e-8667-436f-9f78-b49800eba251'],
      },
      upsertSecret: async ({ secretValue, secretKey }) => {
        stored = { secretKey, secretValue };
        return { ok: true, action: 'created' };
      },
      fetchSecret: async () => stored.secretValue,
    });
    assert.equal(apply.ok, true);
    assert.equal(apply.written, 1);
    assert.equal(apply.verified, 1);
    assert.equal(apply.results[0].digest_match, true);
    assert.equal(apply.results[0].purge_eligible, true);
    assert.equal(apply.local_deleted_count, 0);
    const applyJson = JSON.stringify(apply);
    assert.equal(applyJson.includes('super-secret-value-never-emit'), false);
    assert.equal(stored.secretKey, 'mivia_demo_env_key');

    await assert.rejects(
      () => runLocalToSmImport({ manifest, mode: 'dry_run', purgeLocal: true }),
      (error) => error instanceof LocalSecretToSmError && error.code === 'purge_disabled',
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
