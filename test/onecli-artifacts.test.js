import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { auditOneCliConfig } from '../src/onecli-audit.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function readJson(...parts) {
  return JSON.parse(await readFile(path.join(root, ...parts), 'utf8'));
}

describe('OneCLI Phase 2 artifacts', () => {
  it('pins the reviewed upstream and Agent Access revisions', async () => {
    const lock = await readJson('upstream', 'onecli.lock.json');
    assert.deepEqual(lock, {
      version: 1,
      repository: 'https://github.com/onecli/onecli.git',
      release: '1.45.0',
      commit: '84ccaf74ce6350f8925675457b48272c29f32c1a',
      bitwardenAgentAccessCommit:
        '9cd303f65dc501c19d1d513fb4cf88fe5f44936a',
      auditedDefaultPorts: {
        dashboard: 10254,
        gateway: 10255,
        postgres: 5432,
      },
      credentialCacheTtlSeconds: 60,
    });
  });

  it('keeps deployment-specific sample fields as rejected placeholders', async () => {
    const sample = await readJson(
      'samples',
      'onecli',
      'secure-local.example.json',
    );
    const placeholderValues = [
      sample.images.onecli,
      sample.images.postgres,
      sample.postgres.username,
      sample.postgres.password,
      sample.encryptionKey,
    ];

    assert.ok(
      placeholderValues.every(
        (value) =>
          typeof value === 'string' &&
          value.startsWith('<') &&
          value.endsWith('>'),
      ),
    );
    assert.match(sample.bitwardenRelayUrl, /^https:\/\/<[^>]+>$/);
    assert.deepEqual(sample.binds, {
      dashboard: { host: '127.0.0.1', port: 10254 },
      gateway: { host: '127.0.0.1', port: 10255 },
      postgres: { host: '127.0.0.1', port: 5432 },
    });
    assert.equal(sample.credentialCacheTtlSeconds, 60);
    assert.equal(sample.separateRuntimeBoundaryAcknowledged, true);

    const audit = auditOneCliConfig(sample);
    assert.equal(audit.valid, false);
    assert.ok(
      audit.issues.some((issue) => issue.field === 'images.onecli'),
    );
    assert.ok(
      audit.issues.some((issue) => issue.field === 'encryptionKey'),
    );

    const serializedAudit = JSON.stringify(audit);
    for (const placeholder of placeholderValues) {
      assert.ok(!serializedAudit.includes(placeholder));
    }
    assert.ok(!serializedAudit.includes(sample.bitwardenRelayUrl));
  });

  it('keeps local agent-broker state out of the worktree', async () => {
    const gitignore = await readFile(path.join(root, '.gitignore'), 'utf8');
    assert.match(gitignore, /^\.agent-broker\/$/m);
  });
});
