import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  AUDITED_DEFAULT_PORTS,
  CREDENTIAL_CACHE_TTL_SECONDS,
  OneCliConfigValidationError,
  auditOneCliConfig,
  validateOneCliConfig,
} from '../src/onecli-audit.mjs';

function validConfig(overrides = {}) {
  return {
    version: 1,
    binds: {
      dashboard: { host: '127.0.0.1', port: 10_254 },
      gateway: { host: 'localhost', port: 10_255 },
      postgres: { host: '::1', port: 5432 },
    },
    images: {
      onecli: 'ghcr.io/onecli/onecli:1.45.0',
      postgres: 'postgres:17.5',
    },
    postgres: {
      username: 'onecli_local_test_user',
      password: 'generated-fake-postgres-password',
    },
    encryptionKey: 'generated-fake-encryption-key-for-tests',
    bitwardenRelayUrl: 'https://relay.example.invalid',
    credentialCacheTtlSeconds: 60,
    separateRuntimeBoundaryAcknowledged: true,
    ...overrides,
  };
}

describe('OneCLI proposed-config validation', () => {
  it('accepts a fully constrained local proposal', () => {
    const input = validConfig();
    const config = validateOneCliConfig(input);
    assert.equal(config.binds.postgres.host, '::1');
    assert.equal(config.images.onecli, 'ghcr.io/onecli/onecli:1.45.0');
    assert.equal(config.credentialCacheTtlSeconds, CREDENTIAL_CACHE_TTL_SECONDS);
    assert.notEqual(config, input);
  });

  it('rejects non-loopback dashboard, gateway, and postgres binds', () => {
    for (const name of ['dashboard', 'gateway', 'postgres']) {
      const config = validConfig();
      config.binds[name] = {
        host: '0.0.0.0',
        port: AUDITED_DEFAULT_PORTS[name],
      };
      assert.throws(
        () => validateOneCliConfig(config),
        (error) =>
          error instanceof OneCliConfigValidationError &&
          error.issues.some(
            (issue) =>
              issue.field === `binds.${name}.host` &&
              issue.code === 'non_loopback_bind',
          ),
      );
    }
  });

  it('rejects untagged and latest-tagged images', () => {
    for (const image of [
      'ghcr.io/onecli/onecli',
      'ghcr.io/onecli/onecli:latest',
      'postgres:LATEST',
    ]) {
      const config = validConfig({
        images: { ...validConfig().images, onecli: image },
      });
      assert.throws(() => validateOneCliConfig(config), /pinned tag or digest/);
    }
  });

  it('accepts a digest-pinned image', () => {
    const config = validConfig({
      images: {
        ...validConfig().images,
        onecli: `ghcr.io/onecli/onecli@sha256:${'a'.repeat(64)}`,
      },
    });
    assert.doesNotThrow(() => validateOneCliConfig(config));
  });

  it('rejects malformed image references and digests', () => {
    for (const image of [
      'onecli:',
      'onecli:1.45.0 with-space',
      'onecli@sha256:abc',
      'onecli@md5:0123456789abcdef',
    ]) {
      assert.throws(
        () =>
          validateOneCliConfig(
            validConfig({
              images: { ...validConfig().images, onecli: image },
            }),
          ),
        /pinned tag or digest/,
      );
    }
  });

  it('rejects default or placeholder postgres credentials', () => {
    for (const postgres of [
      { username: 'postgres', password: 'generated-fake-password' },
      { username: 'local_user', password: 'postgres' },
      { username: '<replace-me>', password: 'generated-fake-password' },
      { username: 'local_user', password: '${POSTGRES_PASSWORD}' },
    ]) {
      assert.throws(
        () => validateOneCliConfig(validConfig({ postgres })),
        /postgres credentials/,
      );
    }
  });

  it('rejects missing and placeholder encryption keys', () => {
    for (const encryptionKey of [
      '',
      'CHANGE_ME',
      '<generated-encryption-key>',
      '${ONECLI_ENCRYPTION_KEY}',
      '{{ encryption_key }}',
    ]) {
      assert.throws(
        () => validateOneCliConfig(validConfig({ encryptionKey })),
        /encryptionKey/,
      );
    }
  });

  it('requires an https or wss Bitwarden relay URL', () => {
    for (const bitwardenRelayUrl of [
      'http://relay.example.invalid',
      'ws://relay.example.invalid',
      'file:///tmp/relay',
      'not-a-url',
    ]) {
      assert.throws(
        () => validateOneCliConfig(validConfig({ bitwardenRelayUrl })),
        /bitwardenRelayUrl/,
      );
    }

    assert.doesNotThrow(() =>
      validateOneCliConfig(
        validConfig({ bitwardenRelayUrl: 'wss://relay.example.invalid' }),
      ),
    );
  });

  it('rejects relay URLs containing user information', () => {
    assert.throws(
      () =>
        validateOneCliConfig(
          validConfig({
            bitwardenRelayUrl:
              'https://generated-fake-user:generated-fake-password@relay.example.invalid',
          }),
        ),
      /without credentials/,
    );
  });

  it('requires valid non-zero bind ports', () => {
    for (const port of [0, -1, 1.5, 65_536, '10254']) {
      assert.throws(
        () =>
          validateOneCliConfig(
            validConfig({
              binds: {
                ...validConfig().binds,
                dashboard: { host: '127.0.0.1', port },
              },
            }),
          ),
        /integer from 1 through 65535/,
      );
    }
  });

  it('requires audited default ports for the pinned OneCLI baseline', () => {
    for (const name of ['dashboard', 'gateway', 'postgres']) {
      const config = validConfig();
      config.binds[name].port += 1;
      assert.throws(
        () => validateOneCliConfig(config),
        /must be the audited default/,
      );
    }
  });

  it('requires the source-fixed Bitwarden provider cache TTL', () => {
    for (const credentialCacheTtlSeconds of [
      0,
      -1,
      1.5,
      59,
      61,
      Number.POSITIVE_INFINITY,
    ]) {
      assert.throws(
        () =>
          validateOneCliConfig(
            validConfig({ credentialCacheTtlSeconds }),
          ),
        /credentialCacheTtlSeconds/,
      );
    }
  });

  it('requires explicit acknowledgement of a separate runtime boundary', () => {
    for (const separateRuntimeBoundaryAcknowledged of [false, undefined, 'yes']) {
      assert.throws(
        () =>
          validateOneCliConfig(
            validConfig({ separateRuntimeBoundaryAcknowledged }),
          ),
        /separateRuntimeBoundaryAcknowledged/,
      );
    }
  });

  it('returns structured, value-free audit issues', () => {
    const secretLikeInput = 'fake-sensitive-value-never-echo';
    const result = auditOneCliConfig(
      validConfig({
        encryptionKey: `<${secretLikeInput}>`,
        bitwardenRelayUrl: `http://${secretLikeInput}.invalid`,
      }),
    );

    assert.equal(result.valid, false);
    assert.ok(result.issues.length >= 2);
    assert.ok(result.issues.every(({ code, field, message }) =>
      [code, field, message].every((value) => typeof value === 'string'),
    ));
    assert.ok(!JSON.stringify(result).includes(secretLikeInput));
  });

  it('aggregates independent issues without including supplied values', () => {
    const sensitiveValue = 'generated-fake-never-report-this-value';
    const result = auditOneCliConfig({
      version: 2,
      binds: {},
      images: {},
      postgres: {
        username: 'postgres',
        password: sensitiveValue,
      },
      encryptionKey: `<${sensitiveValue}>`,
      bitwardenRelayUrl: `http://${sensitiveValue}.invalid`,
      credentialCacheTtlSeconds: 0,
      separateRuntimeBoundaryAcknowledged: false,
    });

    assert.equal(result.valid, false);
    assert.ok(result.issues.length >= 10);
    assert.ok(!JSON.stringify(result).includes(sensitiveValue));
    assert.throws(
      () => validateOneCliConfig(null),
      (error) =>
        error instanceof OneCliConfigValidationError &&
        error.issues[0].field === '$',
    );
  });
});
