const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);
const REQUIRED_BINDS = ['dashboard', 'gateway', 'postgres'];
const REQUIRED_IMAGES = ['onecli', 'postgres'];
export const AUDITED_DEFAULT_PORTS = Object.freeze({
  dashboard: 10_254,
  gateway: 10_255,
  postgres: 5_432,
});
export const CREDENTIAL_CACHE_TTL_SECONDS = 60;
const DEFAULT_POSTGRES_VALUES = new Set([
  'postgres',
  'password',
  'admin',
  'root',
]);

/**
 * @typedef {{ code: string, field: string, message: string }} AuditIssue
 */

/**
 * Validate a proposed local OneCLI configuration without performing I/O.
 *
 * The returned object is a normalized copy and can contain the supplied
 * credential fields. Do not serialize it to logs or command output.
 *
 * @param {unknown} raw
 * @returns {{
 *   version: 1,
 *   binds: Record<string, { host: string, port: number }>,
 *   images: Record<string, string>,
 *   postgres: { username: string, password: string },
 *   encryptionKey: string,
 *   bitwardenRelayUrl: string,
 *   credentialCacheTtlSeconds: number,
 *   separateRuntimeBoundaryAcknowledged: true
 * }}
 */
export function validateOneCliConfig(raw) {
  const result = inspectOneCliConfig(raw);
  if (result.issues.length > 0) {
    throw new OneCliConfigValidationError(result.issues);
  }
  return /** @type {NonNullable<typeof result.config>} */ (result.config);
}

/**
 * Return only value-free validation findings suitable for JSON reports.
 *
 * @param {unknown} raw
 * @returns {{ valid: boolean, issues: AuditIssue[] }}
 */
export function auditOneCliConfig(raw) {
  const { issues } = inspectOneCliConfig(raw);
  return { valid: issues.length === 0, issues };
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {{ host: string, port: number }}
 */
export function validateLoopbackBind(value, field = 'bind') {
  if (!isRecord(value)) {
    fail('invalid_bind', field, `${field} must be an object with host and port`);
  }

  const host =
    typeof value.host === 'string' ? value.host.trim().toLowerCase() : '';
  if (!LOOPBACK_HOSTS.has(host)) {
    fail(
      'non_loopback_bind',
      `${field}.host`,
      `${field}.host must be 127.0.0.1, ::1, or localhost`,
    );
  }

  if (
    !Number.isInteger(value.port) ||
    Number(value.port) < 1 ||
    Number(value.port) > 65_535
  ) {
    fail(
      'invalid_bind_port',
      `${field}.port`,
      `${field}.port must be an integer from 1 through 65535`,
    );
  }

  return { host, port: Number(value.port) };
}

/**
 * @param {unknown} value
 * @param {string} field
 * @returns {string}
 */
export function validatePinnedImage(value, field = 'image') {
  if (typeof value !== 'string' || value.trim() === '') {
    fail(
      'unpinned_image',
      field,
      `${field} must use an explicit pinned tag or digest, never latest`,
    );
  }

  const image = value.trim();
  if (/\s|[<>{}]/.test(image)) {
    fail(
      'unpinned_image',
      field,
      `${field} must use an explicit pinned tag or digest, never latest`,
    );
  }

  const digestMatch = image.match(/^([^@]+)@sha256:([a-fA-F0-9]{64})$/);
  if (digestMatch && digestMatch[1].trim() !== '') return image;

  const lastSlash = image.lastIndexOf('/');
  const lastColon = image.lastIndexOf(':');
  const tag = lastColon > lastSlash ? image.slice(lastColon + 1) : '';
  const imageName = lastColon > lastSlash ? image.slice(0, lastColon) : '';
  if (
    imageName === '' ||
    !/^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/.test(tag) ||
    tag.toLowerCase() === 'latest' ||
    image.includes('@')
  ) {
    fail(
      'unpinned_image',
      field,
      `${field} must use an explicit pinned tag or digest, never latest`,
    );
  }

  return image;
}

/**
 * @param {unknown} value
 * @returns {{ username: string, password: string }}
 */
export function validatePostgresCredentials(value) {
  if (!isRecord(value)) {
    fail(
      'invalid_postgres_credentials',
      'postgres',
      'postgres credentials must be explicit non-default values',
    );
  }

  const username =
    typeof value.username === 'string' ? value.username.trim() : '';
  const password =
    typeof value.password === 'string' ? value.password.trim() : '';
  if (
    isPlaceholder(username) ||
    isPlaceholder(password) ||
    DEFAULT_POSTGRES_VALUES.has(username.toLowerCase()) ||
    DEFAULT_POSTGRES_VALUES.has(password.toLowerCase()) ||
    username === password
  ) {
    fail(
      'default_postgres_credentials',
      'postgres',
      'postgres credentials must be explicit non-default values',
    );
  }

  return { username, password };
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function validateEncryptionKey(value) {
  const key = typeof value === 'string' ? value.trim() : '';
  if (isPlaceholder(key)) {
    fail(
      'placeholder_encryption_key',
      'encryptionKey',
      'encryptionKey must be a non-placeholder value supplied at deployment time',
    );
  }
  return key;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function validateBitwardenRelayUrl(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    fail(
      'invalid_relay_url',
      'bitwardenRelayUrl',
      'bitwardenRelayUrl must be a valid https or wss URL',
    );
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    fail(
      'invalid_relay_url',
      'bitwardenRelayUrl',
      'bitwardenRelayUrl must be a valid https or wss URL',
    );
  }

  if (
    !['https:', 'wss:'].includes(url.protocol) ||
    url.hostname === '' ||
    url.username !== '' ||
    url.password !== ''
  ) {
    fail(
      'insecure_relay_url',
      'bitwardenRelayUrl',
      'bitwardenRelayUrl must be a valid https or wss URL without credentials',
    );
  }
  return url.href;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
export function validateCredentialCacheTtl(value) {
  if (value !== CREDENTIAL_CACHE_TTL_SECONDS) {
    fail(
      'invalid_cache_ttl',
      'credentialCacheTtlSeconds',
      `credentialCacheTtlSeconds must be exactly ${CREDENTIAL_CACHE_TTL_SECONDS} for the pinned Bitwarden provider baseline`,
    );
  }
  return CREDENTIAL_CACHE_TTL_SECONDS;
}

/**
 * @param {unknown} value
 * @returns {true}
 */
export function validateSeparateRuntimeBoundaryAcknowledgement(value) {
  if (value !== true) {
    fail(
      'runtime_boundary_not_acknowledged',
      'separateRuntimeBoundaryAcknowledged',
      'separateRuntimeBoundaryAcknowledged must explicitly be true',
    );
  }
  return true;
}

/**
 * @param {unknown} raw
 */
function inspectOneCliConfig(raw) {
  /** @type {AuditIssue[]} */
  const issues = [];
  if (!isRecord(raw)) {
    return {
      config: null,
      issues: [
        {
          code: 'invalid_config',
          field: '$',
          message: 'proposed configuration must be a JSON object',
        },
      ],
    };
  }

  if (raw.version !== 1) {
    issues.push({
      code: 'unsupported_version',
      field: 'version',
      message: 'version must be 1',
    });
  }

  /** @type {Record<string, { host: string, port: number }>} */
  const binds = {};
  for (const name of REQUIRED_BINDS) {
    collect(
      issues,
      () => {
        const bind = validateLoopbackBind(
          isRecord(raw.binds) ? raw.binds[name] : null,
          `binds.${name}`,
        );
        if (bind.port !== AUDITED_DEFAULT_PORTS[name]) {
          fail(
            'unexpected_bind_port',
            `binds.${name}.port`,
            `binds.${name}.port must be the audited default ${AUDITED_DEFAULT_PORTS[name]}`,
          );
        }
        return bind;
      },
      (bind) => {
        binds[name] = bind;
      },
    );
  }

  /** @type {Record<string, string>} */
  const images = {};
  for (const name of REQUIRED_IMAGES) {
    collect(
      issues,
      () => validatePinnedImage(isRecord(raw.images) ? raw.images[name] : null, `images.${name}`),
      (image) => {
        images[name] = image;
      },
    );
  }

  let postgres = { username: '', password: '' };
  collect(issues, () => validatePostgresCredentials(raw.postgres), (value) => {
    postgres = value;
  });

  let encryptionKey = '';
  collect(issues, () => validateEncryptionKey(raw.encryptionKey), (value) => {
    encryptionKey = value;
  });

  let bitwardenRelayUrl = '';
  collect(issues, () => validateBitwardenRelayUrl(raw.bitwardenRelayUrl), (value) => {
    bitwardenRelayUrl = value;
  });

  let credentialCacheTtlSeconds = 0;
  collect(issues, () => validateCredentialCacheTtl(raw.credentialCacheTtlSeconds), (value) => {
    credentialCacheTtlSeconds = value;
  });

  let separateRuntimeBoundaryAcknowledged = false;
  collect(
    issues,
    () =>
      validateSeparateRuntimeBoundaryAcknowledgement(
        raw.separateRuntimeBoundaryAcknowledged,
      ),
    (value) => {
      separateRuntimeBoundaryAcknowledged = value;
    },
  );

  return {
    config:
      issues.length === 0
        ? {
            version: /** @type {1} */ (1),
            binds,
            images,
            postgres,
            encryptionKey,
            bitwardenRelayUrl,
            credentialCacheTtlSeconds,
            separateRuntimeBoundaryAcknowledged:
              /** @type {true} */ (separateRuntimeBoundaryAcknowledged),
          }
        : null,
    issues,
  };
}

/**
 * @template T
 * @param {AuditIssue[]} issues
 * @param {() => T} operation
 * @param {(value: T) => void} onSuccess
 */
function collect(issues, operation, onSuccess) {
  try {
    onSuccess(operation());
  } catch (error) {
    if (error instanceof OneCliConfigValidationError) {
      issues.push(...error.issues);
      return;
    }
    throw error;
  }
}

/**
 * Empty strings and common template syntaxes are placeholders.
 * @param {string} value
 */
function isPlaceholder(value) {
  return (
    value === '' ||
    /(?:change[_ -]?me|replace[_ -]?me|placeholder)/i.test(value) ||
    /<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}/.test(value)
  );
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {string} code
 * @param {string} field
 * @param {string} message
 * @returns {never}
 */
function fail(code, field, message) {
  throw new OneCliConfigValidationError([{ code, field, message }]);
}

export class OneCliConfigValidationError extends Error {
  /** @param {AuditIssue[]} issues */
  constructor(issues) {
    super(issues.map((issue) => issue.message).join('; '));
    this.name = 'OneCliConfigValidationError';
    this.issues = issues.map((issue) => ({ ...issue }));
  }
}
