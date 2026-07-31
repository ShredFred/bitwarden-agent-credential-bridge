const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;
const OCI_SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/**
 * Validate a canonical lowercase SHA-256 checksum.
 *
 * @param {unknown} value
 * @param {string} [field]
 */
export function validateSha256Checksum(value, field = 'checksum') {
  if (typeof value !== 'string' || !SHA256_HEX_PATTERN.test(value)) {
    throw new SupplyChainValidationError(
      field,
      `${field} must be a canonical lowercase SHA-256 checksum`,
    );
  }
  return value;
}

/**
 * Validate a canonical lowercase OCI SHA-256 digest.
 *
 * @param {unknown} value
 * @param {string} [field]
 */
export function validateOciDigest(value, field = 'digest') {
  if (typeof value !== 'string' || !OCI_SHA256_PATTERN.test(value)) {
    throw new SupplyChainValidationError(
      field,
      `${field} must be a canonical lowercase OCI SHA-256 digest`,
    );
  }
  return value;
}

/**
 * Validate the canonical three-part versions used by the evidence lock.
 *
 * @param {unknown} value
 * @param {string} [field]
 */
export function validateVersion(value, field = 'version') {
  if (typeof value !== 'string' || !VERSION_PATTERN.test(value)) {
    throw new SupplyChainValidationError(
      field,
      `${field} must be a canonical three-part version`,
    );
  }
  return value;
}

/**
 * Select and validate an exact OCI manifest from an image evidence record.
 *
 * @param {unknown} image
 * @param {{ os?: unknown, architecture?: unknown }} platform
 */
export function selectPlatformManifest(image, platform) {
  const os = typeof platform?.os === 'string' ? platform.os : '';
  const architecture =
    typeof platform?.architecture === 'string' ? platform.architecture : '';
  const key = `${os}/${architecture}`;

  if (
    !isRecord(image) ||
    !isRecord(image.manifests) ||
    !Object.hasOwn(image.manifests, key)
  ) {
    throw new SupplyChainValidationError(
      'platform',
      `platform must identify an explicitly locked platform manifest`,
    );
  }

  validateOciDigest(image.indexDigest, 'indexDigest');
  const digest = validateOciDigest(
    image.manifests[key],
    `manifests.${key}`,
  );
  return { platform: key, digest };
}

/**
 * Phase 3 cannot promote candidate AAC compatibility without live evidence.
 *
 * @param {unknown} value
 * @param {string} [field]
 */
export function validateCompatibilityStatus(
  value,
  field = 'compatibility.status',
) {
  if (value !== 'unverified') {
    throw new SupplyChainValidationError(
      field,
      `${field} must remain unverified until an approved disposable live test`,
    );
  }
  return value;
}

/** @param {unknown} value */
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export class SupplyChainValidationError extends Error {
  /**
   * @param {string} field
   * @param {string} message
   */
  constructor(field, message) {
    super(message);
    this.name = 'SupplyChainValidationError';
    this.field = field;
  }
}
