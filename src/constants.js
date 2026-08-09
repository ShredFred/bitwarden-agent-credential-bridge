import { randomBytes } from 'node:crypto';

/**
 * Constant payloads and credential-class allow-list for the fake-only harness.
 * Runtime sentinels are generated per process via generateFakeSentinel().
 * Never hard-code a runtime sentinel in tracked source.
 */

export const FAKE_API_CONSTANT_BODY = Object.freeze({
  ok: true,
  service: 'fake-sample-api',
  message: 'constant-response-from-fake-sample-api',
});

export {
  BASIC_SHAPED_CREDENTIAL_CLASSES,
  CREDENTIAL_CLASS_BY_VERSION,
  HTTP_INJECTION_CREDENTIAL_CLASSES,
  REJECTED_CREDENTIAL_CLASSES,
  SENTINEL_CREDENTIAL_CLASSES,
  SESSION_BROKER_CREDENTIAL_CLASSES,
  SUPPORTED_CREDENTIAL_CLASSES,
  isRejectedCredentialClass,
  isSupportedCredentialClass,
} from './credential-classes.js';

/** Exact credential value placeholder required by policies. */
export const CREDENTIAL_PLACEHOLDER = '{{credential}}';
export const USERNAME_PLACEHOLDER = '{{username}}';
export const PASSWORD_PLACEHOLDER = '{{password}}';

/**
 * Generate a cryptographically random fake credential sentinel for this process.
 * Pass the result explicitly into the fake API and broker; do not persist it.
 * @returns {string}
 */
export function generateFakeSentinel() {
  return `bw-fake-${randomBytes(32).toString('base64url')}`;
}
