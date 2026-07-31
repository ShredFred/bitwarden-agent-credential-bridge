import { randomBytes } from 'node:crypto';

/**
 * Constant payloads and credential-class allow-list for Phase 1.
 * Runtime bearer sentinels are generated per process via generateFakeSentinel().
 * Never hard-code a runtime sentinel in tracked source.
 */

export const FAKE_API_CONSTANT_BODY = Object.freeze({
  ok: true,
  service: 'fake-sample-api',
  message: 'constant-response-from-fake-sample-api',
});

/** Credential classes supported by this Phase 1 harness. All others fail closed. */
export const SUPPORTED_CREDENTIAL_CLASSES = Object.freeze(['http_bearer']);

/** Exact Authorization value placeholder required by policies. */
export const CREDENTIAL_PLACEHOLDER = '{{credential}}';

/**
 * Generate a cryptographically random fake bearer sentinel for this process.
 * Pass the result explicitly into the fake API and broker; do not persist it.
 * @returns {string}
 */
export function generateFakeSentinel() {
  return `bw-fake-${randomBytes(32).toString('base64url')}`;
}
