/**
 * Branded disposable/dev Bitwarden live scope (Phase 7 / choice 1B).
 *
 * Library APIs never accept an approval flag as a capability. The CLI runner
 * may construct a branded scope after an exact approval flag; forged/cloned
 * objects are rejected. Always reports authorization_ready=false.
 *
 * DPAPI unlock is secret-at-rest protection only — it is not MFA, OAuth, SMS,
 * or interactive second-factor support.
 */
const VALID_SCOPES = new WeakSet();

export class DisposableBitwardenLiveGateError extends Error {
  /**
   * @param {string} code
   */
  constructor(code) {
    super(`Disposable Bitwarden live gate rejected: ${code}`);
    this.name = 'DisposableBitwardenLiveGateError';
    this.code = code;
  }
}

/**
 * Build an in-process branded disposable/dev Bitwarden scope.
 * Call only from the operator-approved CLI runner after the exact approval flag.
 * @returns {Readonly<{
 *   schema_version: 1,
 *   mode: 'disposable_bitwarden_live',
 *   personal_vault_forbidden: true,
 *   company_vault_forbidden: true,
 *   organization_membership_forbidden: true,
 *   helper_vault_free: true,
 *   oauth_forbidden: true,
 *   mfa_interactive_forbidden: true,
 *   sms_forbidden: true,
 *   email_forbidden: true,
 *   dpapi_is_not_mfa: true,
 *   mutation_authorized: false,
 *   live_test_executed: false,
 *   authorization_ready: false,
 *   install_gate_eligible: false,
 * }>}
 */
export function buildDisposableBitwardenLiveScope() {
  const scope = Object.freeze({
    schema_version: 1,
    mode: 'disposable_bitwarden_live',
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    organization_membership_forbidden: true,
    helper_vault_free: true,
    oauth_forbidden: true,
    mfa_interactive_forbidden: true,
    sms_forbidden: true,
    email_forbidden: true,
    dpapi_is_not_mfa: true,
    mutation_authorized: false,
    live_test_executed: false,
    authorization_ready: false,
    install_gate_eligible: false,
  });
  VALID_SCOPES.add(scope);
  return scope;
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isDisposableBitwardenLiveScope(value) {
  return value !== null && typeof value === 'object' && VALID_SCOPES.has(value);
}

/**
 * @param {unknown} value
 */
export function assertDisposableBitwardenLiveScope(value) {
  if (!isDisposableBitwardenLiveScope(value)) {
    throw new DisposableBitwardenLiveGateError('invalid_scope');
  }
}

/**
 * Evidence returned by a fixed disposable collector. Values are booleans only;
 * never include vault inventory, IDs, secrets, or account names.
 * @typedef {{
 *   disposable_account_verified: boolean,
 *   organization_membership_absent: boolean,
 *   item_personal_only: boolean,
 *   adapter_fixed: boolean,
 * }} DisposableVaultEvidence
 */

/**
 * Evaluate collector evidence under a branded scope. Never authorizes production.
 * @param {unknown} scope
 * @param {unknown} evidence
 * @returns {Readonly<{
 *   evidence_structurally_valid: boolean,
 *   disposable_preflight_passed: boolean,
 *   live_secret_resolved: false,
 *   authorization_ready: false,
 *   company_vault_forbidden: true,
 *   personal_vault_forbidden: true,
 *   dpapi_is_not_mfa: true,
 * }>}
 */
export function evaluateDisposableBitwardenEvidence(scope, evidence) {
  assertDisposableBitwardenLiveScope(scope);
  if (
    evidence === null ||
    typeof evidence !== 'object' ||
    Array.isArray(evidence) ||
    Object.getPrototypeOf(evidence) !== Object.prototype
  ) {
    throw new DisposableBitwardenLiveGateError('invalid_evidence');
  }
  const keys = Reflect.ownKeys(evidence);
  const required = [
    'disposable_account_verified',
    'organization_membership_absent',
    'item_personal_only',
    'adapter_fixed',
  ];
  if (keys.length !== required.length || !required.every((k) => keys.includes(k))) {
    throw new DisposableBitwardenLiveGateError('invalid_evidence');
  }
  for (const key of required) {
    if (typeof /** @type {Record<string, unknown>} */ (evidence)[key] !== 'boolean') {
      throw new DisposableBitwardenLiveGateError('invalid_evidence');
    }
  }
  const e = /** @type {DisposableVaultEvidence} */ (evidence);
  const passed =
    e.disposable_account_verified === true &&
    e.organization_membership_absent === true &&
    e.item_personal_only === true &&
    e.adapter_fixed === true;

  return Object.freeze({
    evidence_structurally_valid: true,
    disposable_preflight_passed: passed,
    live_secret_resolved: false,
    authorization_ready: false,
    company_vault_forbidden: true,
    personal_vault_forbidden: true,
    dpapi_is_not_mfa: true,
  });
}
