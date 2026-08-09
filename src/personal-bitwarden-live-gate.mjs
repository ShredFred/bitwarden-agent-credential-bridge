/**
 * Phase 13: branded personal Bitwarden live scope.
 *
 * Library APIs never accept an approval flag as a capability. The CLI runner
 * may construct a branded scope after `--i-approve-personal-bitwarden-agent-resolve`.
 * Company/organization vaults remain forbidden. Helper stays vault-free.
 * authorization_ready stays false (Windows 9e/10c evidence path is separate).
 */
const VALID_SCOPES = new WeakSet();

export class PersonalBitwardenLiveGateError extends Error {
  constructor(code) {
    super(`Personal Bitwarden live gate rejected: ${code}`);
    this.name = 'PersonalBitwardenLiveGateError';
    this.code = code;
  }
}

/**
 * Build an in-process branded personal Bitwarden scope.
 * Call only from the operator-approved CLI after the exact approval flag.
 */
export function buildPersonalBitwardenLiveScope() {
  const scope = Object.freeze({
    schema_version: 1,
    mode: 'personal_bitwarden_live',
    personal_vault_allowed: true,
    personal_vault_forbidden: false,
    company_vault_forbidden: true,
    organization_vault_forbidden: true,
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

export function isPersonalBitwardenLiveScope(value) {
  return value !== null && typeof value === 'object' && VALID_SCOPES.has(value);
}

export function assertPersonalBitwardenLiveScope(value) {
  if (!isPersonalBitwardenLiveScope(value)) {
    throw new PersonalBitwardenLiveGateError('invalid_scope');
  }
}

/**
 * Evaluate collector evidence under a branded personal scope.
 * Never authorizes production writer isolation.
 */
export function evaluatePersonalBitwardenEvidence(scope, evidence) {
  assertPersonalBitwardenLiveScope(scope);
  if (
    evidence === null ||
    typeof evidence !== 'object' ||
    Array.isArray(evidence) ||
    Object.getPrototypeOf(evidence) !== Object.prototype
  ) {
    throw new PersonalBitwardenLiveGateError('invalid_evidence');
  }
  const keys = Reflect.ownKeys(evidence);
  const required = [
    'personal_account_digest_matched',
    'organization_membership_absent',
    'company_vault_absent',
    'adapter_fixed',
  ];
  if (keys.length !== required.length || !required.every((k) => keys.includes(k))) {
    throw new PersonalBitwardenLiveGateError('invalid_evidence');
  }
  for (const key of required) {
    if (typeof /** @type {Record<string, unknown>} */ (evidence)[key] !== 'boolean') {
      throw new PersonalBitwardenLiveGateError('invalid_evidence');
    }
  }
  const e = /** @type {Record<string, boolean>} */ (evidence);
  const passed =
    e.personal_account_digest_matched === true &&
    e.organization_membership_absent === true &&
    e.company_vault_absent === true &&
    e.adapter_fixed === true;

  return Object.freeze({
    evidence_structurally_valid: true,
    personal_preflight_passed: passed,
    live_secret_resolved: false,
    authorization_ready: false,
    company_vault_forbidden: true,
    organization_vault_forbidden: true,
    personal_vault_allowed: true,
    dpapi_is_not_mfa: true,
    helper_vault_free: true,
  });
}
