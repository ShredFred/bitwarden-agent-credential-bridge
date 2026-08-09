/**
 * Phase 14: branded Secrets Manager machine-account live scope.
 *
 * Library APIs never accept an approval flag as a capability. The CLI may
 * construct a branded scope after `--i-approve-secrets-manager-machine-resolve`.
 * Helper stays vault-free. authorization_ready stays false.
 */
const VALID_SCOPES = new WeakSet();

export class SecretsManagerLiveGateError extends Error {
  constructor(code) {
    super(`Secrets Manager live gate rejected: ${code}`);
    this.name = 'SecretsManagerLiveGateError';
    this.code = code;
  }
}

/**
 * Build an in-process branded SM same-user scope.
 * Call only from the operator-approved CLI after the exact approval flag.
 */
export function buildSecretsManagerLiveScope() {
  const scope = Object.freeze({
    schema_version: 1,
    mode: 'secrets_manager_machine_live',
    secrets_manager_allowed: true,
    same_user_bridge_only: true,
    helper_vault_free: true,
    env_inject_forbidden: true,
    oauth_forbidden: true,
    mfa_interactive_forbidden: true,
    sms_forbidden: true,
    email_forbidden: true,
    mutation_authorized: false,
    live_test_executed: false,
    authorization_ready: false,
    install_gate_eligible: false,
    localservice_vault_forbidden: true,
  });
  VALID_SCOPES.add(scope);
  return scope;
}

export function isSecretsManagerLiveScope(value) {
  return value !== null && typeof value === 'object' && VALID_SCOPES.has(value);
}

export function assertSecretsManagerLiveScope(value) {
  if (!isSecretsManagerLiveScope(value)) {
    throw new SecretsManagerLiveGateError('invalid_scope');
  }
}

/**
 * Evaluate collector evidence under a branded SM scope.
 * Never authorizes production writer isolation.
 */
export function evaluateSecretsManagerEvidence(scope, evidence) {
  assertSecretsManagerLiveScope(scope);
  if (
    evidence === null ||
    typeof evidence !== 'object' ||
    Array.isArray(evidence) ||
    Object.getPrototypeOf(evidence) !== Object.prototype
  ) {
    throw new SecretsManagerLiveGateError('invalid_evidence');
  }
  const keys = Reflect.ownKeys(evidence);
  const required = [
    'machine_config_loaded',
    'token_present',
    'adapter_fixed',
    'projects_allowlisted',
  ];
  if (keys.length !== required.length || !required.every((k) => keys.includes(k))) {
    throw new SecretsManagerLiveGateError('invalid_evidence');
  }
  for (const key of required) {
    if (typeof /** @type {Record<string, unknown>} */ (evidence)[key] !== 'boolean') {
      throw new SecretsManagerLiveGateError('invalid_evidence');
    }
  }
  const e = /** @type {Record<string, boolean>} */ (evidence);
  const passed =
    e.machine_config_loaded === true &&
    e.token_present === true &&
    e.adapter_fixed === true &&
    e.projects_allowlisted === true;

  return Object.freeze({
    evidence_structurally_valid: true,
    sm_preflight_passed: passed,
    live_secret_resolved: false,
    authorization_ready: false,
    secrets_manager_allowed: true,
    helper_vault_free: true,
    env_inject_forbidden: true,
    localservice_vault_forbidden: true,
  });
}
