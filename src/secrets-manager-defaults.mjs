/**
 * Operator defaults for the guided same-user Secrets Manager path.
 * Project UUIDs are identifiers (not secrets). Tokens stay local-only.
 */
export const SM_DEFAULT_PROJECTS = Object.freeze({
  mivia: 'e186495e-8667-436f-9f78-b49800eba251',
  private_hq: '1d9a72dc-75aa-4bf3-a528-b49800ebbf68',
});

export const SM_DEFAULT_ALLOWED_PROJECT_IDS = Object.freeze([
  SM_DEFAULT_PROJECTS.mivia,
  SM_DEFAULT_PROJECTS.private_hq,
]);

export const SM_SETUP_APPROVAL_FLAG = '--i-approve-sm-machine-setup';
export const SM_UNINSTALL_APPROVAL_FLAG = '--i-approve-sm-machine-uninstall';
export const SM_WRITE_APPROVAL_FLAG = '--i-approve-secrets-manager-machine-write';
export const SM_RESOLVE_APPROVAL_FLAG = '--i-approve-secrets-manager-machine-resolve';

/** Canonical tracked operational SM bindings (MiViA + private-hq). */
export const SM_OPERATIONAL_BINDINGS_PATH = 'samples/operational/bindings-sm.json';
