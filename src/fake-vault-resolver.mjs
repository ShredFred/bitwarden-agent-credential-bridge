import { generateFakeSentinel } from './constants.js';

export class FakeVaultResolverError extends Error {
  constructor(code) {
    super(`Fake vault resolver rejected: ${code}`);
    this.name = 'FakeVaultResolverError';
    this.code = code;
  }
}

/**
 * Map strict service aliases to in-memory fake secrets for broker injection.
 * Never reads DPAPI, network, or Bitwarden.
 */
export function resolveFakeVaultSecrets(aliasMap) {
  if (aliasMap === null || typeof aliasMap !== 'object' || Array.isArray(aliasMap)) {
    throw new FakeVaultResolverError('invalid_alias_map');
  }
  const aliases = Object.keys(aliasMap);
  if (aliases.length < 1 || aliases.length > 32) {
    throw new FakeVaultResolverError('invalid_alias_map');
  }
  const secrets = Object.create(null);
  for (const alias of aliases) {
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(alias)) {
      throw new FakeVaultResolverError('invalid_alias');
    }
    const entry = aliasMap[alias];
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new FakeVaultResolverError('invalid_entry');
    }
    const keys = Object.keys(entry);
    if (keys.length !== 1 || keys[0] !== 'credential_class') {
      throw new FakeVaultResolverError('invalid_entry');
    }
    const credentialClass = entry.credential_class;
    if (credentialClass === 'http_bearer' || credentialClass === 'http_api_key_header') {
      secrets[alias] = Object.freeze({
        credential_class: credentialClass,
        credential: generateFakeSentinel(),
      });
    } else if (credentialClass === 'http_basic' || credentialClass === 'browser_form_login') {
      secrets[alias] = Object.freeze({
        credential_class: credentialClass,
        username: `user_${alias}`,
        password: generateFakeSentinel(),
      });
    } else {
      throw new FakeVaultResolverError('unsupported_credential_class');
    }
  }
  return Object.freeze(secrets);
}

/**
 * Pick one alias secret for broker start without exposing other aliases.
 */
export function selectFakeVaultSecret(secrets, alias) {
  if (secrets === null || typeof secrets !== 'object' || typeof alias !== 'string' ||
      !Object.prototype.hasOwnProperty.call(secrets, alias)) {
    throw new FakeVaultResolverError('unknown_alias');
  }
  return secrets[alias];
}
