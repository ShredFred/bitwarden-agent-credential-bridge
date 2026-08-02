import { startBroker } from './broker.js';
import { resolveFakeVaultSecrets, selectFakeVaultSecret } from './fake-vault-resolver.mjs';

/**
 * Start the foreground broker using one fake-vault alias secret.
 */
export async function startBrokerWithFakeVault(options) {
  const secrets = resolveFakeVaultSecrets(options.aliasMap);
  const selected = selectFakeVaultSecret(secrets, options.alias);
  if (selected.credential_class === 'http_basic') {
    return startBroker({
      policy: options.policy,
      credentials: { username: selected.username, password: selected.password },
      fetchImpl: options.fetchImpl,
      log: options.log,
    });
  }
  return startBroker({
    policy: options.policy,
    sentinel: selected.credential,
    fetchImpl: options.fetchImpl,
    log: options.log,
  });
}
