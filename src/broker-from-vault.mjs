import { startBroker } from './broker.js';
import { startBrowserSessionBroker } from './browser-session-broker.mjs';
import { resolveFakeVaultSecrets, selectFakeVaultSecret } from './fake-vault-resolver.mjs';
import { validatePolicy } from './policy.js';

/**
 * Start the foreground broker or browser session broker using one fake-vault alias.
 * Policy credential_class must match the resolved secret class.
 */
export async function startBrokerWithFakeVault(options) {
  const secrets = resolveFakeVaultSecrets(options.aliasMap);
  const selected = selectFakeVaultSecret(secrets, options.alias);
  let policy;
  try {
    policy = validatePolicy(options.policy);
  } catch {
    throw new Error('invalid_policy');
  }
  if (policy.credential_class !== selected.credential_class) {
    const err = new Error('wrong_broker');
    err.code = 'wrong_broker';
    throw err;
  }
  if (selected.credential_class === 'browser_form_login') {
    return startBrowserSessionBroker({
      policy,
      credentials: { username: selected.username, password: selected.password },
      fetchImpl: options.fetchImpl,
      log: options.log,
    });
  }
  if (selected.credential_class === 'http_basic') {
    return startBroker({
      policy,
      credentials: { username: selected.username, password: selected.password },
      fetchImpl: options.fetchImpl,
      log: options.log,
    });
  }
  return startBroker({
    policy,
    sentinel: selected.credential,
    fetchImpl: options.fetchImpl,
    log: options.log,
  });
}
