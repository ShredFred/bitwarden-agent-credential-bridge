/**
 * CLI argument parsing for the Bridge-owned browser SM start command.
 * Approval flags are never a library capability — the script checks argv.
 */

export const SM_RESOLVE_APPROVAL_FLAG = '--i-approve-secrets-manager-machine-resolve';
export const BRIDGE_OWNED_BROWSER_APPROVAL_FLAG = '--i-approve-bridge-owned-browser';
export const BRIDGE_OWNED_BROWSER_CLI_BIND = 'http://127.0.0.1:18792';

const ALIAS_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
const KNOWN_SWITCHES = new Set([
  SM_RESOLVE_APPROVAL_FLAG,
  BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
  '--headed',
  '--headless',
]);

/**
 * @param {string[]} argv
 * @returns {{
 *   ok: true,
 *   alias: string,
 *   driver: 'fetch' | 'playwright',
 *   headless: boolean,
 * } | {
 *   ok: false,
 *   code: string,
 *   required_flags?: string[],
 * }}
 */
export function parseBridgeOwnedBrowserCli(argv) {
  if (!Array.isArray(argv)) {
    return { ok: false, code: 'invalid_request' };
  }
  const hasSm = argv.includes(SM_RESOLVE_APPROVAL_FLAG);
  const hasBrowser = argv.includes(BRIDGE_OWNED_BROWSER_APPROVAL_FLAG);
  if (!hasSm || !hasBrowser) {
    return {
      ok: false,
      code: 'approval_flag_required',
      required_flags: [SM_RESOLVE_APPROVAL_FLAG, BRIDGE_OWNED_BROWSER_APPROVAL_FLAG],
    };
  }
  const alias = flagValue(argv, '--alias');
  if (typeof alias !== 'string' || !ALIAS_PATTERN.test(alias)) {
    return { ok: false, code: 'invalid_alias' };
  }
  const driverRaw = flagValue(argv, '--driver');
  const driver = driverRaw === null ? 'fetch' : driverRaw;
  if (driver !== 'fetch' && driver !== 'playwright') {
    return { ok: false, code: 'invalid_request' };
  }
  if (hasUnknownCliFlag(argv)) {
    return { ok: false, code: 'invalid_request' };
  }
  if (argv.includes('--headless') && argv.includes('--headed')) {
    return { ok: false, code: 'invalid_request' };
  }
  if (argv.includes('--headed') && driver === 'fetch') {
    return { ok: false, code: 'invalid_request' };
  }
  const headless = !argv.includes('--headed');
  return { ok: true, alias, driver, headless };
}

/**
 * @param {string[]} argv
 */
function hasUnknownCliFlag(argv) {
  for (const arg of argv) {
    if (typeof arg !== 'string' || !arg.startsWith('-')) continue;
    if (arg.startsWith('--alias=') || arg.startsWith('--driver=')) continue;
    if (arg === '--alias' || arg === '--driver') continue;
    if (KNOWN_SWITCHES.has(arg)) continue;
    return true;
  }
  return false;
}

/**
 * @param {string[]} argv
 * @param {string} name
 * @returns {string | null}
 */
function flagValue(argv, name) {
  const prefix = `${name}=`;
  const eq = argv.find((arg) => arg.startsWith(prefix));
  if (eq) return eq.slice(prefix.length);
  const idx = argv.indexOf(name);
  if (idx < 0 || idx + 1 >= argv.length) return null;
  const next = argv[idx + 1];
  if (typeof next !== 'string' || next.startsWith('-')) return null;
  return next;
}
