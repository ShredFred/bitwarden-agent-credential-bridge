/**
 * Phase 17 targeting contract for a Bridge-owned browser.
 * The agent may only pick among Bridge-enumerated candidates by index.
 * Free-form selectors, cookies, and credential values are not representable.
 */

export class BridgeBrowserTargetingError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(`Bridge browser targeting rejected: ${code}`);
    this.name = 'BridgeBrowserTargetingError';
    this.code = code;
  }
}

export const ALLOWED_AGENT_OPS = Object.freeze([
  'status',
  'contract',
  'snapshot',
  'select_targets',
  'inject_login',
  'goto',
  'screenshot',
]);

export const AGENT_ERROR_CODES = Object.freeze([
  'adapter_failed',
  'already_logged_in',
  'captcha_required',
  'challenge_blocked',
  'command_forbidden',
  'concurrent_session_forbidden',
  'extra_field_forbidden',
  'inject_before_select',
  'invalid_request',
  'mfa_required',
  'not_found',
  'not_logged_in',
  'origin_mismatch',
  'path_denied',
  'playwright_absent',
  'playwright_launch_failed',
  'password_entry_active',
  'screenshot_too_large',
  'screenshot_unsupported',
  'sensitive_response_blocked',
  'session_expired',
  'session_material_forbidden',
  'stale_generation',
  'success_path_mismatch',
  'target_kind_mismatch',
]);

export const FORBIDDEN_AGENT_OPS = Object.freeze([
  'eval',
  'run_code',
  'cdp',
  'cookie_list',
  'cookie_get',
  'cookie_set',
  'cookie_clear',
  'state_save',
  'state_load',
  'fill',
  'type',
  'press',
  'pdf',
  'localstorage_list',
  'localstorage_get',
  'sessionstorage_list',
  'sessionstorage_get',
  'playwright',
  'playwright_cli',
  'request',
  'request_body',
  'response_body',
  'fill_password',
]);

const SELECT_KEYS = Object.freeze([
  'generation',
  'username_index',
  'password_index',
  'submit_index',
]);

const MFA_HINT = /\b(mfa|2fa|totp|otp|one[-\s]?time)|enter mfa code|mfa_required|otp_required\b/i;
const CAPTCHA_HINT = /\b(captcha|recaptcha|hcaptcha|bot[-\s]?check)\b/i;

/**
 * Classify a login HTML document into value-free page facts.
 * Hidden field *values* stay internal to the adapter; facts expose names only.
 *
 * @param {string} html
 * @param {string} pageUrl
 */
export function parseLoginPageFacts(html, pageUrl) {
  if (typeof html !== 'string' || html.length > 256 * 1024) {
    throw new BridgeBrowserTargetingError('page_unreadable');
  }
  if (typeof pageUrl !== 'string') {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
  let url;
  try {
    url = new URL(pageUrl);
  } catch {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }

  let challenge = 'none';
  if (MFA_HINT.test(html)) challenge = 'mfa';
  else if (CAPTCHA_HINT.test(html)) challenge = 'captcha';

  const formMatch = html.match(/<form\b([^>]*)>([\s\S]*?)<\/form>/i);
  const formAttrs = formMatch ? parseAttrs(formMatch[1]) : {};
  const formInner = formMatch ? formMatch[2] : html;
  const actionRaw = typeof formAttrs.action === 'string' ? formAttrs.action : url.pathname;
  let formAction;
  try {
    formAction = new URL(actionRaw, url).href;
  } catch {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }

  /** @type {{ name: string, type: string, hidden: boolean }[]} */
  const fields = [];
  const inputRe = /<input\b([^>]*)>/gi;
  let inputMatch;
  while ((inputMatch = inputRe.exec(formInner)) !== null) {
    const attrs = parseAttrs(inputMatch[1]);
    const name = typeof attrs.name === 'string' ? attrs.name : '';
    if (name === '') continue;
    const type = (attrs.type || 'text').toLowerCase();
    fields.push({
      name,
      type,
      hidden: type === 'hidden',
    });
  }

  /** @type {{ type: string, label: string }[]} */
  const buttons = [];
  const buttonRe = /<button\b([^>]*)>([\s\S]*?)<\/button>/gi;
  let buttonMatch;
  while ((buttonMatch = buttonRe.exec(formInner)) !== null) {
    const attrs = parseAttrs(buttonMatch[1]);
    const type = (attrs.type || 'submit').toLowerCase();
    const label = stripTags(buttonMatch[2]).trim() || 'submit';
    buttons.push({ type, label });
  }

  return Object.freeze({
    origin: url.origin,
    path: url.pathname,
    form_action: formAction,
    challenge,
    fields: Object.freeze(fields.map((f) => Object.freeze({ ...f }))),
    buttons: Object.freeze(buttons.map((b) => Object.freeze({ ...b }))),
  });
}

/**
 * Build the agent-visible candidate list. No values, cookies, or selectors.
 *
 * @param {ReturnType<typeof parseLoginPageFacts>} facts
 */
export function enumerateAgentCandidates(facts) {
  if (facts.challenge !== 'none') {
    return Object.freeze([]);
  }
  /** @type {{ index: number, kind: string, name: string }[]} */
  const candidates = [];
  let index = 0;
  for (const field of facts.fields) {
    if (field.hidden) continue;
    if (field.type === 'password') {
      candidates.push({ index, kind: 'password', name: field.name });
      index += 1;
      continue;
    }
    if (field.type === 'text' || field.type === 'email' || field.type === '') {
      candidates.push({ index, kind: 'username', name: field.name });
      index += 1;
    }
  }
  for (const button of facts.buttons) {
    if (button.type === 'submit' || button.type === 'button') {
      candidates.push({ index, kind: 'submit', name: button.label });
      index += 1;
    }
  }
  return Object.freeze(candidates.map((c) => Object.freeze(c)));
}

/**
 * @param {unknown} raw
 * @returns {{ generation: number, username_index: number, password_index: number, submit_index: number }}
 */
export function parseTargetSelection(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new BridgeBrowserTargetingError('invalid_request');
  }
  const keys = Object.keys(raw).sort();
  if (keys.length !== SELECT_KEYS.length || keys.join(',') !== [...SELECT_KEYS].sort().join(',')) {
    throw new BridgeBrowserTargetingError('extra_field_forbidden');
  }
  /** @type {Record<string, unknown>} */
  const obj = /** @type {Record<string, unknown>} */ (raw);
  for (const key of SELECT_KEYS) {
    if (typeof obj[key] !== 'number' || !Number.isInteger(obj[key]) || obj[key] < 0) {
      throw new BridgeBrowserTargetingError('invalid_request');
    }
  }
  if (/** @type {number} */ (obj.generation) < 1) {
    throw new BridgeBrowserTargetingError('invalid_request');
  }
  return {
    generation: /** @type {number} */ (obj.generation),
    username_index: /** @type {number} */ (obj.username_index),
    password_index: /** @type {number} */ (obj.password_index),
    submit_index: /** @type {number} */ (obj.submit_index),
  };
}

/**
 * Authorize an agent selection against the current candidate generation.
 *
 * @param {{ generation: number, origin: string, candidates: readonly { index: number, kind: string, name: string }[], form_action: string }} snapshot
 * @param {ReturnType<typeof parseTargetSelection>} selection
 * @param {{ login_origin: string, username_field: string, password_field: string }} policy
 */
export function authorizeTargetSelection(snapshot, selection, policy) {
  if (selection.generation !== snapshot.generation) {
    throw new BridgeBrowserTargetingError('stale_generation');
  }
  const expectedOrigin = originOf(policy.login_origin);
  if (snapshot.origin !== expectedOrigin) {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
  let formOrigin;
  try {
    formOrigin = new URL(snapshot.form_action).origin;
  } catch {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
  if (formOrigin !== expectedOrigin) {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }

  const username = candidateAt(snapshot.candidates, selection.username_index);
  const password = candidateAt(snapshot.candidates, selection.password_index);
  const submit = candidateAt(snapshot.candidates, selection.submit_index);
  if (username.kind !== 'username') {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
  if (password.kind !== 'password') {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
  if (submit.kind !== 'submit') {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
  if (username.name !== policy.username_field || password.name !== policy.password_field) {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
  return Object.freeze({ username, password, submit });
}

/**
 * Re-verify live facts immediately before injection.
 *
 * @param {ReturnType<typeof parseLoginPageFacts>} liveFacts
 * @param {ReturnType<typeof authorizeTargetSelection>} authorized
 * @param {{ login_origin: string }} policy
 */
export function assertInjectSafe(liveFacts, authorized, policy) {
  if (liveFacts.challenge !== 'none') {
    throw new BridgeBrowserTargetingError('challenge_blocked');
  }
  const expectedOrigin = originOf(policy.login_origin);
  if (liveFacts.origin !== expectedOrigin) {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
  let formOrigin;
  try {
    formOrigin = new URL(liveFacts.form_action).origin;
  } catch {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
  if (formOrigin !== expectedOrigin) {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
  const passwordField = liveFacts.fields.find((f) => f.name === authorized.password.name);
  if (!passwordField || passwordField.type !== 'password' || passwordField.hidden) {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
  const usernameField = liveFacts.fields.find((f) => f.name === authorized.username.name);
  if (!usernameField || usernameField.hidden || usernameField.type === 'password') {
    throw new BridgeBrowserTargetingError('target_kind_mismatch');
  }
}

/**
 * @param {string} op
 * @returns {string | null} stable deny code, or null if allowed
 */
export function denyAgentOp(op) {
  if (typeof op !== 'string') return 'invalid_request';
  if (FORBIDDEN_AGENT_OPS.includes(op)) {
    if (
      op.startsWith('cookie_') ||
      op.startsWith('state_') ||
      op === 'eval' ||
      op === 'run_code' ||
      op === 'cdp' ||
      op === 'fill_password' ||
      op === 'fill' ||
      op === 'type'
    ) {
      return 'session_material_forbidden';
    }
    return 'command_forbidden';
  }
  if (!ALLOWED_AGENT_OPS.includes(op)) return 'command_forbidden';
  return null;
}

function candidateAt(candidates, index) {
  const found = candidates.find((c) => c.index === index);
  if (!found) throw new BridgeBrowserTargetingError('invalid_request');
  return found;
}

function originOf(loginOrigin) {
  try {
    return new URL(loginOrigin).origin;
  } catch {
    throw new BridgeBrowserTargetingError('origin_mismatch');
  }
}

function parseAttrs(raw) {
  /** @type {Record<string, string>} */
  const attrs = {};
  const re = /([a-zA-Z_:][\w:.-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let match;
  while ((match = re.exec(raw)) !== null) {
    attrs[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
  }
  return attrs;
}

function stripTags(value) {
  return value.replace(/<[^>]+>/g, '');
}
