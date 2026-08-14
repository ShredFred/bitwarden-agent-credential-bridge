import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  authorizeTargetSelection,
  denyAgentOp,
  enumerateAgentCandidates,
  FORBIDDEN_AGENT_OPS,
  parseLoginPageFacts,
  parseTargetSelection,
  BridgeBrowserTargetingError,
} from '../src/bridge-browser-targeting.mjs';

const LOGIN_HTML =
  '<form method="POST" action="/login">' +
  '<input name="username" />' +
  '<input name="password" type="password" />' +
  '<input type="hidden" name="csrf" value="token-1" />' +
  '<button type="submit">login</button></form>';

describe('bridge browser targeting', () => {
  it('enumerates username, password, and submit without values or hidden fields', () => {
    const facts = parseLoginPageFacts(LOGIN_HTML, 'http://127.0.0.1:9/login');
    assert.equal(facts.challenge, 'none');
    assert.equal(facts.origin, 'http://127.0.0.1:9');
    const candidates = enumerateAgentCandidates(facts);
    assert.deepEqual(candidates.map((c) => c.kind), ['username', 'password', 'submit']);
    assert.equal(JSON.stringify(candidates).includes('token-1'), false);
    assert.equal(candidates.some((c) => c.name === 'csrf'), false);
  });

  it('rejects extra selector fields and kind mismatches', () => {
    const facts = parseLoginPageFacts(LOGIN_HTML, 'http://127.0.0.1:9/login');
    const candidates = enumerateAgentCandidates(facts);
    const snapshot = {
      generation: 1,
      origin: facts.origin,
      candidates,
      form_action: facts.form_action,
    };
    const policy = {
      login_origin: 'http://127.0.0.1:9',
      username_field: 'username',
      password_field: 'password',
    };
    assert.throws(
      () => parseTargetSelection({
        generation: 1,
        username_index: 0,
        password_index: 1,
        submit_index: 2,
        selector: '#password',
      }),
      (error) => error instanceof BridgeBrowserTargetingError &&
        error.code === 'extra_field_forbidden',
    );
    const swapped = parseTargetSelection({
      generation: 1,
      username_index: 1,
      password_index: 0,
      submit_index: 2,
    });
    assert.throws(
      () => authorizeTargetSelection(snapshot, swapped, policy),
      (error) => error instanceof BridgeBrowserTargetingError &&
        error.code === 'target_kind_mismatch',
    );
    assert.throws(
      () => authorizeTargetSelection(snapshot, parseTargetSelection({
        generation: 99,
        username_index: 0,
        password_index: 1,
        submit_index: 2,
      }), policy),
      (error) => error instanceof BridgeBrowserTargetingError &&
        error.code === 'stale_generation',
    );
  });

  it('maps cookie/eval/fill ops to session_material_forbidden', () => {
    for (const op of ['eval', 'cookie_list', 'state_save', 'fill', 'fill_password', 'cdp']) {
      assert.equal(denyAgentOp(op), 'session_material_forbidden');
    }
    assert.equal(denyAgentOp('screenshot'), null);
    assert.equal(denyAgentOp('playwright_cli'), 'command_forbidden');
    assert.equal(denyAgentOp('snapshot'), null);
    assert.equal(denyAgentOp('contract'), null);
    assert.ok(FORBIDDEN_AGENT_OPS.includes('cookie_list'));
  });

  it('detects MFA and CAPTCHA without offering password candidates', () => {
    const mfa = parseLoginPageFacts(
      '<p>Enter MFA code</p>',
      'http://127.0.0.1:9/login',
    );
    assert.equal(mfa.challenge, 'mfa');
    assert.equal(enumerateAgentCandidates(mfa).length, 0);
    const captcha = parseLoginPageFacts(
      '<div class="recaptcha">bot-check</div>',
      'http://127.0.0.1:9/login',
    );
    assert.equal(captcha.challenge, 'captcha');
    assert.equal(enumerateAgentCandidates(captcha).length, 0);
  });
});
