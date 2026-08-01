import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  AgentTokenError,
  oneCliProxyAuthorizationValue,
  validateAgentToken,
} from '../src/agent-token.js';

describe('OneCLI agent token boundary', () => {
  it('builds the exact OneCLI Basic token shape', () => {
    const token = 'agent-token-0123456789';
    assert.equal(validateAgentToken(token), token);
    assert.equal(oneCliProxyAuthorizationValue(token),
      `Basic ${Buffer.from(`${token}:`).toString('base64')}`);
  });

  it('rejects ambiguous, control, non-ASCII, short, and oversized values', () => {
    for (const invalid of ['', 'short', 'a'.repeat(513), 'a'.repeat(16) + ':',
      'a'.repeat(16) + '\n', 'a'.repeat(16) + 'é', null, {}]) {
      assert.throws(() => validateAgentToken(invalid), AgentTokenError);
    }
  });
});
