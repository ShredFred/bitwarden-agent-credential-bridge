export const MIN_AGENT_TOKEN_LENGTH = 16;
export const MAX_AGENT_TOKEN_LENGTH = 512;

export class AgentTokenError extends Error {
  constructor(code) {
    super(`invalid OneCLI agent token: ${code}`);
    this.name = 'AgentTokenError';
    this.code = code;
  }
}

export function validateAgentToken(value) {
  if (typeof value !== 'string' || value.length < MIN_AGENT_TOKEN_LENGTH ||
      value.length > MAX_AGENT_TOKEN_LENGTH || !/^[\x21-\x7e]+$/.test(value) ||
      value.includes(':')) throw new AgentTokenError('invalid_shape');
  return value;
}

export function oneCliProxyAuthorizationValue(value) {
  const token = validateAgentToken(value);
  return `Basic ${Buffer.from(`${token}:`, 'ascii').toString('base64')}`;
}
