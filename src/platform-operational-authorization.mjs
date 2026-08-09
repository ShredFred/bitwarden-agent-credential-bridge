import process from 'node:process';
import {
  absentWindowsOperationalAuthorization,
  composeWindowsOperationalAuthorization,
} from './windows-operational-authorization.mjs';
import {
  absentMacosOperationalAuthorization,
  composeMacosOperationalAuthorization,
} from './macos-operational-authorization.mjs';
import {
  absentLinuxOperationalAuthorization,
  composeLinuxOperationalAuthorization,
} from './linux-operational-authorization.mjs';

/**
 * Platform-scoped operational authorization dispatch.
 * Never copies Windows readiness onto darwin/linux (or the reverse).
 */

export class PlatformOperationalAuthorizationError extends Error {
  constructor(code = 'unsupported_platform') {
    super(`Platform operational authorization rejected: ${code}`);
    this.name = 'PlatformOperationalAuthorizationError';
    this.code = code;
  }
}

export function absentOperationalAuthorizationForPlatform(platform = process.platform) {
  if (platform === 'win32') return absentWindowsOperationalAuthorization();
  if (platform === 'darwin') return absentMacosOperationalAuthorization();
  if (platform === 'linux') return absentLinuxOperationalAuthorization();
  throw new PlatformOperationalAuthorizationError('unsupported_platform');
}

export function composeOperationalAuthorizationForPlatform(platform, evidence) {
  if (platform === 'win32') return composeWindowsOperationalAuthorization(evidence);
  if (platform === 'darwin') return composeMacosOperationalAuthorization(evidence);
  if (platform === 'linux') return composeLinuxOperationalAuthorization(evidence);
  throw new PlatformOperationalAuthorizationError('unsupported_platform');
}
