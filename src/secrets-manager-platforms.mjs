/**
 * Same-user Secrets Manager is supported on Windows, macOS, and Linux.
 * Distinct-writer helpers (LocalService / LaunchDaemon / systemd) are separate.
 */

const PLATFORMS = new Set(['win32', 'darwin', 'linux']);

/**
 * @param {NodeJS.Platform} [platform]
 * @returns {boolean}
 */
export function isSecretsManagerSameUserPlatform(platform = process.platform) {
  return PLATFORMS.has(platform);
}
