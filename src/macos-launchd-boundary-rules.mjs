import { createHash } from 'node:crypto';

export const MACOS_HELPER_LABEL = 'de.frederikstadler.bitwarden-agent-credential-bridge.helper';
export const MACOS_HELPER_ACCOUNT = '_bwagentbridge';
export const MACOS_HELPER_BINARY_PATH = `/Library/PrivilegedHelperTools/${MACOS_HELPER_LABEL}`;
const MAX_REQUIREMENT_BYTES = 64 * 1024;
const FORBIDDEN_TRIGGERS = Object.freeze([
  'KeepAlive',
  'RunAtLoad',
  'StartInterval',
  'StartCalendarInterval',
  'StartOnMount',
  'QueueDirectories',
  'WatchPaths',
  'LaunchEvents',
  'Sockets',
  'PathState',
  'OtherJobEnabled',
]);

export function evaluateMacosLaunchdPlist(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    return Object.freeze({
      system_domain_plist: false,
      demand_activation_only: false,
      mach_service_declared: false,
    });
  }
  return Object.freeze({
    system_domain_plist: value.Label === MACOS_HELPER_LABEL &&
      value.UserName === MACOS_HELPER_ACCOUNT && exactProgramBinding(value),
    demand_activation_only: FORBIDDEN_TRIGGERS.every((key) =>
      value[key] === undefined || value[key] === false),
    mach_service_declared: exactMachService(value.MachServices),
  });
}

export function digestDesignatedRequirementStdout(stdout) {
  if (typeof stdout !== 'string' || stdout.includes('\0') ||
      Buffer.byteLength(stdout, 'utf8') > MAX_REQUIREMENT_BYTES ||
      !(/^designated => [^\r\n]+\n$/.test(stdout) ||
        /^# designated => cdhash H"[0-9a-f]{40}"\n$/.test(stdout))) return null;
  return createHash('sha256').update(Buffer.from(stdout, 'utf8')).digest('hex');
}

function exactProgramBinding(plist) {
  if (typeof plist.Program === 'string') {
    return plist.Program === MACOS_HELPER_BINARY_PATH && plist.ProgramArguments === undefined;
  }
  return plist.Program === undefined && Array.isArray(plist.ProgramArguments) &&
    plist.ProgramArguments.length === 1 && plist.ProgramArguments[0] === MACOS_HELPER_BINARY_PATH;
}

function exactMachService(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== 1 ||
      !Object.hasOwn(value, MACOS_HELPER_LABEL)) return false;
  const configured = value[MACOS_HELPER_LABEL];
  return configured === true || (configured !== null && typeof configured === 'object' &&
    !Array.isArray(configured) && Object.getPrototypeOf(configured) === Object.prototype &&
    Reflect.ownKeys(configured).length === 0);
}
