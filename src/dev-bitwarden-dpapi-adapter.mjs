import { execFile } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { DevBitwardenResolverError } from './dev-bitwarden-resolver.mjs';

const execFileAsync = promisify(execFile);
const FIXED_PURPOSE_SHA256 =
  'ca67ca6a2a61f930458091c3109d568bc3c60483399ccc2a2cf2bd066b50fee6';
const FIXED_ITEM_REF = 'dpapi-store';
const SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'dev-bitwarden-dpapi-probe.ps1',
);

/**
 * Create an injected adapter that reads the fixed DPAPI-backed development
 * credential store through a short-lived PowerShell probe. Stdout carries only
 * the password and must never be logged by callers.
 */
export function createDevBitwardenDpapiAdapter() {
  return async function devBitwardenDpapiAdapter(request) {
    if (request.item_ref !== FIXED_ITEM_REF || request.field !== 'password') {
      throw new DevBitwardenResolverError('unsupported_item_ref');
    }
    if (request.credential_class !== 'http_bearer' &&
        request.credential_class !== 'http_api_key_header' &&
        request.credential_class !== 'http_api_key_query') {
      throw new DevBitwardenResolverError('unsupported_credential_class');
    }
    if (process.platform !== 'win32') {
      throw new DevBitwardenResolverError('unsupported_platform');
    }

    const systemRoot = process.env.SystemRoot;
    if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
      throw new DevBitwardenResolverError('system_root_absent');
    }
    const powershell = path.join(
      systemRoot,
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe',
    );

    let stdout;
    let stderr;
    let code;
    try {
      const result = await execFileAsync(powershell, [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        SCRIPT,
        '-Field',
        'password',
        '-ExpectedPurposeSha256',
        FIXED_PURPOSE_SHA256,
      ], {
        windowsHide: true,
        timeout: 15000,
        maxBuffer: 64 * 1024,
        encoding: 'utf8',
        env: {
          SystemRoot: systemRoot,
          USERPROFILE: process.env.USERPROFILE,
          windir: process.env.windir,
          PATH: process.env.PATH,
        },
      });
      stdout = result.stdout;
      stderr = result.stderr;
      code = 0;
    } catch (error) {
      code = typeof error?.code === 'number' ? error.code : 1;
      stdout = typeof error?.stdout === 'string' ? error.stdout : '';
      stderr = typeof error?.stderr === 'string' ? error.stderr : '';
    }

    if (code !== 0 || typeof stderr === 'string' && stderr.length > 0) {
      throw new DevBitwardenResolverError('dpapi_probe_failed');
    }
    if (typeof stdout !== 'string' || stdout.length < 8 || stdout.length > 4096) {
      throw new DevBitwardenResolverError('invalid_secret');
    }
    return { credential: stdout };
  };
}

export const DEV_BITWARDEN_DPAPI_ITEM_REF = FIXED_ITEM_REF;
export const DEV_BITWARDEN_DPAPI_PURPOSE_SHA256 = FIXED_PURPOSE_SHA256;
