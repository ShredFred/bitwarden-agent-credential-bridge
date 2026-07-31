import os from 'node:os';
import process from 'node:process';
import { deriveUserRoots } from '../src/bootstrap-plan.mjs';
import { auditBootstrapHost } from '../src/bootstrap-preflight.mjs';
import { createWindowsSecurityAdapter } from '../src/windows-security-adapter.mjs';

async function main() {
  let report;
  try {
    const roots = deriveUserRoots(process.platform, os.homedir(), process.env);
    report = await auditBootstrapHost({
      platform: process.platform,
      roots,
      currentUid: typeof process.getuid === 'function' ? process.getuid() : undefined,
      windowsSecurity:
        process.platform === 'win32'
          ? createWindowsSecurityAdapter()
          : undefined,
    });
  } catch {
    report = {
      ready: false,
      checks: [{ id: 'bootstrap_preflight', status: 'failed', reason: 'preflight_failed' }],
    };
  }
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = report.ready ? 0 : 1;
}

await main();
