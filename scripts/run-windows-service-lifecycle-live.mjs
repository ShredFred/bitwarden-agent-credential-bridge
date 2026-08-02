#!/usr/bin/env node
import process from 'node:process';
import { runOperatorApprovedWindowsServiceLifecycleLiveTest } from '../src/windows-service-lifecycle-live.mjs';

if (process.platform !== 'win32') {
  console.error('{"ok":false,"code":"unsupported_platform"}');
  process.exit(2);
}

try {
  const report = await runOperatorApprovedWindowsServiceLifecycleLiveTest();
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exit(report.live_test_verified ? 0 : 1);
} catch (error) {
  const code = error && typeof error === 'object' && 'code' in error ? error.code : 'live_test_failed';
  process.stdout.write(`${JSON.stringify({ ok: false, code })}\n`);
  process.exit(1);
}
