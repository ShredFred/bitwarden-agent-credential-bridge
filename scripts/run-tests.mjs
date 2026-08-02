#!/usr/bin/env node
/**
 * Cross-platform unit-test entrypoint for CI and local `npm test`.
 * Avoids shell glob differences between Windows and Unix runners.
 */
import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const testDir = path.join(process.cwd(), 'test');
const files = (await readdir(testDir))
  .filter((name) => name.endsWith('.test.js'))
  .sort()
  .map((name) => path.join('test', name));

if (files.length < 1) {
  process.stderr.write('No test/*.test.js files found\n');
  process.exit(1);
}

const child = spawn(
  process.execPath,
  ['--test', '--test-concurrency=1', ...files],
  { stdio: 'inherit', windowsHide: true },
);

child.on('exit', (code, signal) => {
  if (signal) {
    process.exit(1);
  }
  process.exit(code ?? 1);
});
