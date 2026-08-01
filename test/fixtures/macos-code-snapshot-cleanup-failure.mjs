import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { verifyMacosCodeSnapshot } from '../../src/macos-code-snapshot-verifier.mjs';
import { digestDesignatedRequirementStdout } from '../../src/macos-launchd-boundary-rules.mjs';

const execFileAsync = promisify(execFile);
const PREFIX = 'bw-agent-code-snapshot-';
const bytes = await fs.readFile('/bin/ls');
const { stdout } = await execFileAsync('/usr/bin/codesign', ['-d', '-r-', '--', '/bin/ls'], {
  encoding: 'utf8', maxBuffer: 64 * 1024,
});
const requirementDigest = digestDesignatedRequirementStdout(stdout);
let blockedRoot;
const originalRmdir = fs.rmdir;
fs.rmdir = async (target, ...args) => {
  if (path.basename(target).startsWith(PREFIX)) {
    blockedRoot = target;
    throw new Error('injected cleanup failure');
  }
  return originalRmdir.call(fs, target, ...args);
};

let rejected = false;
try {
  await verifyMacosCodeSnapshot(bytes, requirementDigest);
} catch (error) {
  rejected = error instanceof Error && error.message === 'snapshot cleanup failed';
} finally {
  fs.rmdir = originalRmdir;
  if (blockedRoot !== undefined) {
    await originalRmdir.call(fs, blockedRoot);
  }
}
if (!rejected || blockedRoot === undefined) process.exitCode = 1;
else process.stdout.write('cleanup_failure_rejected\n');
