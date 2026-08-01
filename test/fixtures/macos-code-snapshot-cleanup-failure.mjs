import { execFile } from 'node:child_process';
import { mkdirSync, rmdirSync, watch } from 'node:fs';
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
const watcher = watch(os.tmpdir(), (_event, filename) => {
  if (typeof filename !== 'string' || !filename.startsWith(PREFIX)) return;
  const candidate = path.join(os.tmpdir(), filename);
  try {
    mkdirSync(path.join(candidate, 'cleanup-blocker'), { mode: 0o700 });
    blockedRoot = candidate;
  } catch {
    // A later event retries if the verifier has not completed directory creation.
  }
});

let rejected = false;
try {
  await verifyMacosCodeSnapshot(bytes, requirementDigest);
} catch (error) {
  rejected = error instanceof Error && error.message === 'snapshot cleanup failed';
} finally {
  watcher.close();
  if (blockedRoot !== undefined) {
    rmdirSync(path.join(blockedRoot, 'cleanup-blocker'));
    rmdirSync(blockedRoot);
  }
}
if (!rejected || blockedRoot === undefined) process.exitCode = 1;
else process.stdout.write('cleanup_failure_rejected\n');
