import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  buildMacosLaunchdLifecyclePackage,
  MacosLaunchdLifecyclePackageError,
} from '../../src/macos-launchd-lifecycle-package.mjs';

const PREFIX = 'bw-agent-launchd-package-';
const originalRmdir = fs.rmdir;
const blockedRoots = new Set();
fs.rmdir = async (target, ...args) => {
  if (path.basename(target).startsWith(PREFIX)) {
    blockedRoots.add(target);
    throw new Error('injected package cleanup failure');
  }
  return originalRmdir.call(fs, target, ...args);
};

let rejected = false;
try {
  await buildMacosLaunchdLifecyclePackage();
} catch (error) {
  rejected = error instanceof MacosLaunchdLifecyclePackageError && error.code === 'cleanup_failed';
} finally {
  fs.rmdir = originalRmdir;
  for (const root of blockedRoots) await originalRmdir.call(fs, root);
}

const residue = (await fs.readdir(await fs.realpath(os.tmpdir())))
  .filter((name) => name.startsWith(PREFIX));
if (!rejected || blockedRoots.size !== 2 || residue.length !== 0) process.exitCode = 1;
else process.stdout.write('package_cleanup_failure_rejected\n');
