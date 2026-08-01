import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import { digestDesignatedRequirementStdout } from './macos-launchd-boundary-rules.mjs';

const execFileAsync = promisify(execFile);
const SNAPSHOT_PREFIX = 'bw-agent-code-snapshot-';
const SNAPSHOT_NAME = 'reviewed-helper';
const MAX_BINARY_BYTES = 64 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES = 64 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const TOOL_ENV = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  LANG: 'C',
  LC_ALL: 'C',
});

/**
 * Verify Apple signing and the designated requirement against an exclusive copy
 * of one already-open file snapshot. No caller-selected path or tool is accepted.
 */
export async function verifyMacosCodeSnapshot(bytes, expectedRequirementSha256) {
  if (process.platform !== 'darwin' || !Buffer.isBuffer(bytes) || bytes.byteLength < 1 ||
      bytes.byteLength > MAX_BINARY_BYTES || !SHA256.test(expectedRequirementSha256 ?? '')) {
    return false;
  }

  let root;
  let snapshotPath;
  let handle;
  let verified = false;
  let operationFailed = false;
  try {
    const tempBase = path.resolve(os.tmpdir());
    root = await fs.mkdtemp(path.join(tempBase, SNAPSHOT_PREFIX));
    snapshotPath = path.join(root, SNAPSHOT_NAME);
    await requirePrivateRoot(root, tempBase);

    const noFollow = requireNoFollow();
    handle = await fs.open(
      snapshotPath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_RDWR | noFollow,
      0o600,
    );
    await writeAll(handle, bytes);
    await handle.sync();

    const before = await handle.stat();
    const pathBefore = await fs.lstat(snapshotPath);
    const copiedBefore = await readHandleBytes(handle, before.size);
    if (!sameIdentity(before, pathBefore) || before.size !== bytes.byteLength ||
        (before.mode & 0o777) !== 0o600 || before.uid !== process.geteuid() ||
        !safeBufferDigestEqual(copiedBefore, bytes)) {
      throw new Error('unsafe snapshot');
    }

    await runCodesign(['--verify', '--strict', '--verbose=0', '--', snapshotPath]);
    const { stdout } = await runCodesign(['-d', '-r-', '--', snapshotPath]);
    const requirementDigest = digestDesignatedRequirementStdout(stdout);

    const after = await handle.stat();
    const pathAfter = await fs.lstat(snapshotPath);
    const copiedAfter = await readHandleBytes(handle, after.size);
    verified = requirementDigest !== null &&
      safeHexDigestEqual(requirementDigest, expectedRequirementSha256) &&
      sameIdentity(before, after) && sameIdentity(after, pathAfter) &&
      (after.mode & 0o777) === 0o600 && after.uid === process.geteuid() &&
      safeBufferDigestEqual(copiedBefore, copiedAfter);
  } catch {
    operationFailed = true;
    verified = false;
  } finally {
    let cleanupFailed = false;
    if (handle !== undefined) {
      try { await handle.close(); } catch { cleanupFailed = true; }
    }
    if (snapshotPath !== undefined) {
      try { await fs.unlink(snapshotPath); } catch { cleanupFailed = true; }
    }
    if (root !== undefined) {
      try { await fs.rmdir(root); } catch { cleanupFailed = true; }
    }
    if (cleanupFailed) throw new Error('snapshot cleanup failed');
  }
  return !operationFailed && verified;
}

async function requirePrivateRoot(root, tempBase) {
  const resolvedRoot = path.resolve(root);
  if (path.dirname(resolvedRoot) !== tempBase ||
      !path.basename(resolvedRoot).startsWith(SNAPSHOT_PREFIX)) {
    throw new Error('unsafe snapshot root');
  }
  const stat = await fs.lstat(resolvedRoot);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid() ||
      (stat.mode & 0o777) !== 0o700) {
    throw new Error('unsafe snapshot root');
  }
}

async function runCodesign(args) {
  const result = await execFileAsync('/usr/bin/codesign', args, {
    timeout: 3000,
    maxBuffer: MAX_TOOL_OUTPUT_BYTES,
    encoding: 'utf8',
    env: TOOL_ENV,
  });
  return { stdout: result.stdout, stderr: result.stderr };
}

async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset, offset);
    if (result.bytesWritten < 1) throw new Error('short write');
    offset += result.bytesWritten;
  }
}

async function readHandleBytes(handle, size) {
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_BINARY_BYTES) {
    throw new Error('invalid snapshot size');
  }
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await handle.read(bytes, offset, size - offset, offset);
    if (result.bytesRead < 1) throw new Error('short read');
    offset += result.bytesRead;
  }
  return bytes;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function safeBufferDigestEqual(left, right) {
  const leftDigest = createHash('sha256').update(left).digest();
  const rightDigest = createHash('sha256').update(right).digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function safeHexDigestEqual(left, right) {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function requireNoFollow() {
  if (!Number.isInteger(fsConstants.O_NOFOLLOW) || fsConstants.O_NOFOLLOW === 0) {
    throw new Error('unsupported nofollow');
  }
  return fsConstants.O_NOFOLLOW;
}
