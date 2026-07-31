import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { parseHelperRequest } from '../src/helper-protocol.mjs';

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_LAUNCHER_BYTES = 1024 * 1024;
const INHERITED_LAUNCHER_FD = 3;

main();

function main() {
  try {
    const requestBytes = readBounded(0, MAX_REQUEST_BYTES);
    const request = parseHelperRequest(requestBytes);
    const launcherBytes = readBounded(INHERITED_LAUNCHER_FD, MAX_LAUNCHER_BYTES);
    const digest = createHash('sha256').update(launcherBytes).digest('hex');
    const verified = launcherBytes.byteLength === request.launcher.byte_length &&
      digest === request.launcher.sha256;
    writeResult(verified ? 'verified' : 'launcher_handle_mismatch', verified);
    if (!verified) process.exitCode = 1;
  } catch {
    writeResult('verification_failed', false);
    process.exitCode = 1;
  }
}

function readBounded(fd, maxBytes) {
  const chunks = [];
  let total = 0;
  const buffer = Buffer.allocUnsafe(16 * 1024);
  while (true) {
    const count = fs.readSync(fd, buffer, 0, buffer.length, null);
    if (count === 0) break;
    total += count;
    if (total > maxBytes) throw new Error('bounded input exceeded');
    chunks.push(Buffer.from(buffer.subarray(0, count)));
  }
  if (total === 0) throw new Error('empty input');
  return Buffer.concat(chunks, total);
}

function writeResult(code, verified) {
  process.stdout.write(`${JSON.stringify({
    protocol_version: 1,
    code,
    request_verified: verified,
    launcher_handle_verified: verified,
  })}\n`);
}
