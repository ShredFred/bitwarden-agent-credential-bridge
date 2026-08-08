import fs from 'node:fs';
import process from 'node:process';

export const TOKEN_FRAME_FD = 3;
export const POLICY_FRAME_FD = 4;
export const PARENT_LEASE_FD = 5;
export const MAX_RUNTIME_POLICY_BYTES = 16 * 1024;
export const RUNTIME_FRAME_TIMEOUT_MS = 5_000;

const TOKEN_MAGIC = Buffer.from('BWAT', 'ascii');
const POLICY_MAGIC = Buffer.from('BWAP', 'ascii');

export class OneCliProxyRuntimeFrameError extends Error {
  constructor(code) {
    super(`OneCLI proxy runtime frame failed: ${code}`);
    this.name = 'OneCliProxyRuntimeFrameError';
    this.code = code;
  }
}

export async function readOneCliAgentTokenFrame(fd = TOKEN_FRAME_FD) {
  const payload = await readFrame(fd, TOKEN_MAGIC, 512);
  try {
    if (payload.some((byte) => byte < 0x21 || byte > 0x7e)) {
      throw new OneCliProxyRuntimeFrameError('invalid_token_encoding');
    }
    return payload.toString('ascii');
  } finally {
    payload.fill(0);
  }
}

export function requireDistinctRuntimeIpcDescriptors(
  tokenFd = TOKEN_FRAME_FD,
  policyFd = POLICY_FRAME_FD,
  leaseFd = PARENT_LEASE_FD,
) {
  const identities = [tokenFd, policyFd, leaseFd].map((fd) => {
    const stat = requireIpcDescriptor(fd);
    return `${stat.dev}:${stat.ino}`;
  });
  if (new Set(identities).size !== identities.length) {
    throw new OneCliProxyRuntimeFrameError('descriptors_not_distinct');
  }
}

export async function readOneCliProxyPolicyFrame(fd = POLICY_FRAME_FD) {
  const payload = await readFrame(fd, POLICY_MAGIC, MAX_RUNTIME_POLICY_BYTES);
  try {
    const text = payload.toString('utf8');
    if (Buffer.byteLength(text, 'utf8') !== payload.length || text.includes('\0')) {
      throw new OneCliProxyRuntimeFrameError('invalid_policy_encoding');
    }
    return JSON.parse(text);
  } catch (error) {
    if (error instanceof OneCliProxyRuntimeFrameError) throw error;
    throw new OneCliProxyRuntimeFrameError('invalid_policy_json');
  } finally {
    payload.fill(0);
  }
}

export function encodeOneCliAgentTokenFrame(token) {
  const payload = Buffer.from(token, 'ascii');
  return encodeFrame(TOKEN_MAGIC, payload);
}

export function encodeOneCliProxyPolicyFrame(policy) {
  return encodeFrame(POLICY_MAGIC, Buffer.from(JSON.stringify(policy), 'utf8'));
}

export function monitorParentLease(fd, onEnd) {
  requireIpcDescriptor(fd);
  const stream = fs.createReadStream(null, { fd, autoClose: true });
  let ended = false;
  const finish = () => {
    if (ended) return;
    ended = true;
    onEnd();
  };
  stream.on('data', () => {
    stream.destroy();
    finish();
  });
  stream.once('end', finish);
  stream.once('error', finish);
  return () => stream.destroy();
}

async function readFrame(fd, expectedMagic, maximumPayload) {
  requireIpcDescriptor(fd);
  const maximumFrame = 9 + maximumPayload;
  const chunks = [];
  let total = 0;
  const stream = fs.createReadStream(null, { fd, autoClose: true });
  const bytes = await new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      stream.destroy();
      settleReject('frame_timeout');
    }, RUNTIME_FRAME_TIMEOUT_MS);
    timer.unref();
    const cleanup = () => clearTimeout(timer);
    const settleReject = (code) => {
      if (settled) return;
      settled = true;
      cleanup();
      for (const chunk of chunks) chunk.fill(0);
      reject(new OneCliProxyRuntimeFrameError(code));
    };
    stream.on('data', (chunk) => {
      total += chunk.length;
      if (total > maximumFrame) {
        stream.destroy();
        settleReject('frame_too_large');
      } else chunks.push(Buffer.from(chunk));
    });
    stream.once('error', () => settleReject('frame_read_failed'));
    stream.once('end', () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks, total));
      for (const chunk of chunks) chunk.fill(0);
    });
  });
  try {
    if (bytes.length < 9 || !bytes.subarray(0, 4).equals(expectedMagic) ||
        bytes[4] !== 1) throw new OneCliProxyRuntimeFrameError('invalid_frame_header');
    const declared = bytes.readUInt32BE(5);
    if (declared < 1 || declared > maximumPayload || bytes.length !== 9 + declared) {
      throw new OneCliProxyRuntimeFrameError('invalid_frame_length');
    }
    return Buffer.from(bytes.subarray(9));
  } finally {
    bytes.fill(0);
  }
}

function encodeFrame(magic, payload) {
  const frame = Buffer.alloc(9 + payload.length);
  magic.copy(frame, 0);
  frame[4] = 1;
  frame.writeUInt32BE(payload.length, 5);
  payload.copy(frame, 9);
  return frame;
}

function requireIpcDescriptor(fd) {
  if (!Number.isInteger(fd) || fd < 3) {
    throw new OneCliProxyRuntimeFrameError('invalid_descriptor');
  }
  let stat;
  try { stat = fs.fstatSync(fd); } catch {
    throw new OneCliProxyRuntimeFrameError('missing_descriptor');
  }
  // Node child_process implements extra `stdio: "pipe"` channels as Unix
  // socketpairs on macOS and as FIFOs/pipes on other supported platforms.
  if (stat.isFIFO() || stat.isSocket()) {
    return stat;
  }
  // Windows: libuv reports anonymous stdio pipes with the FIFO type bit
  // (S_IFIFO / 0x1000), but Node's Stats.isFIFO() stays false. Accept only
  // that mode class and keep files, devices, directories, and links rejected.
  if (process.platform === 'win32' && isWindowsAnonymousPipeStat(stat)) {
    return stat;
  }
  throw new OneCliProxyRuntimeFrameError('descriptor_not_ipc');
}

const WINDOWS_S_IFMT = 0xf000;
const WINDOWS_S_IFIFO = 0x1000;

function isWindowsAnonymousPipeStat(stat) {
  return (stat.mode & WINDOWS_S_IFMT) === WINDOWS_S_IFIFO &&
    !stat.isFile() &&
    !stat.isDirectory() &&
    !stat.isCharacterDevice() &&
    !stat.isBlockDevice() &&
    !stat.isSymbolicLink();
}
