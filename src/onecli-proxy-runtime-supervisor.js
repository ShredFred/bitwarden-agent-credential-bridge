import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { validateAgentToken } from './agent-token.js';
import {
  encodeOneCliAgentTokenFrame,
  encodeOneCliProxyPolicyFrame,
} from './onecli-proxy-runtime-frame.js';
import { validatePolicy } from './policy.js';

const MODULE_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(MODULE_DIRECTORY, '..');
const RUNTIME_ENTRYPOINT = path.join(REPOSITORY_ROOT, 'scripts', 'run-onecli-proxy.mjs');
const READY_TIMEOUT_MS = 5_000;
const GRACEFUL_CLOSE_TIMEOUT_MS = 5_000;
const TERMINATE_TIMEOUT_MS = 2_000;
const MAX_READY_BYTES = 512;

export class OneCliProxyRuntimeSupervisorError extends Error {
  constructor(code) {
    super(`OneCLI proxy runtime supervisor failed: ${code}`);
    this.name = 'OneCliProxyRuntimeSupervisorError';
    this.code = code;
  }
}

/**
 * Start the fixed repo-owned OneCLI proxy runtime. The returned handle contains
 * no token and accepts no executable, argv, environment, cwd, or descriptor input.
 */
export async function startOneCliProxyRuntimeSupervisor({ policy, agentToken }) {
  const token = validateAgentToken(agentToken);
  const validatedPolicy = validatePolicy(policy);
  if (validatedPolicy.version !== 4 || validatedPolicy.credential_class !== 'onecli_proxy') {
    throw new OneCliProxyRuntimeSupervisorError('unsupported_policy');
  }

  const tokenFrame = encodeOneCliAgentTokenFrame(token);
  const policyFrame = encodeOneCliProxyPolicyFrame(validatedPolicy);
  let child;
  try {
    child = spawn(process.execPath, [RUNTIME_ENTRYPOINT], {
      cwd: REPOSITORY_ROOT,
      env: Object.freeze({ LANG: 'C', LC_ALL: 'C' }),
      stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
  } catch {
    tokenFrame.fill(0);
    policyFrame.fill(0);
    throw new OneCliProxyRuntimeSupervisorError('spawn_failed');
  }

  let closeRequested = false;
  let closePromise;
  let outputViolation = false;
  let active = false;
  const exitResult = new Promise((resolve) => {
    child.once('exit', (code, signal) => {
      active = false;
      try { child.stdio[5]?.end(); } catch {}
      resolve(Object.freeze({
        expected: closeRequested && code === 0 && signal === null && !outputViolation,
        code,
        signal,
      }));
    });
  });
  const spawned = new Promise((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', () => reject(new OneCliProxyRuntimeSupervisorError('spawn_failed')));
  });

  const forceStop = async () => {
    closeRequested = true;
    try { child.stdio[5]?.end(); } catch {}
    let result = await waitFor(exitResult, GRACEFUL_CLOSE_TIMEOUT_MS);
    if (result !== null) return result;
    try { child.kill('SIGTERM'); } catch {}
    result = await waitFor(exitResult, TERMINATE_TIMEOUT_MS);
    if (result !== null) return result;
    try { child.kill('SIGKILL'); } catch {}
    return exitResult;
  };

  try {
    await spawned;
    await Promise.all([
      writeFrame(child.stdio[3], tokenFrame),
      writeFrame(child.stdio[4], policyFrame),
    ]);
    const rejectUnexpectedOutput = () => {
      outputViolation = true;
      active = false;
      try { child.stdio[5]?.end(); } catch {}
      try { child.kill('SIGKILL'); } catch {}
    };
    const ready = await readReadyRecord(
      child.stdout, child.stderr, exitResult, rejectUnexpectedOutput,
    );
    await verifyLoopbackListener(ready.host, ready.port);
    if (outputViolation || child.exitCode !== null || child.signalCode !== null) {
      throw new OneCliProxyRuntimeSupervisorError('protocol_violation');
    }
    active = true;

    const close = () => {
      if (closePromise === undefined) closePromise = forceStop();
      return closePromise;
    };
    const requireActive = (value) => {
      if (!active) throw new OneCliProxyRuntimeSupervisorError('runtime_inactive');
      return value;
    };
    return Object.freeze(Object.defineProperties({
      schema_version: 1,
      kind: 'onecli_proxy_runtime_supervisor',
      exit: exitResult,
      close,
    }, {
      host: { enumerable: true, get: () => requireActive(ready.host) },
      port: { enumerable: true, get: () => requireActive(ready.port) },
      proxy_url: { enumerable: true,
        get: () => requireActive(`http://${ready.host}:${ready.port}`) },
    }));
  } catch (error) {
    await forceStop();
    if (error instanceof OneCliProxyRuntimeSupervisorError) throw error;
    throw new OneCliProxyRuntimeSupervisorError('startup_failed');
  } finally {
    tokenFrame.fill(0);
    policyFrame.fill(0);
  }
}

async function writeFrame(stream, frame) {
  if (stream === null || stream === undefined) {
    throw new OneCliProxyRuntimeSupervisorError('ipc_unavailable');
  }
  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(new OneCliProxyRuntimeSupervisorError('ipc_write_failed'));
      else resolve();
    };
    stream.once('error', finish);
    stream.end(frame, finish);
  });
}

async function readReadyRecord(stdout, stderr, exitResult, onProtocolViolation) {
  if (stdout === null || stderr === null) {
    throw new OneCliProxyRuntimeSupervisorError('stdio_unavailable');
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let bytes = Buffer.alloc(0);
    const timer = setTimeout(() => fail('ready_timeout'), READY_TIMEOUT_MS);
    timer.unref();
    const cleanup = () => {
      clearTimeout(timer);
      stdout.off('data', onStdout);
      stderr.off('data', onStderr);
      stdout.off('error', onStdoutError);
      stderr.off('error', onStderrError);
    };
    const fail = (code) => {
      if (settled) return;
      settled = true;
      cleanup();
      bytes.fill(0);
      reject(new OneCliProxyRuntimeSupervisorError(code));
    };
    const onStdoutError = () => {
      if (settled) onProtocolViolation();
      else fail('stdio_unavailable');
    };
    const onStderrError = () => {
      if (settled) onProtocolViolation();
      else fail('stdio_unavailable');
    };
    const onStderr = () => {
      if (settled) onProtocolViolation();
      else fail('unexpected_stderr');
    };
    const onStdout = (chunk) => {
      if (settled) {
        onProtocolViolation();
        return;
      }
      const next = Buffer.concat([bytes, chunk]);
      bytes.fill(0);
      bytes = next;
      if (bytes.length > MAX_READY_BYTES) return fail('ready_too_large');
      const newline = bytes.indexOf(0x0a);
      if (newline === -1) return;
      if (newline !== bytes.length - 1) return fail('unexpected_stdout');
      let ready;
      try {
        const text = bytes.subarray(0, newline).toString('utf8');
        if (Buffer.byteLength(text, 'utf8') !== newline || text.includes('\0')) {
          return fail('invalid_ready_record');
        }
        ready = JSON.parse(text);
      } catch {
        return fail('invalid_ready_record');
      }
      if (!isValidReadyRecord(ready)) return fail('invalid_ready_record');
      settled = true;
      clearTimeout(timer);
      bytes.fill(0);
      resolve(ready);
    };
    stdout.on('data', onStdout);
    stderr.on('data', onStderr);
    stdout.once('error', onStdoutError);
    stderr.once('error', onStderrError);
    void exitResult.then(() => fail('exit_before_ready'));
  });
}

function verifyLoopbackListener(host, port) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => finish(false), 1_000);
    timer.unref();
    const finish = (connected) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (connected) resolve();
      else reject(new OneCliProxyRuntimeSupervisorError('listener_unavailable'));
    };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

function isValidReadyRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  return keys.length === 4 && keys[0] === 'host' && keys[1] === 'kind' &&
    keys[2] === 'port' && keys[3] === 'schema_version' &&
    value.schema_version === 1 && value.kind === 'onecli_proxy_ready' &&
    value.host === '127.0.0.1' && Number.isInteger(value.port) &&
    value.port >= 1 && value.port <= 65535;
}

async function waitFor(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
    timer.unref();
  });
  const result = await Promise.race([promise, timeout]);
  clearTimeout(timer);
  return result;
}
