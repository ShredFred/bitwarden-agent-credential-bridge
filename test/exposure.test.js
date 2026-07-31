import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startBroker } from '../src/broker.js';
import { generateFakeSentinel } from '../src/constants.js';
import { startFakeApi } from '../src/fake-api.js';
import { loadPolicy, withUpstream } from '../src/policy.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const samplePolicyPath = path.join(root, 'policies', 'sample-fake-service.json');

const SKIP_DIR_NAMES = new Set([
  '.git',
  'node_modules',
  '.cursor',
  'agent-transcripts',
]);

/**
 * @param {string} label
 * @param {unknown} value
 * @param {string} sentinel
 */
function assertNoSentinel(label, value, sentinel) {
  const text =
    typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  assert.ok(
    !text.includes(sentinel),
    `${label} must not contain the runtime sentinel`,
  );
}

/**
 * Recursively collect files under the worktree, skipping VCS/deps noise.
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
async function listWorktreeFiles(dir) {
  /** @type {string[]} */
  const files = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (SKIP_DIR_NAMES.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listWorktreeFiles(full)));
      continue;
    }
    if (entry.isFile() || entry.isSymbolicLink()) {
      files.push(full);
    }
  }
  return files;
}

describe('exposure: runtime sentinel must not reach agent-readable surfaces', () => {
  const sentinel = generateFakeSentinel();

  /** @type {Awaited<ReturnType<typeof startFakeApi>>} */
  let api;
  /** @type {Awaited<ReturnType<typeof startBroker>>} */
  let broker;
  /** @type {import('../src/broker.js').BrokerLogEntry[]} */
  let logs;
  /** @type {string[]} */
  let stdoutChunks;
  /** @type {string[]} */
  let stderrChunks;
  /** @type {typeof console.log} */
  let originalLog;
  /** @type {typeof console.error} */
  let originalError;
  /** @type {typeof console.info} */
  let originalInfo;
  /** @type {typeof console.warn} */
  let originalWarn;

  before(async () => {
    logs = [];
    stdoutChunks = [];
    stderrChunks = [];
    originalLog = console.log;
    originalError = console.error;
    originalInfo = console.info;
    originalWarn = console.warn;

    console.log = (...args) => {
      stdoutChunks.push(args.map(String).join(' '));
      originalLog(...args);
    };
    console.info = (...args) => {
      stdoutChunks.push(args.map(String).join(' '));
      originalInfo(...args);
    };
    console.warn = (...args) => {
      stderrChunks.push(args.map(String).join(' '));
      originalWarn(...args);
    };
    console.error = (...args) => {
      stderrChunks.push(args.map(String).join(' '));
      originalError(...args);
    };

    const sample = await loadPolicy(samplePolicyPath);
    api = await startFakeApi({
      sentinel,
      path: sample.path,
      method: sample.method,
    });
    const policy = withUpstream(sample, api.baseUrl);
    broker = await startBroker({
      policy,
      sentinel,
      log: (entry) => {
        logs.push(entry);
        // Mimic foreground logging without ever printing the sentinel.
        console.info(`[broker:${entry.level}] ${entry.message}`);
      },
    });
  });

  after(async () => {
    console.log = originalLog;
    console.error = originalError;
    console.info = originalInfo;
    console.warn = originalWarn;
    await broker.close();
    await api.close();
  });

  it('keeps the sentinel out of broker logs, stdout, stderr, and the HTTP response', async () => {
    const res = await fetch(broker.url, {
      method: 'GET',
      headers: { Authorization: 'Bearer caller-visible-only' },
    });
    const bodyText = await res.text();
    const headerObj = Object.fromEntries(res.headers.entries());

    assert.equal(res.status, 200);
    assertNoSentinel('response body', bodyText, sentinel);
    assertNoSentinel('response headers', headerObj, sentinel);
    assertNoSentinel('broker logs', logs, sentinel);
    assertNoSentinel('captured stdout', stdoutChunks.join('\n'), sentinel);
    assertNoSentinel('captured stderr', stderrChunks.join('\n'), sentinel);
    assertNoSentinel('process.env', process.env, sentinel);
  });

  it('keeps the runtime sentinel out of every tracked/worktree repo file', async () => {
    const files = await listWorktreeFiles(root);
    assert.ok(files.length > 0, 'expected worktree files to scan');

    for (const filePath of files) {
      let info;
      try {
        info = await stat(filePath);
      } catch {
        continue;
      }
      if (!info.isFile()) continue;
      // Skip unlikely huge/binary blobs; Phase 1 tree is text-only.
      if (info.size > 2_000_000) continue;

      const content = await readFile(filePath, 'utf8');
      assert.ok(
        !content.includes(sentinel),
        `worktree file must not contain runtime sentinel: ${path.relative(root, filePath)}`,
      );
    }
  });

  it('fails the suite if a simulated leak appears on a caller surface', () => {
    assert.throws(
      () => assertNoSentinel('leaky surface', { token: sentinel }, sentinel),
      /must not contain the runtime sentinel/,
    );
  });

  it('demo child process stdout/stderr do not contain a hard-coded sentinel pattern from source', async () => {
    // The demo generates its own sentinel; we assert the child never prints
    // credential-shaped Bearer tokens and exits cleanly.
    const demoPath = path.join(root, 'src', 'run-demo.js');
    const result = await runChild(process.execPath, [demoPath], { cwd: root });
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /demo status:\s*200/);
    assert.doesNotMatch(result.stdout, /Authorization:\s*Bearer\s+\S+/i);
    assert.doesNotMatch(result.stderr, /Authorization:\s*Bearer\s+\S+/i);
    assert.doesNotMatch(result.stdout, /bw-fake-[A-Za-z0-9_-]{20,}/);
    assert.doesNotMatch(result.stderr, /bw-fake-[A-Za-z0-9_-]{20,}/);
  });
});

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{ cwd: string }} opts
 * @returns {Promise<{ code: number | null, stdout: string, stderr: string }>}
 */
function runChild(command, args, opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: opts.cwd,
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}
