import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildApplyManifest } from '../src/apply-manifest.mjs';
import { createDisposableWorkspace } from '../src/disposable-workspace.mjs';
import { buildHelperRequest } from '../src/helper-protocol.mjs';
import {
  InheritedLauncherTransferError,
  parseWorkerResult,
  verifyInheritedLauncherTransfer,
} from '../src/inherited-launcher-transfer.mjs';

async function fixture() {
  const workspace = await createDisposableWorkspace();
  const launcherBytes = Buffer.from(`fake inherited launcher ${workspace.nonce}`);
  const launcherSha256 = createHash('sha256').update(launcherBytes).digest('hex');
  const manifest = buildApplyManifest({
    platform: workspace.platform,
    homedir: workspace.homedir,
    env: workspace.env,
    launcherBytes,
    observed: {
      config_dir: 'absent', config_file: 'absent', install_root: 'absent', bin_dir: 'absent',
      launcher: { kind: 'absent' },
    },
  });
  const request = buildHelperRequest({
    requestId: 'a'.repeat(32), workspace, manifest, launcherSha256,
    launcherByteLength: launcherBytes.byteLength,
  });
  return { workspace, launcherBytes, request };
}

async function cleanup(workspace) {
  await fs.rm(workspace.root, { recursive: true, force: true });
}

describe('inherited read-only launcher transfer', () => {
  it('passes a real inherited handle to a child that independently verifies bytes and request', async () => {
    const value = await fixture();
    try {
      const result = await verifyInheritedLauncherTransfer({
        workspace: value.workspace,
        requestBytes: value.request.bytes,
        launcherBytes: value.launcherBytes,
      });
      assert.deepEqual(result, { request_verified: true, launcher_handle_verified: true });
      assert.equal(JSON.stringify(result).includes(value.launcherBytes.toString('utf8')), false);
      const entries = await fs.readdir(value.workspace.root);
      assert.equal(entries.some((name) => name.startsWith('.launcher-transfer-')), false);
    } finally {
      await cleanup(value.workspace);
    }
  });

  it('rejects a launcher that does not match the request before spawning', async () => {
    const value = await fixture();
    let spawned = false;
    try {
      await assert.rejects(
        verifyInheritedLauncherTransfer({
          workspace: value.workspace,
          requestBytes: value.request.bytes,
          launcherBytes: Buffer.from('different launcher'),
        }, { spawnImpl: () => { spawned = true; } }),
        (error) => error instanceof InheritedLauncherTransferError &&
          error.code === 'request_binding_mismatch',
      );
      assert.equal(spawned, false);
    } finally {
      await cleanup(value.workspace);
    }
  });

  it('accepts no caller-supplied handle, path, evidence, or extra input field', async () => {
    const value = await fixture();
    try {
      for (const extra of [
        { launcherPath: 'C:\\unsafe' }, { launcherFd: 3 },
        { peerEvidence: { different_principal: true } },
      ]) {
        await assert.rejects(
          verifyInheritedLauncherTransfer({
            workspace: value.workspace,
            requestBytes: value.request.bytes,
            launcherBytes: value.launcherBytes,
            ...extra,
          }),
          (error) => error instanceof InheritedLauncherTransferError && error.code === 'invalid_input',
        );
      }
      const mutableWorkspace = { ...value.workspace, env: { ...value.workspace.env } };
      await assert.rejects(
        verifyInheritedLauncherTransfer({
          workspace: mutableWorkspace,
          requestBytes: value.request.bytes,
          launcherBytes: value.launcherBytes,
        }),
        (error) => error instanceof InheritedLauncherTransferError && error.code === 'invalid_input',
      );
    } finally {
      await cleanup(value.workspace);
    }
  });

  it('copies request and launcher buffers before the first asynchronous boundary', async () => {
    const value = await fixture();
    const requestBytes = Buffer.from(value.request.bytes);
    const launcherBytes = Buffer.from(value.launcherBytes);
    try {
      const pending = verifyInheritedLauncherTransfer({
        workspace: value.workspace, requestBytes, launcherBytes,
      });
      requestBytes.fill(0);
      launcherBytes.fill(0);
      assert.deepEqual(await pending, {
        request_verified: true,
        launcher_handle_verified: true,
      });
    } finally {
      await cleanup(value.workspace);
    }
  });

  it('makes a real child exit non-zero on an inherited-handle digest mismatch', async () => {
    const value = await fixture();
    const mismatchPath = path.join(value.workspace.root, 'mismatch-launcher');
    let handle;
    try {
      await fs.writeFile(mismatchPath, Buffer.from('wrong inherited bytes'), { flag: 'wx' });
      handle = await fs.open(mismatchPath, 'r');
      const workerPath = path.join(
        path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'inherited-launcher-worker.mjs',
      );
      const child = spawn(process.execPath, [workerPath], {
        cwd: value.workspace.root, env: {}, windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe', handle.fd],
      });
      const stdout = [];
      const stderr = [];
      child.stdout.on('data', (chunk) => stdout.push(chunk));
      child.stderr.on('data', (chunk) => stderr.push(chunk));
      child.stdin.end(value.request.bytes);
      const exitCode = await new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('close', resolve);
      });
      assert.equal(exitCode, 1);
      assert.equal(Buffer.concat(stderr).byteLength, 0);
      const result = JSON.parse(Buffer.concat(stdout).toString('utf8'));
      assert.deepEqual(result, {
        protocol_version: 1,
        code: 'launcher_handle_mismatch',
        request_verified: false,
        launcher_handle_verified: false,
      });
      assert.equal(JSON.stringify(result).includes('wrong inherited bytes'), false);
    } finally {
      await handle?.close();
      await cleanup(value.workspace);
    }
  });

  it('parses only the exact value-free success response', () => {
    const valid = Buffer.from('{"protocol_version":1,"code":"verified","request_verified":true,"launcher_handle_verified":true}\n');
    assert.deepEqual(parseWorkerResult(valid), {
      request_verified: true,
      launcher_handle_verified: true,
    });
    for (const invalid of [
      Buffer.from(''), Buffer.from('{}'), Buffer.from('not json'),
      Buffer.from(' {"protocol_version":1,"code":"verified","request_verified":true,"launcher_handle_verified":true}\n'),
      Buffer.from('{"protocol_version":1,"code":"verified","request_verified":true,"launcher_handle_verified":true,"path":"C:/leak"}'),
      Buffer.from('{"protocol_version":1,"code":"launcher_handle_mismatch","request_verified":false,"launcher_handle_verified":false}'),
    ]) {
      assert.throws(
        () => parseWorkerResult(invalid),
        (error) => error instanceof InheritedLauncherTransferError && error.code === 'invalid_worker_output',
      );
    }
  });

  it('puts only the worker path in argv and no launcher material in argv or env', async () => {
    const value = await fixture();
    let invocation;
    const spawnImpl = (executable, args, options) => {
      invocation = { executable, args, options };
      return fakeSpawn({
        stdout: '{"protocol_version":1,"code":"verified","request_verified":true,"launcher_handle_verified":true}\n',
        code: 0,
      })();
    };
    try {
      await verifyInheritedLauncherTransfer({
        workspace: value.workspace,
        requestBytes: value.request.bytes,
        launcherBytes: value.launcherBytes,
      }, { spawnImpl });
      assert.equal(invocation.args.length, 1);
      assert.deepEqual(invocation.options.env, {});
      assert.equal(JSON.stringify(invocation.args).includes(value.launcherBytes.toString('utf8')), false);
      assert.equal(JSON.stringify(invocation.options.env).includes(value.launcherBytes.toString('utf8')), false);
      assert.equal(invocation.options.cwd, value.workspace.root);
      assert.equal(typeof invocation.options.stdio[3], 'number');
    } finally {
      await cleanup(value.workspace);
    }
  });

  it('fails closed on worker noise, failure, timeout, and oversized output', async () => {
    const value = await fixture();
    const cases = [
      [fakeSpawn({ stdout: 'not json', code: 0 }), 'invalid_worker_output'],
      [fakeSpawn({ stderr: 'raw SID S-1-5-21', code: 0 }), 'worker_failed'],
      [fakeSpawn({ stdout: 'x'.repeat(2048), code: 0 }), 'invalid_worker_output'],
      [fakeSpawn({ neverCloses: true }), 'worker_timeout'],
    ];
    try {
      for (const [spawnImpl, code] of cases) {
        await assert.rejects(
          verifyInheritedLauncherTransfer({
            workspace: value.workspace,
            requestBytes: value.request.bytes,
            launcherBytes: value.launcherBytes,
          }, { spawnImpl, timeoutMs: 100 }),
          (error) => error instanceof InheritedLauncherTransferError && error.code === code &&
            !error.message.includes('S-1-5-21'),
        );
      }
    } finally {
      await cleanup(value.workspace);
    }
  });
});

function fakeSpawn({ stdout = '', stderr = '', code = 0, neverCloses = false }) {
  return () => {
    const listeners = new Map();
    const stream = (content) => ({
      on(event, callback) {
        if (event === 'data' && content !== '') queueMicrotask(() => callback(Buffer.from(content)));
        return this;
      },
    });
    const child = {
      stdout: stream(stdout),
      stderr: stream(stderr),
      stdin: { on() {}, end() {} },
      on(event, callback) {
        listeners.set(event, callback);
        if (event === 'close' && !neverCloses) setTimeout(() => callback(code), 5);
        return this;
      },
      kill() {},
    };
    return child;
  };
}
