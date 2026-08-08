import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { afterEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  encodeOneCliAgentTokenFrame,
  encodeOneCliProxyPolicyFrame,
  OneCliProxyRuntimeFrameError,
  readOneCliAgentTokenFrame,
} from '../src/onecli-proxy-runtime-frame.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const children = new Set();
const servers = new Set();
afterEach(async () => {
  for (const child of children) child.kill('SIGKILL');
  children.clear();
  for (const server of servers) await closeServer(server);
  servers.clear();
});

describe('OneCLI proxy inherited runtime', () => {
  it('runs a complete child-process request without token argv/env/file/output exposure', {
    timeout: 10000,
  }, async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const expectedAuthorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const gateway = http.createServer((req, res) => {
      assert.equal(req.headers['proxy-authorization'], expectedAuthorization);
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('runtime-ok');
    });
    servers.add(gateway);
    await listen(gateway);
    const gatewayAddress = gateway.address();
    const policy = {
      version: 4, service: 'runtime-fixture', credential_class: 'onecli_proxy',
      bind: 'http://127.0.0.1:0', gateway: `http://127.0.0.1:${gatewayAddress.port}`,
      target_host: 'fake-target.test', target_port: 443, method: 'GET',
      path: '/v1/resource', agent_token: '{{credential}}',
    };
    const child = spawn(process.execPath, [path.join(root, 'scripts', 'run-onecli-proxy.mjs')], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '' },
    });
    children.add(child);
    const exitPromise = exited(child);
    let completeStdout = '';
    let completeStderr = '';
    child.stdout.on('data', (chunk) => { completeStdout += chunk; });
    child.stderr.on('data', (chunk) => { completeStderr += chunk; });
    child.stdio[3].end(encodeOneCliAgentTokenFrame(token));
    child.stdio[4].end(encodeOneCliProxyPolicyFrame(policy));
    const readyLine = await readLine(child.stdout);
    const ready = JSON.parse(readyLine);
    assert.deepEqual(Object.keys(ready).sort(), ['host', 'kind', 'port', 'schema_version']);
    assert.equal(ready.kind, 'onecli_proxy_ready');
    const response = await request({ host: ready.host, port: ready.port,
      path: 'http://fake-target.test:443/v1/resource' });
    assert.equal(response.status, 200);
    assert.equal(response.body, 'runtime-ok');
    assert.equal(child.spawnargs.join(' ').includes(token), false);
    assert.equal(readyLine.includes(token), false);
    child.stdio[5].end();
    const result = await exitPromise;
    children.delete(child);
    assert.equal(result.code, 0);
    assert.equal(result.signal, null);
    assert.equal(result.stderr.includes(token), false);
    assert.equal(result.stderr, '');
    assert.equal(completeStdout.includes(token), false);
    assert.equal(completeStderr.includes(token), false);
    assert.equal(completeStderr, '');
    assert.equal(await connectFails(ready.host, ready.port), true);
  });

  it('rejects missing frames and any command-line arguments without diagnostics', async () => {
    for (const args of [[], ['unexpected']]) {
      const child = spawn(process.execPath,
        [path.join(root, 'scripts', 'run-onecli-proxy.mjs'), ...args], {
          cwd: root, stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
          env: { PATH: process.env.PATH ?? '' },
        });
      children.add(child);
      if (args.length === 0) {
        child.stdio[3].end(Buffer.from('bad'));
        child.stdio[4].end(Buffer.from('bad'));
      }
      child.stdio[5].end();
      const result = await exited(child);
      children.delete(child);
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, '');
    }
  });

  it('rejects trailing frame bytes silently', async () => {
    for (const trailingFd of [3, 4]) {
      const child = spawn(process.execPath, [path.join(root, 'scripts', 'run-onecli-proxy.mjs')], {
        cwd: root, stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH ?? '' },
      });
      children.add(child);
      const tokenFrame = encodeOneCliAgentTokenFrame('agent-token-0123456789');
      const policyFrame = encodeOneCliProxyPolicyFrame({ version: 4 });
      child.stdio[3].end(trailingFd === 3
        ? Buffer.concat([tokenFrame, Buffer.from([0])]) : tokenFrame);
      child.stdio[4].end(trailingFd === 4
        ? Buffer.concat([policyFrame, Buffer.from([0])]) : policyFrame);
      child.stdio[5].end();
      const result = await exited(child);
      children.delete(child);
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, '');
    }
  });

  it('exits without a ready record when the parent lease ends before frames arrive', async () => {
    const child = spawn(process.execPath, [path.join(root, 'scripts', 'run-onecli-proxy.mjs')], {
      cwd: root, stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '' },
    });
    children.add(child);
    const exitPromise = exited(child);
    child.stdio[5].end();
    await new Promise((resolve) => setTimeout(resolve, 25));
    child.stdio[3].end(encodeOneCliAgentTokenFrame('agent-token-0123456789'));
    child.stdio[4].end(encodeOneCliProxyPolicyFrame({
      version: 4, service: 'lease-fixture', credential_class: 'onecli_proxy',
      bind: 'http://127.0.0.1:0', gateway: 'http://127.0.0.1:10255',
      target_host: 'fake-target.test', target_port: 443, method: 'GET',
      path: '/v1/resource', agent_token: '{{credential}}',
    }));
    const result = await exitPromise;
    children.delete(child);
    assert.equal(result.code, 72);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  });

  it('rejects device descriptors and duplicate inherited IPC identities', async () => {
    const devicePath = process.platform === 'win32' ? '\\\\.\\NUL' : '/dev/null';
    const deviceFd = fs.openSync(devicePath, 'r');
    try {
      await assert.rejects(readOneCliAgentTokenFrame(deviceFd),
        (error) => error instanceof OneCliProxyRuntimeFrameError &&
          error.code === 'descriptor_not_ipc');
    } finally {
      fs.closeSync(deviceFd);
    }

    if (process.platform === 'win32') {
      const filePath = path.join(root, 'package.json');
      const fileFd = fs.openSync(filePath, 'r');
      try {
        await assert.rejects(readOneCliAgentTokenFrame(fileFd),
          (error) => error instanceof OneCliProxyRuntimeFrameError &&
            error.code === 'descriptor_not_ipc');
      } finally {
        fs.closeSync(fileFd);
      }
    }

    const moduleUrl = new URL('../src/onecli-proxy-runtime-frame.js', import.meta.url).href;
    const code = `import { requireDistinctRuntimeIpcDescriptors as check } from ${JSON.stringify(moduleUrl)};` +
      `try { check(3, 3, 5); process.exitCode = 1; } catch (e) { process.exitCode = e.code === 'descriptors_not_distinct' ? 0 : 2; }`;
    const child = spawn(process.execPath, ['--input-type=module', '-e', code], {
      stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'ignore', 'pipe'],
      env: { PATH: process.env.PATH ?? '' },
    });
    children.add(child);
    child.stdio[3].end();
    child.stdio[5].end();
    const result = await exited(child);
    children.delete(child);
    assert.equal(result.code, 0);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  });
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
}
function closeServer(server) {
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}
function readLine(stream) {
  return new Promise((resolve, reject) => {
    let text = '';
    const onData = (chunk) => {
      text += chunk.toString('utf8');
      const newline = text.indexOf('\n');
      if (newline !== -1) { cleanup(); resolve(text.slice(0, newline)); }
    };
    const cleanup = () => { stream.off('data', onData); stream.off('error', reject); };
    stream.on('data', onData); stream.on('error', reject);
  });
}
function request(options) {
  return new Promise((resolve, reject) => {
    const req = http.request({ ...options, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode,
        body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.once('error', reject); req.end();
  });
}
function exited(child) {
  return new Promise((resolve) => {
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('exit', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}
function connectFails(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect(port, host);
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', () => resolve(true));
  });
}
