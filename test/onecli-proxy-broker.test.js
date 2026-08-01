import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, it } from 'node:test';
import { startOneCliProxyBroker } from '../src/onecli-proxy-broker.js';
import { BrokerError, startBroker } from '../src/broker.js';

const resources = [];
afterEach(async () => {
  while (resources.length > 0) await resources.pop()();
});

function policy(gateway) {
  return {
    version: 4,
    service: 'fake-onecli-gateway-chain',
    credential_class: 'onecli_proxy',
    bind: 'http://127.0.0.1:0',
    gateway,
    target_host: 'fake-target.test',
    target_port: 443,
    method: 'GET',
    path: '/v1/resource',
    agent_token: '{{credential}}',
  };
}

async function fakeGateway(expectedAuthorization, observations, response = {}) {
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    observations.push({ kind: 'request', url: req.url, headers: req.headers });
    if (req.headers['proxy-authorization'] !== expectedAuthorization) {
      res.writeHead(407); res.end(); return;
    }
    res.writeHead(response.status ?? 200, response.headers ?? { 'content-type': 'text/plain' });
    res.end(response.body ?? 'gateway-ok');
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('connect', (req, socket, head) => {
    observations.push({ kind: 'connect', url: req.url, headers: req.headers });
    if (req.headers['proxy-authorization'] !== expectedAuthorization) {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'); return;
    }
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) socket.write(head);
    socket.pipe(socket);
  });
  await listen(server);
  resources.push(() => close(server, sockets));
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

describe('OneCLI chained proxy broker', () => {
  it('cannot be accidentally routed through the target-credential broker', async () => {
    await assert.rejects(startBroker({
      policy: policy('http://127.0.0.1:10255'),
      sentinel: 'agent-token-0123456789',
    }), (error) => error instanceof BrokerError && error.code === 'wrong_broker');
  });

  it('places exactly one generated agent token on the gateway absolute-form leg', async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const authorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const observations = [];
    const gateway = await fakeGateway(authorization, observations);
    const broker = await startOneCliProxyBroker({ policy: policy(gateway), agentToken: token });
    resources.push(broker.close);
    const result = await proxyRequest(broker, {
      path: 'http://fake-target.test:443/v1/resource',
      headers: { accept: 'text/plain', 'x-forwarded-for': 'evil' },
    });
    assert.equal(result.status, 200);
    assert.equal(result.body, 'gateway-ok');
    assert.equal(observations.length, 1);
    assert.equal(observations[0].url, 'http://fake-target.test:443/v1/resource');
    assert.equal(observations[0].headers['proxy-authorization'], authorization);
    assert.equal(observations[0].headers['x-forwarded-for'], undefined);
    assert.equal(JSON.stringify(result).includes(token), false);
    assert.equal(JSON.stringify(broker.logs).includes(token), false);
  });

  it('chains an exact host:443 CONNECT and relays only opaque caller bytes', async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const authorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const observations = [];
    const gateway = await fakeGateway(authorization, observations);
    const broker = await startOneCliProxyBroker({ policy: policy(gateway), agentToken: token });
    resources.push(broker.close);
    const socket = net.connect(broker.port, broker.host);
    resources.push(async () => socket.destroy());
    socket.write('CONNECT fake-target.test:443 HTTP/1.1\r\nHost: fake-target.test:443\r\n\r\n');
    const head = await readUntil(socket, '\r\n\r\n');
    assert.match(head, /^HTTP\/1\.1 200 /);
    socket.write('opaque-client-bytes');
    const echoed = await readUntil(socket, 'opaque-client-bytes');
    assert.match(echoed, /opaque-client-bytes/);
    assert.equal(observations[0].kind, 'connect');
    assert.equal(observations[0].headers['proxy-authorization'], authorization);
    assert.equal(head.includes(token), false);
  });

  it('rejects target, method, query, caller auth, duplicate headers, and gateway redirects', async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const authorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const observations = [];
    const gateway = await fakeGateway(authorization, observations, { status: 302,
      headers: { location: 'http://evil.test/' } });
    const broker = await startOneCliProxyBroker({ policy: policy(gateway), agentToken: token });
    resources.push(broker.close);
    for (const request of [
      { path: 'http://other.test:443/v1/resource' },
      { path: 'http://fake-target.test:443/v1/resource?x=1' },
      { path: 'http://fake-target.test:443/v1/resource', method: 'POST' },
      { path: 'http://fake-target.test:443/v1/resource', headers: { authorization: 'Basic evil' } },
    ]) {
      const result = await proxyRequest(broker, request);
      assert.ok(result.status >= 400);
      assert.equal(JSON.stringify(result).includes(token), false);
    }
    const redirect = await proxyRequest(broker,
      { path: 'http://fake-target.test:443/v1/resource' });
    assert.equal(redirect.status, 502);
  });

  it('blocks gateway attempts to reflect raw or encoded agent-token material', async () => {
    for (const transform of [
      (value) => value,
      (value) => Buffer.from(`${value}:`).toString('base64'),
      (value) => Buffer.from(value).toString('base64'),
    ]) {
      const token = `agent-${randomBytes(24).toString('base64url')}`;
      const authorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
      const gateway = await fakeGateway(authorization, [], { body: transform(token) });
      const broker = await startOneCliProxyBroker({ policy: policy(gateway), agentToken: token });
      const result = await proxyRequest(broker,
        { path: 'http://fake-target.test:443/v1/resource' });
      assert.equal(result.status, 502);
      assert.equal(JSON.stringify(result).includes(token), false);
      await broker.close();
    }
  });

  it('rejects encoded gateway responses before compressed token material reaches the caller', async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const authorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const gateway = await fakeGateway(authorization, [], {
      headers: { 'content-encoding': 'gzip', 'content-type': 'text/plain' },
      body: gzipSync(token),
    });
    const broker = await startOneCliProxyBroker({ policy: policy(gateway), agentToken: token });
    resources.push(broker.close);
    const result = await proxyRequest(broker,
      { path: 'http://fake-target.test:443/v1/resource' });
    assert.equal(result.status, 502);
    assert.equal(JSON.stringify(result).includes(token), false);
  });

  it('rejects headerless compressed token material and survives caller abort during CONNECT', async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const authorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const gateway = await fakeGateway(authorization, [], { body: gzipSync(token) });
    const broker = await startOneCliProxyBroker({ policy: policy(gateway), agentToken: token });
    resources.push(broker.close);
    const result = await proxyRequest(broker,
      { path: 'http://fake-target.test:443/v1/resource' });
    assert.equal(result.status, 502);
    const socket = net.connect(broker.port, broker.host);
    socket.once('connect', () => {
      socket.write('CONNECT fake-target.test:443 HTTP/1.1\r\nHost: fake-target.test:443\r\n\r\n');
      socket.destroy();
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    const healthy = await proxyRequest(broker,
      { path: 'http://fake-target.test:443/v1/resource' });
    assert.equal(healthy.status, 502);
  });

  it('aborts absolute-form gateway work when the caller disconnects', async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const authorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const sockets = new Set();
    let aborted = false;
    const server = http.createServer((req) => {
      assert.equal(req.headers['proxy-authorization'], authorization);
      req.once('aborted', () => { aborted = true; });
    });
    server.on('connection', (socket) => {
      sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    });
    await listen(server);
    resources.push(() => close(server, sockets));
    const address = server.address();
    const broker = await startOneCliProxyBroker({
      policy: policy(`http://127.0.0.1:${address.port}`), agentToken: token,
    });
    resources.push(broker.close);
    const client = http.request({ host: broker.host, port: broker.port,
      path: 'http://fake-target.test:443/v1/resource', agent: false });
    client.once('error', () => {});
    client.end();
    await new Promise((resolve) => server.once('request', resolve));
    client.destroy();
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.equal(aborted || sockets.size === 0, true);
  });
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
}
function close(server, sockets = new Set()) {
  return new Promise((resolve) => {
    for (const socket of sockets) socket.destroy();
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    server.close(() => resolve());
  });
}
function proxyRequest(broker, options) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: broker.host, port: broker.port, method: options.method ?? 'GET',
      path: options.path, headers: options.headers ?? {}, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.once('error', reject);
    req.end();
  });
}
function readUntil(socket, marker) {
  return new Promise((resolve, reject) => {
    let value = '';
    const onData = (chunk) => {
      value += chunk.toString('utf8');
      if (value.includes(marker)) { cleanup(); resolve(value); }
    };
    const onError = (error) => { cleanup(); reject(error); };
    const cleanup = () => { socket.off('data', onData); socket.off('error', onError); };
    socket.on('data', onData); socket.on('error', onError);
  });
}
