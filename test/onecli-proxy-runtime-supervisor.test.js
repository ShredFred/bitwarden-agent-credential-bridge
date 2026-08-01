import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, it } from 'node:test';
import {
  OneCliProxyRuntimeSupervisorError,
  startOneCliProxyRuntimeSupervisor,
} from '../src/onecli-proxy-runtime-supervisor.js';

const servers = new Set();
const supervisors = new Set();
afterEach(async () => {
  for (const supervisor of supervisors) await supervisor.close();
  supervisors.clear();
  for (const server of servers) await closeServer(server);
  servers.clear();
});

describe('OneCLI proxy runtime supervisor', () => {
  it('starts only the fixed runtime and closes it through the inherited lease', async () => {
    const token = `agent-${randomBytes(24).toString('base64url')}`;
    const expectedAuthorization = `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const gateway = http.createServer((req, res) => {
      assert.equal(req.headers['proxy-authorization'], expectedAuthorization);
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('supervised-ok');
    });
    servers.add(gateway);
    await listen(gateway);
    const supervisor = await startOneCliProxyRuntimeSupervisor({
      agentToken: token,
      policy: policyFor(gateway.address().port),
    });
    supervisors.add(supervisor);

    assert.equal(Object.isFrozen(supervisor), true);
    assert.deepEqual(Object.keys(supervisor).sort(), [
      'close', 'exit', 'host', 'kind', 'port', 'proxy_url', 'schema_version',
    ]);
    assert.equal(supervisor.host, '127.0.0.1');
    assert.equal(supervisor.proxy_url, `http://127.0.0.1:${supervisor.port}`);
    assert.equal(JSON.stringify(supervisor).includes(token), false);
    const endpoint = { host: supervisor.host, port: supervisor.port };
    const response = await request({
      host: supervisor.host,
      port: supervisor.port,
      path: 'http://fake-target.test:443/v1/resource',
    });
    assert.deepEqual(response, { status: 200, body: 'supervised-ok' });

    const result = await supervisor.close();
    supervisors.delete(supervisor);
    assert.deepEqual(result, { expected: true, code: 0, signal: null });
    assert.throws(() => supervisor.proxy_url, (error) =>
      error instanceof OneCliProxyRuntimeSupervisorError && error.code === 'runtime_inactive');
    assert.equal(await connectFails(endpoint.host, endpoint.port), true);
  });

  it('rejects invalid runtime inputs before starting a child', async () => {
    await assert.rejects(startOneCliProxyRuntimeSupervisor({
      agentToken: 'too-short', policy: policyFor(10255),
    }));
    await assert.rejects(startOneCliProxyRuntimeSupervisor({
      agentToken: 'agent-token-0123456789',
      policy: { version: 1 },
    }));
  });

  it('fails closed when the gateway prevents the runtime from becoming ready', async () => {
    const blocker = net.createServer();
    servers.add(blocker);
    await listen(blocker);
    await assert.rejects(startOneCliProxyRuntimeSupervisor({
      agentToken: 'agent-token-0123456789',
      policy: {
        ...policyFor(10255),
        bind: `http://127.0.0.1:${blocker.address().port}`,
      },
    }), (error) => error instanceof OneCliProxyRuntimeSupervisorError &&
      ['exit_before_ready', 'ready_timeout'].includes(error.code));
  });
});

function policyFor(gatewayPort) {
  return {
    version: 4,
    service: 'supervisor-fixture',
    credential_class: 'onecli_proxy',
    bind: 'http://127.0.0.1:0',
    gateway: `http://127.0.0.1:${gatewayPort}`,
    target_host: 'fake-target.test',
    target_port: 443,
    method: 'GET',
    path: '/v1/resource',
    agent_token: '{{credential}}',
  };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
}

function closeServer(server) {
  server.closeAllConnections?.();
  return new Promise((resolve) => server.close(() => resolve()));
}

function request(options) {
  return new Promise((resolve, reject) => {
    const req = http.request({ ...options, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode,
        body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.once('error', reject);
    req.end();
  });
}

function connectFails(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect(port, host);
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', () => resolve(true));
  });
}
