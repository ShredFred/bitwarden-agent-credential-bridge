#!/usr/bin/env node
import process from 'node:process';
import { validateAgentToken } from '../src/agent-token.js';
import { startOneCliProxyBroker } from '../src/onecli-proxy-broker.js';
import {
  monitorParentLease,
  PARENT_LEASE_FD,
  POLICY_FRAME_FD,
  readOneCliAgentTokenFrame,
  readOneCliProxyPolicyFrame,
  requireDistinctRuntimeIpcDescriptors,
  TOKEN_FRAME_FD,
} from '../src/onecli-proxy-runtime-frame.js';
import { validatePolicy } from '../src/policy.js';

async function main() {
  if (process.argv.length !== 2) return 64;
  requireDistinctRuntimeIpcDescriptors();
  let broker;
  let closing = false;
  let closingPromise;
  let leaseEnded = false;
  let readyEmitted = false;
  let stopLeaseMonitor = () => {};
  const startupAbort = new AbortController();
  const close = () => {
    if (broker === undefined) return Promise.resolve(true);
    if (closingPromise !== undefined) return closingPromise;
    closing = true;
    closingPromise = (async () => {
      try {
        await broker.close();
        process.exitCode = 0;
        return true;
      } catch {
        process.exitCode = 71;
        try { broker.server.closeAllConnections?.(); } catch {}
        try { broker.server.close(); } catch {}
        try { broker.server.unref(); } catch {}
        process.exit(71);
      }
    })();
    return closingPromise;
  };
  const terminate = () => {
    stopLeaseMonitor();
    void close().then(() => process.exit(process.exitCode ?? 0));
  };
  process.on('SIGTERM', terminate);
  process.on('SIGINT', terminate);
  stopLeaseMonitor = monitorParentLease(PARENT_LEASE_FD, () => {
    leaseEnded = true;
    startupAbort.abort();
    if (readyEmitted) {
      void close().then(() => process.exit(process.exitCode ?? 0));
    } else {
      void close();
    }
  });
  try {
    const [tokenResult, policyResult] = await Promise.all([
      readOneCliAgentTokenFrame(TOKEN_FRAME_FD),
      readOneCliProxyPolicyFrame(POLICY_FRAME_FD),
    ]);
    const token = validateAgentToken(tokenResult);
    const policy = validatePolicy(policyResult);
    if (policy.version !== 4 || policy.credential_class !== 'onecli_proxy') {
      stopLeaseMonitor();
      return 65;
    }
    if (leaseEnded) {
      stopLeaseMonitor();
      return 72;
    }
    try {
      broker = await startOneCliProxyBroker({
        policy, agentToken: token, signal: startupAbort.signal,
      });
    } catch (error) {
      if (leaseEnded) {
        stopLeaseMonitor();
        return 72;
      }
      throw error;
    }
    if (leaseEnded) {
      const closed = await close();
      stopLeaseMonitor();
      return closed ? 72 : 71;
    }
    if (leaseEnded || closing) {
      const closed = await close();
      stopLeaseMonitor();
      return closed ? 72 : 71;
    }
    process.stdout.once('error', () => {
      stopLeaseMonitor();
      void close().then(() => process.exit(70));
    });
    readyEmitted = true;
    process.stdout.write(JSON.stringify({
      schema_version: 1,
      kind: 'onecli_proxy_ready',
      host: broker.host,
      port: broker.port,
    }) + '\n');
    return null;
  } catch (error) {
    stopLeaseMonitor();
    if (broker !== undefined) await close();
    throw error;
  }
}

try {
  const code = await main();
  if (code !== null) process.exitCode = code;
} catch {
  process.exit(70);
}
