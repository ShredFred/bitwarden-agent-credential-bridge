import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startBroker } from './broker.js';
import { generateFakeSentinel } from './constants.js';
import { startFakeApi } from './fake-api.js';
import { loadPolicy, withUpstream } from './policy.js';

/**
 * Foreground demo: generate a runtime sentinel, start fake API + broker,
 * call through the broker bind URL, print only caller-visible results.
 * Exits non-zero if the sentinel leaks into stdout/stderr or broker logs.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const policyPath = path.join(root, 'policies', 'sample-fake-service.json');

const sentinel = generateFakeSentinel();
const samplePolicy = await loadPolicy(policyPath);

const api = await startFakeApi({
  sentinel,
  path: samplePolicy.path,
  method: samplePolicy.method,
});

const policy = withUpstream(samplePolicy, api.baseUrl);
/** @type {import('./broker.js').BrokerLogEntry[]} */
const brokerLogs = [];

const broker = await startBroker({
  policy,
  sentinel,
  log: (entry) => {
    brokerLogs.push(entry);
  },
});

let exitCode = 0;

try {
  const response = await fetch(broker.url, {
    method: policy.method,
    headers: { Authorization: 'Bearer caller-must-be-stripped' },
  });
  const bodyText = await response.text();

  const surfaces = [
    `status:${response.status}`,
    bodyText,
    JSON.stringify(Object.fromEntries(response.headers.entries())),
    JSON.stringify(brokerLogs),
  ];

  for (const surface of surfaces) {
    if (surface.includes(sentinel)) {
      console.error('REFUSING TO PRINT: sentinel leaked into a caller-visible surface');
      exitCode = 1;
      break;
    }
  }

  if (exitCode === 0) {
    console.log('demo status:', response.status);
    console.log('demo body:', bodyText);
  }
} finally {
  await broker.close();
  await api.close();
}

process.exitCode = exitCode;
