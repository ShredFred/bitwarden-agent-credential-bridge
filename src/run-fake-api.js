import { generateFakeSentinel } from './constants.js';
import { startFakeApi } from './fake-api.js';

/**
 * Foreground fake API process. Generates a runtime sentinel that is never printed.
 * Prefer `npm run start:demo` for an end-to-end run that also starts the broker.
 */

const sentinel = generateFakeSentinel();
const api = await startFakeApi({ sentinel });

console.log(`fake API listening at ${api.baseUrl}`);
console.log('GET /v1/resource requires Authorization: Bearer <runtime-sentinel>');
console.log('Runtime sentinel is not printed (exposure contract).');
console.log('Press Ctrl+C to stop.');

const shutdown = async () => {
  await api.close();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
