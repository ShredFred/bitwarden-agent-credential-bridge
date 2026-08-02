#!/usr/bin/env node
/**
 * Operator-approved disposable browser form-login live gate runner.
 * Default mode exercises the loopback fake site end-to-end (no network).
 * Non-loopback HTTPS requires an explicit hostname argument and only validates
 * the branded gate + origin pin — it does not auto-login to third-party sites.
 */
import process from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateFakeSentinel } from '../src/constants.js';
import {
  buildBrowserFormLoginLiveGate,
  parseLiveHttpsLoginOrigin,
} from '../src/browser-form-login-live-gate.mjs';
import { startBrowserSessionBroker } from '../src/browser-session-broker.mjs';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import { loadPolicy, withBind, withLoginOrigin } from '../src/policy.js';

const samplePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'policies',
  'sample-fake-browser-login.json',
);

const mode = process.argv[2] ?? 'loopback';

if (mode === 'loopback') {
  const username = 'user_abcdefgh';
  const password = generateFakeSentinel();
  const site = await startFakeLoginSite({
    credentials: { username, password },
    hiddenFields: { csrf: 'token-1' },
  });
  let broker;
  try {
    broker = await startBrowserSessionBroker({
      policy: withBind(withLoginOrigin(await loadPolicy(samplePath), site.baseUrl), 'http://127.0.0.1:0'),
      credentials: { username, password },
    });
    const replay = await fetch(broker.replayUrl);
    const ok = replay.status === 200;
    // Drain the body so the upstream socket can close cleanly on Windows.
    await replay.arrayBuffer();
    process.stdout.write(`${JSON.stringify({
      ok,
      mode: 'loopback',
      logged_in: broker.logged_in,
      origin_bound: broker.origin_bound,
      authorization_ready: false,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
    })}\n`);
    process.exitCode = ok ? 0 : 1;
  } finally {
    if (broker) await broker.close().catch(() => {});
    await site.close().catch(() => {});
  }
} else if (mode === 'pin-https') {
  const hostname = process.argv[3];
  if (typeof hostname !== 'string' || hostname.length < 1) {
    process.stdout.write(`${JSON.stringify({ ok: false, code: 'hostname_required', authorization_ready: false })}\n`);
    process.exitCode = 1;
  } else {
    const gate = buildBrowserFormLoginLiveGate(hostname);
    const origin = parseLiveHttpsLoginOrigin(`https://${hostname}`, gate);
    process.stdout.write(`${JSON.stringify({
      ok: true,
      mode: 'pin-https',
      hostname: origin.hostname,
      live_login_executed: false,
      authorization_ready: false,
      note: 'origin pin only; third-party login requires a separate disposable account runbook',
    })}\n`);
    process.exitCode = 0;
  }
} else {
  process.stdout.write(`${JSON.stringify({ ok: false, code: 'invalid_mode', authorization_ready: false })}\n`);
  process.exitCode = 1;
}
