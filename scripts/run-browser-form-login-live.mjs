#!/usr/bin/env node
/**
 * Operator-approved disposable browser form-login live runner.
 *
 * Modes:
 *   loopback     — local fake site (no network)
 *   pin-https    — brand/pin an HTTPS hostname only (no login)
 *   public-demo  — live HTTPS login against the-internet.herokuapp.com
 *                  (public automation demo credentials; requires explicit flag)
 *
 * Does not read personal/company Bitwarden. authorization_ready stays false.
 */
import process from 'node:process';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { generateFakeSentinel } from '../src/constants.js';
import {
  buildBrowserFormLoginLiveGate,
  parseLiveHttpsLoginOrigin,
} from '../src/browser-form-login-live-gate.mjs';
import { startBrowserSessionBroker } from '../src/browser-session-broker.mjs';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';
import {
  loadPolicy,
  validateLiveBrowserFormLoginPolicy,
  withBind,
  withLoginOrigin,
} from '../src/policy.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const samplePath = path.join(root, 'policies', 'sample-fake-browser-login.json');
const demoPolicyPath = path.join(root, 'policies', 'sample-disposable-public-demo-login.json');

const PUBLIC_DEMO_HOST = 'the-internet.herokuapp.com';
const PUBLIC_DEMO_USER = 'tomsmith';
const PUBLIC_DEMO_PASSWORD = 'SuperSecretPassword!';
const APPROVAL_FLAG = '--i-approve-disposable-public-demo';

const mode = process.argv[2] ?? 'loopback';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

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
    await replay.arrayBuffer();
    emit({
      ok,
      mode: 'loopback',
      logged_in: broker.logged_in,
      origin_bound: broker.origin_bound,
      live_login_executed: true,
      authorization_ready: false,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
    }, ok ? 0 : 1);
  } finally {
    if (broker) await broker.close().catch(() => {});
    await site.close().catch(() => {});
  }
} else if (mode === 'pin-https') {
  const hostname = process.argv[3];
  if (typeof hostname !== 'string' || hostname.length < 1) {
    emit({ ok: false, code: 'hostname_required', authorization_ready: false }, 1);
  } else {
    const gate = buildBrowserFormLoginLiveGate(hostname);
    const origin = parseLiveHttpsLoginOrigin(`https://${hostname}`, gate);
    emit({
      ok: true,
      mode: 'pin-https',
      hostname: origin.hostname,
      live_login_executed: false,
      authorization_ready: false,
    });
  }
} else if (mode === 'public-demo') {
  if (!process.argv.includes(APPROVAL_FLAG)) {
    emit({
      ok: false,
      code: 'approval_flag_required',
      required_flag: APPROVAL_FLAG,
      target_host: PUBLIC_DEMO_HOST,
      authorization_ready: false,
      note: 'Explicit operator approval flag required before contacting the public demo host',
    }, 1);
  } else {
    const gate = buildBrowserFormLoginLiveGate(PUBLIC_DEMO_HOST);
    parseLiveHttpsLoginOrigin(`https://${PUBLIC_DEMO_HOST}`, gate);
    const raw = JSON.parse(await readFile(demoPolicyPath, 'utf8'));
    const policy = validateLiveBrowserFormLoginPolicy(raw, gate);
    let broker;
    try {
      broker = await startBrowserSessionBroker({
        policy,
        credentials: { username: PUBLIC_DEMO_USER, password: PUBLIC_DEMO_PASSWORD },
        liveGate: gate,
      });
      const replay = await fetch(broker.replayUrl);
      const body = await replay.text();
      const lower = body.toLowerCase();
      const ok = replay.status === 200 &&
        lower.includes('secure area') &&
        !body.includes(PUBLIC_DEMO_PASSWORD) &&
        !lower.includes('login page');
      emit({
        ok,
        mode: 'public-demo',
        target_host: PUBLIC_DEMO_HOST,
        logged_in: broker.logged_in === true,
        origin_bound: broker.origin_bound === true,
        replay_status: replay.status,
        live_login_executed: true,
        authorization_ready: false,
        personal_vault_forbidden: true,
        company_vault_forbidden: true,
        helper_vault_free: true,
      }, ok ? 0 : 1);
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error
        ? error.code
        : 'live_login_failed';
      emit({
        ok: false,
        mode: 'public-demo',
        target_host: PUBLIC_DEMO_HOST,
        code,
        live_login_executed: true,
        authorization_ready: false,
      }, 1);
    } finally {
      if (broker) await broker.close().catch(() => {});
    }
  }
} else {
  emit({ ok: false, code: 'invalid_mode', authorization_ready: false }, 1);
}
