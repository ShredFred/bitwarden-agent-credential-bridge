import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { generateFakeSentinel } from '../src/constants.js';
import {
  BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
  parseBridgeOwnedBrowserCli,
  SM_RESOLVE_APPROVAL_FLAG,
} from '../src/bridge-owned-browser-cli.mjs';
import { startBridgeOwnedBrowserForBinding } from '../src/bridge-owned-browser-session.mjs';
import { BridgeOwnedBrowserError } from '../src/bridge-owned-browser.mjs';
import { loadOperationalBindingsFile } from '../src/operational-bridge.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const script = path.join(root, 'scripts', 'run-bridge-owned-browser-sm.mjs');

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout });
    });
  });
}

describe('bridge-owned browser SM CLI', () => {
  it('requires both approval flags and a valid alias', () => {
    assert.equal(parseBridgeOwnedBrowserCli(['node', 'x']).code, 'approval_flag_required');
    assert.equal(
      parseBridgeOwnedBrowserCli(['node', 'x', SM_RESOLVE_APPROVAL_FLAG]).code,
      'approval_flag_required',
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
      ]).code,
      'invalid_alias',
    );
    assert.deepEqual(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
      ]),
      { ok: true, alias: 'phq_web', driver: 'fetch', headless: true },
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias=phq_web',
        '--driver=playwright',
      ]).headless,
      true,
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
        '--driver',
        'playwright',
        '--headed',
      ]).headless,
      false,
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
        '--driver',
        'playwright',
        '--headless',
      ]).headless,
      true,
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
        '--headed',
        '--headless',
      ]).code,
      'invalid_request',
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
        '--headed',
      ]).code,
      'invalid_request',
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
        '--screenshot',
      ]).code,
      'invalid_request',
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
        '--driver',
        'playwright',
        '--devtools',
      ]).code,
      'invalid_request',
    );
    assert.equal(
      parseBridgeOwnedBrowserCli([
        SM_RESOLVE_APPROVAL_FLAG,
        BRIDGE_OWNED_BROWSER_APPROVAL_FLAG,
        '--alias',
        'phq_web',
        '--driver',
        'chrome',
      ]).code,
      'invalid_request',
    );
  });

  it('exits with approval_flag_required without starting SM', async () => {
    const result = await runCli([]);
    assert.equal(result.code, 1);
    const payload = JSON.parse(result.stdout.split('\n')[0]);
    assert.equal(payload.ok, false);
    assert.equal(payload.code, 'approval_flag_required');
    assert.equal(payload.authorization_ready, false);
    assert.ok(payload.required_flags.includes(BRIDGE_OWNED_BROWSER_APPROVAL_FLAG));
  });

  it('starts a loopback owned browser from a fake resolver without leaking secrets', async () => {
    const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    const credentials = { username: 'user_abcdefgh', password: generateFakeSentinel() };
    const started = await startBridgeOwnedBrowserForBinding({
      repoRoot: root,
      bindings,
      alias: 'demo_browser',
      resolveSecret: async (binding) => ({
        credential_class: binding.credential_class,
        username: credentials.username,
        password: credentials.password,
      }),
    });
    try {
      assert.equal(started.runtime, 'bridge_owned_browser');
      assert.equal(started.session.agent_cdp_absent, true);
      const contract = await (await fetch(`${started.session.baseUrl}/contract`)).json();
      assert.ok(contract.allowed_ops.includes('inject_login'));
      assert.equal(contract.screenshot_password_entry_forbidden, true);
      assert.equal(contract.screenshot_unsupported, true);
      assert.equal(contract.screenshot_json_pixels_absent, true);
      assert.equal(contract.headless, true);
      assert.equal(contract.driver, 'fetch');
      assert.ok(contract.allowed_ops.includes('screenshot'));
      const snap = await (await fetch(`${started.session.baseUrl}/snapshot`)).json();
      await fetch(`${started.session.baseUrl}/select_targets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          generation: snap.generation,
          username_index: 0,
          password_index: 1,
          submit_index: 2,
        }),
      });
      const injected = await (await fetch(`${started.session.baseUrl}/inject_login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ generation: snap.generation }),
      })).json();
      assert.equal(injected.logged_in, true);
      const surface = JSON.stringify({ contract, snap, injected, handle: {
        baseUrl: started.session.baseUrl,
        alias: started.alias,
      } });
      assert.equal(surface.includes(credentials.password), false);
      assert.equal(surface.includes('token-demo_browser'), false);
    } finally {
      await started.close();
    }
  });

  it('rejects non-browser aliases', async () => {
    const bindings = await loadOperationalBindingsFile(root, 'samples/operational/bindings.json');
    await assert.rejects(
      () => startBridgeOwnedBrowserForBinding({
        repoRoot: root,
        bindings,
        alias: 'demo_bearer',
        resolveSecret: async () => ({ credential_class: 'http_bearer', credential: 'x' }),
      }),
      (error) => error instanceof BridgeOwnedBrowserError && error.code === 'wrong_broker',
    );
  });
});
