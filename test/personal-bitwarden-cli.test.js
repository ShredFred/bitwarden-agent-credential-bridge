import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const liveScript = path.join(root, 'scripts', 'run-personal-bitwarden-live.mjs');
const laptopScript = path.join(root, 'scripts', 'run-windows-laptop-ready.mjs');

function runNode(scriptPath, args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scriptPath, ...args], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

describe('personal Bitwarden CLI fail-closed', () => {
  it('rejects live runner without the approval flag', async () => {
    const result = await runNode(liveScript);
    assert.notEqual(result.code, 0);
    const payload = JSON.parse(result.stdout.trim().split(/\r?\n/).pop());
    assert.equal(payload.code, 'approval_flag_required');
    assert.equal(payload.authorization_ready, false);
    assert.equal(payload.company_vault_forbidden, true);
    assert.equal(payload.helper_vault_free, true);
  });

  it('rejects laptop-ready without any approval flag', async () => {
    const result = await runNode(laptopScript);
    assert.notEqual(result.code, 0);
    const payload = JSON.parse(result.stdout.trim().split(/\r?\n/).pop());
    assert.equal(payload.code, 'approval_flag_required');
    assert.equal(payload.authorization_ready, false);
  });
});
