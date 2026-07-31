import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  WindowsSecurityProbeError,
  createWindowsSecurityAdapter,
  parseProbeResult,
} from '../src/windows-security-adapter.mjs';

const valid = JSON.stringify({ reparsePoint: false, ownerCurrentUser: true, writableByOtherUsers: false });

describe('Windows security adapter', () => {
  it('accepts exactly three boolean result fields', () => {
    assert.deepEqual(parseProbeResult(valid), {
      reparsePoint: false,
      ownerCurrentUser: true,
      writableByOtherUsers: false,
    });
    assert.deepEqual(parseProbeResult(`\uFEFF${valid}`), JSON.parse(valid));
  });

  it('rejects malformed, extra, noisy, and stderr output without reflecting it', () => {
    for (const [stdout, stderr] of [
      ['', ''],
      ['not-json sensitive', ''],
      [valid + '\nextra', ''],
      [JSON.stringify({ reparsePoint: false, ownerCurrentUser: true }), ''],
      [JSON.stringify({ reparsePoint: false, ownerCurrentUser: true, writableByOtherUsers: false, sid: 'sensitive' }), ''],
      [JSON.stringify({ reparsePoint: 0, ownerCurrentUser: true, writableByOtherUsers: false }), ''],
      [valid, 'sensitive stderr'],
    ]) {
      assert.throws(
        () => parseProbeResult(stdout, stderr),
        (error) => error instanceof WindowsSecurityProbeError && error.code === 'invalid_output' && !error.message.includes('sensitive'),
      );
    }
  });

  it('uses argument-array process hardening and fixed resource limits', async () => {
    let invocation;
    const adapter = createWindowsSecurityAdapter({
      powershellPath: 'powershell-test.exe',
      scriptPath: 'C:\\safe probe.ps1',
      timeoutMs: 1234,
      execFileImpl: (file, args, options, callback) => {
        invocation = { file, args, options };
        callback(null, valid, '');
      },
    });
    const target = 'C:\\target with spaces & metacharacters';
    assert.deepEqual(await adapter(target), JSON.parse(valid));
    assert.equal(invocation.file, 'powershell-test.exe');
    assert.equal(invocation.args.at(-1), target);
    assert.deepEqual(invocation.args.slice(0, 7), ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\\safe probe.ps1']);
    assert.deepEqual(invocation.options, { windowsHide: true, timeout: 1234, maxBuffer: 4096, encoding: 'utf8' });
  });

  it('maps process failures and timeouts to stable value-free errors', async () => {
    for (const processError of [Object.assign(new Error('sensitive output'), { killed: false }), Object.assign(new Error('sensitive timeout'), { killed: true })]) {
      const adapter = createWindowsSecurityAdapter({ execFileImpl: (_file, _args, _options, callback) => callback(processError, 'secret stdout', 'secret stderr') });
      await assert.rejects(
        () => adapter('C:\\target'),
        (error) => error instanceof WindowsSecurityProbeError && !error.message.includes('sensitive') && !error.message.includes('secret'),
      );
    }
  });

  it('runs the repo-owned probe against a harmless temporary file on Windows', { skip: process.platform !== 'win32' }, async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-win-probe-'));
    const target = path.join(dir, 'probe.txt');
    try {
      await fs.writeFile(target, 'non-secret');
      const result = await createWindowsSecurityAdapter()(target);
      assert.equal(typeof result.reparsePoint, 'boolean');
      assert.equal(typeof result.ownerCurrentUser, 'boolean');
      assert.equal(typeof result.writableByOtherUsers, 'boolean');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
