import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_REQUIRED_PORTS,
  runOneCliPreflight,
} from '../scripts/preflight-onecli.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

describe('OneCLI read-only preflight', () => {
  it('reports ready when tools exist and required Linux ports are free', async () => {
    const calls = [];
    const result = await runOneCliPreflight({
      platform: 'linux',
      runner: async (command, args, options) => {
        calls.push({ command, args, options });
        return { code: 0, stdout: '' };
      },
    });

    assert.equal(result.ready, true);
    assert.deepEqual(
      result.checks.map(({ id, status }) => ({ id, status })),
      [
        { id: 'platform', status: 'supported' },
        { id: 'docker', status: 'available' },
        { id: 'docker_compose', status: 'available' },
        { id: 'aac', status: 'available' },
        { id: 'port.dashboard', status: 'free' },
        { id: 'port.gateway', status: 'free' },
        { id: 'port.postgres', status: 'free' },
      ],
    );
    assert.equal(calls.length, 6);
    assert.deepEqual(calls[0].args, ['--version']);
    assert.deepEqual(calls[1].args, ['compose', 'version']);
    assert.deepEqual(calls[2].args, ['--version']);
    assert.ok(
      calls
        .slice(3)
        .every(
          ({ command, args, options }) =>
            command === 'ss' &&
            args.includes('-ltn') &&
            options.captureStdout === true,
        ),
    );
  });

  it('turns missing tools into structured not-ready checks', async () => {
    const result = await runOneCliPreflight({
      platform: 'linux',
      requiredPorts: [],
      runner: async () => {
        throw new Error('spawn ENOENT: generated-fake-sensitive-path');
      },
    });

    assert.equal(result.ready, false);
    for (const id of ['docker', 'docker_compose', 'aac']) {
      assert.deepEqual(
        result.checks.find((check) => check.id === id),
        { id, ready: false, status: 'missing_or_failed' },
      );
    }
    assert.doesNotMatch(JSON.stringify(result), /ENOENT|sensitive-path|stack/i);
  });

  it('reports an occupied port without returning command output', async () => {
    const sensitiveOutput = 'generated-fake-port-inventory-must-not-appear';
    const result = await runOneCliPreflight({
      platform: 'linux',
      requiredPorts: [{ name: 'dashboard', port: 10254 }],
      runner: async (command) =>
        command === 'ss'
          ? { code: 0, stdout: sensitiveOutput, stderr: sensitiveOutput }
          : { code: 0, stdout: sensitiveOutput, stderr: sensitiveOutput },
    });

    assert.equal(result.ready, false);
    assert.deepEqual(
      result.checks.find((check) => check.id === 'port.dashboard'),
      { id: 'port.dashboard', ready: false, status: 'in_use', port: 10254 },
    );
    assert.ok(!JSON.stringify(result).includes(sensitiveOutput));
  });

  it('does not invoke host commands for unsupported platforms', async () => {
    let calls = 0;
    const result = await runOneCliPreflight({
      platform: 'freebsd',
      runner: async () => {
        calls += 1;
        return { code: 0 };
      },
    });

    assert.equal(calls, 0);
    assert.deepEqual(result, {
      version: 1,
      kind: 'onecli-readiness-preflight',
      ready: false,
      checks: [
        {
          id: 'platform',
          ready: false,
          status: 'unsupported_platform',
          platform: 'freebsd',
        },
      ],
    });
  });

  it('uses status-only local-port probes on Windows and macOS', async () => {
    for (const [platform, expectedCommand, freeCode] of [
      ['win32', 'powershell.exe', 0],
      ['darwin', 'lsof', 1],
    ]) {
      const calls = [];
      const result = await runOneCliPreflight({
        platform,
        requiredPorts: [{ name: 'dashboard', port: 10254 }],
        runner: async (command, args, options) => {
          calls.push({ command, args, options });
          if (command === expectedCommand) {
            return { code: freeCode, stdout: 'ignored-output' };
          }
          return { code: 0, stdout: 'ignored-output' };
        },
      });

      assert.equal(result.ready, true);
      assert.equal(calls.at(-1).command, expectedCommand);
      assert.equal(calls.at(-1).options.captureStdout, false);
      assert.doesNotMatch(JSON.stringify(result), /ignored-output/);
    }
  });

  it('rejects invalid required-port definitions without probing them', async () => {
    let portProbeCalls = 0;
    const result = await runOneCliPreflight({
      platform: 'linux',
      requiredPorts: [
        { name: 'bad', port: 0 },
        { name: '', port: 10254 },
      ],
      runner: async (command) => {
        if (command === 'ss') portProbeCalls += 1;
        return { code: 0, stdout: '' };
      },
    });

    assert.equal(portProbeCalls, 0);
    assert.equal(result.ready, false);
    assert.equal(
      result.checks.filter(
        (check) => check.status === 'invalid_port_requirement',
      ).length,
      2,
    );
  });

  it('defines only the documented default local ports', () => {
    assert.deepEqual(DEFAULT_REQUIRED_PORTS, [
      { name: 'dashboard', port: 10254 },
      { name: 'gateway', port: 10255 },
      { name: 'postgres', port: 5432 },
    ]);
  });

  it('does not read process environment values or expose command output', async () => {
    const source = await readFile(
      path.join(root, 'scripts', 'preflight-onecli.mjs'),
      'utf8',
    );
    assert.doesNotMatch(source, /process\.env|env\s*:/);

    const sensitiveValue = 'generated-fake-environment-value-never-output';
    const result = await runOneCliPreflight({
      platform: 'linux',
      requiredPorts: [],
      runner: async () => ({
        code: 0,
        stdout: sensitiveValue,
        stderr: sensitiveValue,
      }),
    });
    assert.equal(result.ready, true);
    assert.ok(!JSON.stringify(result).includes(sensitiveValue));
  });
});
