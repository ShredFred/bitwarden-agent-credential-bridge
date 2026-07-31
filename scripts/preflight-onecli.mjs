import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SUPPORTED_PLATFORMS = new Set(['win32', 'darwin', 'linux']);
const COMMAND_TIMEOUT_MS = 5_000;
const MAX_CAPTURED_OUTPUT_BYTES = 16_384;

export const DEFAULT_REQUIRED_PORTS = Object.freeze([
  Object.freeze({ name: 'dashboard', port: 10_254 }),
  Object.freeze({ name: 'gateway', port: 10_255 }),
  Object.freeze({ name: 'postgres', port: 5432 }),
]);

/**
 * Run only non-mutating local readiness checks.
 *
 * The injected runner makes the behavior testable without invoking host tools.
 * Command output and thrown error text are deliberately excluded from reports.
 *
 * @param {{
 *   platform?: string,
 *   runner?: CommandRunner,
 *   requiredPorts?: ReadonlyArray<{ name: string, port: number }>
 * }} [options]
 */
export async function runOneCliPreflight({
  platform = process.platform,
  runner = runReadOnlyCommand,
  requiredPorts = DEFAULT_REQUIRED_PORTS,
} = {}) {
  const checks = [
    {
      id: 'platform',
      ready: SUPPORTED_PLATFORMS.has(platform),
      status: SUPPORTED_PLATFORMS.has(platform)
        ? 'supported'
        : 'unsupported_platform',
      platform,
    },
  ];

  if (!SUPPORTED_PLATFORMS.has(platform)) {
    return report(checks);
  }

  checks.push(
    await checkTool(runner, 'docker', 'docker', ['--version']),
    await checkTool(runner, 'docker_compose', 'docker', ['compose', 'version']),
    await checkTool(runner, 'aac', 'aac', ['--version']),
  );

  for (const requiredPort of requiredPorts) {
    checks.push(await checkPort(runner, platform, requiredPort));
  }

  return report(checks);
}

/**
 * Default runner for read-only version and local listening-port commands.
 * It never invokes a shell and never returns stderr.
 *
 * @type {CommandRunner}
 */
export function runReadOnlyCommand(
  command,
  args,
  { captureStdout = false, timeoutMs = COMMAND_TIMEOUT_MS } = {},
) {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = '';
    const child = spawn(command, args, {
      shell: false,
      stdio: ['ignore', captureStdout ? 'pipe' : 'ignore', 'ignore'],
      windowsHide: true,
    });

    if (captureStdout && child.stdout) {
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk) => {
        if (Buffer.byteLength(stdout) < MAX_CAPTURED_OUTPUT_BYTES) {
          stdout += chunk;
        }
      });
    }

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.once('error', () => {
      finish({ code: null, stdout: '', timedOut: false });
    });
    child.once('close', (code) => {
      finish({
        code: Number.isInteger(code) ? code : null,
        stdout: captureStdout ? stdout.slice(0, MAX_CAPTURED_OUTPUT_BYTES) : '',
        timedOut: false,
      });
    });

    const timer = setTimeout(() => {
      child.kill();
      finish({ code: null, stdout: '', timedOut: true });
    }, timeoutMs);
    timer.unref();
  });
}

/**
 * @param {CommandRunner} runner
 * @param {string} id
 * @param {string} command
 * @param {string[]} args
 */
async function checkTool(runner, id, command, args) {
  const outcome = await invoke(runner, command, args);
  return {
    id,
    ready: outcome.code === 0,
    status:
      outcome.code === 0
        ? 'available'
        : outcome.timedOut
          ? 'timed_out'
          : 'missing_or_failed',
  };
}

/**
 * @param {CommandRunner} runner
 * @param {string} platform
 * @param {{ name: string, port: number }} requiredPort
 */
async function checkPort(runner, platform, requiredPort) {
  const { name, port } = requiredPort;
  if (
    typeof name !== 'string' ||
    name.trim() === '' ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535
  ) {
    return {
      id: `port.${typeof name === 'string' && name ? name : 'invalid'}`,
      ready: false,
      status: 'invalid_port_requirement',
    };
  }

  const probe = portProbe(platform, port);
  const outcome = await invoke(runner, probe.command, probe.args, {
    captureStdout: probe.captureStdout,
  });

  let status = 'probe_failed';
  let ready = false;
  if (outcome.timedOut) {
    status = 'timed_out';
  } else if (probe.mode === 'zero_means_free' && outcome.code === 0) {
    status = 'free';
    ready = true;
  } else if (probe.mode === 'one_means_free' && outcome.code === 1) {
    status = 'free';
    ready = true;
  } else if (
    probe.mode === 'empty_stdout_means_free' &&
    outcome.code === 0
  ) {
    ready = outcome.stdout.trim() === '';
    status = ready ? 'free' : 'in_use';
  } else if (
    (probe.mode === 'zero_means_free' && outcome.code === 3) ||
    (probe.mode === 'one_means_free' && outcome.code === 0)
  ) {
    status = 'in_use';
  }

  return { id: `port.${name}`, ready, status, port };
}

/**
 * @param {string} platform
 * @param {number} port
 */
function portProbe(platform, port) {
  if (platform === 'win32') {
    return {
      command: 'powershell.exe',
      args: [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { exit 4 }; $listener = Get-NetTCPConnection -State Listen -LocalPort ${port} -ErrorAction SilentlyContinue; if ($listener) { exit 3 } else { exit 0 }`,
      ],
      captureStdout: false,
      mode: 'zero_means_free',
    };
  }

  if (platform === 'darwin') {
    return {
      command: 'lsof',
      args: ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'],
      captureStdout: false,
      mode: 'one_means_free',
    };
  }

  return {
    command: 'ss',
    args: ['-H', '-ltn', `sport = :${port}`],
    captureStdout: true,
    mode: 'empty_stdout_means_free',
  };
}

/**
 * @param {CommandRunner} runner
 * @param {string} command
 * @param {string[]} args
 * @param {{ captureStdout?: boolean }} [options]
 */
async function invoke(runner, command, args, options = {}) {
  try {
    const result = await runner(command, [...args], {
      captureStdout: options.captureStdout === true,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    return {
      code: Number.isInteger(result?.code) ? result.code : null,
      stdout: typeof result?.stdout === 'string' ? result.stdout : '',
      timedOut: result?.timedOut === true,
    };
  } catch {
    return { code: null, stdout: '', timedOut: false };
  }
}

/** @param {Array<Record<string, unknown> & { ready: boolean }>} checks */
function report(checks) {
  return {
    version: 1,
    kind: 'onecli-readiness-preflight',
    ready: checks.every((check) => check.ready),
    checks,
  };
}

/**
 * @typedef {(
 *   command: string,
 *   args: string[],
 *   options?: { captureStdout?: boolean, timeoutMs?: number }
 * ) => Promise<{ code: number | null, stdout?: string, timedOut?: boolean }>} CommandRunner
 */

async function main() {
  const result = await runOneCliPreflight();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.ready ? 0 : 1;
}

const invokedPath = process.argv[1];
if (
  typeof invokedPath === 'string' &&
  fileURLToPath(import.meta.url) === invokedPath
) {
  main().catch(() => {
    process.stdout.write(
      `${JSON.stringify({
        version: 1,
        kind: 'onecli-readiness-preflight',
        ready: false,
        checks: [
          {
            id: 'preflight',
            ready: false,
            status: 'unexpected_failure',
          },
        ],
      }, null, 2)}\n`,
    );
    process.exitCode = 1;
  });
}
