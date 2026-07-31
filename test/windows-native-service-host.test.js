import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = path.join(ROOT, 'native', 'windows-helper-service');
const PROJECT = 'BridgeWindowsHelperService.csproj';
const EXE = 'BitwardenAgentCredentialBridgeHelper.exe';
const ILLINK_VERSION = '8.0.29';
const ILLINK_NUPKG_SHA256 = '5e75b0b31660410b04fbb17614de9ba40bf44976cae45227094b544df085dce2';
const PIPE_PATH = String.raw`\\.\pipe\BitwardenAgentCredentialBridgeHelper.v1.denial`;

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
}

function connectToDenialPipe(sentNonce, acknowledge = true) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 10000;
    const attempt = () => {
      const socket = net.createConnection(PIPE_PATH);
      const chunks = [];
      let connected = false;
      let acknowledged = false;
      socket.once('connect', () => {
        connected = true;
        if (sentNonce !== null) socket.write(`${sentNonce}\n`);
      });
      socket.on('data', (chunk) => {
        chunks.push(chunk);
        if (acknowledge && !acknowledged) {
          acknowledged = true;
          socket.write('ack\n');
        }
      });
      socket.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      socket.once('error', (error) => {
        socket.destroy();
        if (connected && error.code === 'EPIPE') {
          resolve(Buffer.concat(chunks).toString('utf8'));
        } else if ((error.code === 'ENOENT' || error.code === 'EBUSY') && Date.now() < deadline) {
          setTimeout(attempt, 20);
        } else {
          reject(error);
        }
      });
    };
    attempt();
  });
}

function connectAndPause(sentNonce) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 10000;
    const attempt = () => {
      const socket = net.createConnection(PIPE_PATH);
      socket.once('connect', () => {
        socket.write(`${sentNonce}\n`);
        socket.pause();
        resolve(socket);
      });
      socket.once('error', (error) => {
        socket.destroy();
        if ((error.code === 'ENOENT' || error.code === 'EBUSY') && Date.now() < deadline) {
          setTimeout(attempt, 20);
        } else {
          reject(error);
        }
      });
    };
    attempt();
  });
}

async function publishOnce(root) {
  const projectDir = path.join(root, 'project');
  const outputDir = path.join(root, 'publish');
  await fs.cp(SOURCE, projectDir, { recursive: true, force: false, errorOnExist: true });
  const cliHome = path.join(root, 'dotnet-home');
  const packages = path.join(root, 'packages');
  const localFeed = path.join(root, 'local-feed');
  const buildTemp = path.join(root, 'temp');
  const appData = path.join(cliHome, 'AppData', 'Roaming');
  const localAppData = path.join(cliHome, 'AppData', 'Local');
  await fs.mkdir(cliHome, { recursive: true });
  await fs.mkdir(packages, { recursive: true });
  await fs.mkdir(localFeed, { recursive: true });
  await fs.mkdir(buildTemp, { recursive: true });
  await fs.mkdir(appData, { recursive: true });
  await fs.mkdir(localAppData, { recursive: true });
  const cachedPackage = path.join(
    os.homedir(), '.nuget', 'packages', 'microsoft.net.illink.tasks', ILLINK_VERSION,
    `microsoft.net.illink.tasks.${ILLINK_VERSION}.nupkg`,
  );
  const packageBytes = await fs.readFile(cachedPackage);
  assert.equal(createHash('sha256').update(packageBytes).digest('hex'), ILLINK_NUPKG_SHA256);
  await fs.copyFile(cachedPackage, path.join(localFeed, path.basename(cachedPackage)));
  const systemRoot = process.env.SystemRoot;
  const programFiles = process.env.ProgramFiles;
  assert.equal(typeof systemRoot, 'string');
  assert.equal(typeof programFiles, 'string');
  const dotnetRoot = path.join(programFiles, 'dotnet');
  const buildEnv = {
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    ComSpec: path.join(systemRoot, 'System32', 'cmd.exe'),
    PATH: `${dotnetRoot};${path.join(systemRoot, 'System32')}`,
    PATHEXT: '.COM;.EXE;.BAT;.CMD',
    ProgramFiles: programFiles,
    TEMP: buildTemp,
    TMP: buildTemp,
    USERPROFILE: cliHome,
    HOME: cliHome,
    APPDATA: appData,
    LOCALAPPDATA: localAppData,
    DOTNET_CLI_HOME: cliHome,
    DOTNET_ROOT: dotnetRoot,
    DOTNET_CLI_TELEMETRY_OPTOUT: '1',
    DOTNET_GENERATE_ASPNET_CERTIFICATE: 'false',
    DOTNET_NOLOGO: '1',
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1',
    NUGET_PACKAGES: packages,
    NUGET_HTTP_CACHE_PATH: path.join(localAppData, 'NuGet', 'http-cache'),
  };
  await execFileAsync('dotnet', [
    'restore', PROJECT, '--configfile', 'NuGet.Config', '--source', localFeed, '--nologo',
    '--property:NuGetAudit=false',
  ], { cwd: projectDir, env: buildEnv, windowsHide: true, timeout: 120000, maxBuffer: 1024 * 1024, encoding: 'utf8' });
  await execFileAsync('dotnet', [
    'publish', PROJECT, '--no-restore', '--configuration', 'Release',
    '--runtime', 'win-x64', '--output', outputDir, '--nologo',
    '--disable-build-servers',
  ], { cwd: projectDir, env: buildEnv, windowsHide: true, timeout: 120000, maxBuffer: 1024 * 1024, encoding: 'utf8' });
  const executable = path.join(outputDir, EXE);
  assert.deepEqual(await fs.readdir(outputDir), [EXE]);
  const bytes = await fs.readFile(executable);
  return { executable, digest: createHash('sha256').update(bytes).digest('hex') };
}

describe('native Windows helper service host scaffold', () => {
  it('contains no network, vault, process-launch, or manifest-executor surface', async () => {
    assert.deepEqual(
      (await fs.readdir(SOURCE)).sort(),
      [PROJECT, 'DenialPipeProbe.cs', 'Program.cs', 'global.json', 'NuGet.Config'].sort(),
    );
    const project = await fs.readFile(path.join(SOURCE, PROJECT), 'utf8');
    assert.equal(project.includes('PackageReference'), false);
    const source = `${await fs.readFile(path.join(SOURCE, 'Program.cs'), 'utf8')}\n${await fs.readFile(path.join(SOURCE, 'DenialPipeProbe.cs'), 'utf8')}`;
    for (const forbidden of [
      'System.Net', 'HttpClient', 'Socket', 'TcpListener', 'WinHttp', 'WSAStartup',
      'Process.Start', 'CreateProcess', 'System.Diagnostics', 'System.IO.',
      'CreateFile', 'Microsoft.Win32', 'Registry.',
      'Environment.GetEnvironmentVariable', 'Manifest', 'Vault',
    ]) {
      assert.equal(source.includes(forbidden), false, forbidden);
    }
  });

  it('publishes deterministically and exercises only the value-free console contract', {
    skip: process.platform !== 'win32',
    timeout: 180000,
  }, async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-service-build-'));
    try {
      const first = await publishOnce(path.join(root, 'one'));
      const second = await publishOnce(path.join(root, 'two'));
      assert.match(first.digest, /^[0-9a-f]{64}$/);
      assert.equal(first.digest, second.digest);

      const selfTest = await execFileAsync(first.executable, ['--self-test'], {
        windowsHide: true, timeout: 10000, maxBuffer: 4096, encoding: 'utf8',
      });
      assert.equal(selfTest.stderr, '');
      assert.deepEqual(JSON.parse(selfTest.stdout), {
        schema_version: 1,
        platform_win32: true,
        service_name_bound: true,
        scm_entrypoint_compiled: true,
        scm_lifecycle_live_verified: false,
        console_denial_pipe_compiled: true,
        service_pipe_activation_absent: true,
        service_pipe_acl_absent: true,
        manifest_executor_absent: true,
        network_stack_absent: true,
        vault_client_absent: true,
        install_gate_eligible: false,
      });

      const nonce = 'a'.repeat(64);
      const child = spawn(first.executable, ['--console-pipe-denial', nonce], {
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const stdout = [];
      const stderr = [];
      child.stdout.on('data', (chunk) => stdout.push(chunk));
      child.stderr.on('data', (chunk) => stderr.push(chunk));
      const [pipeResponse, childResult] = await Promise.all([
        connectToDenialPipe(nonce), waitForExit(child),
      ]);
      assert.deepEqual(childResult, { code: 0, signal: null });
      assert.equal(Buffer.concat(stdout).length, 0);
      assert.equal(Buffer.concat(stderr).length, 0);
      assert.deepEqual(JSON.parse(pipeResponse), {
        schema_version: 1,
        local_transport: true,
        remote_clients_rejected: true,
        first_instance: true,
        client_pid_bound: true,
        caller_token_bound: true,
        helper_token_bound: true,
        same_token_user: true,
        different_principal: false,
        authorization_denied: true,
      });

      const mismatchChild = spawn(first.executable, ['--console-pipe-denial', nonce], {
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const [mismatchResponse, mismatchResult] = await Promise.all([
        connectToDenialPipe('b'.repeat(64)), waitForExit(mismatchChild),
      ]);
      assert.equal(mismatchResponse, '');
      assert.deepEqual(mismatchResult, { code: 12, signal: null });

      for (const malformed of ['a'.repeat(8), `${'a'.repeat(64)}\r`, `${'a'.repeat(64)}\nextra`]) {
        const malformedChild = spawn(first.executable, ['--console-pipe-denial', nonce], {
          windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
        });
        const [malformedResponse, malformedResult] = await Promise.all([
          connectToDenialPipe(malformed), waitForExit(malformedChild),
        ]);
        assert.equal(malformedResponse, '');
        assert.deepEqual(malformedResult, { code: 12, signal: null });
      }

      const idleChild = spawn(first.executable, ['--console-pipe-denial', nonce], {
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const idleStartedAt = Date.now();
      const [idleResponse, idleResult] = await Promise.all([
        connectToDenialPipe(null), waitForExit(idleChild),
      ]);
      assert.equal(idleResponse, '');
      assert.deepEqual(idleResult, { code: 12, signal: null });
      assert.ok(Date.now() - idleStartedAt >= 1000);
      assert.ok(Date.now() - idleStartedAt < 5000);

      const noAckChild = spawn(first.executable, ['--console-pipe-denial', nonce], {
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const noAckStartedAt = Date.now();
      const [noAckResponse, noAckResult] = await Promise.all([
        connectToDenialPipe(nonce, false), waitForExit(noAckChild),
      ]);
      assert.deepEqual(JSON.parse(noAckResponse), {
        schema_version: 1,
        local_transport: true,
        remote_clients_rejected: true,
        first_instance: true,
        client_pid_bound: true,
        caller_token_bound: true,
        helper_token_bound: true,
        same_token_user: true,
        different_principal: false,
        authorization_denied: true,
      });
      assert.deepEqual(noAckResult, { code: 15, signal: null });
      assert.ok(Date.now() - noAckStartedAt >= 1000);
      assert.ok(Date.now() - noAckStartedAt < 5000);

      const unreadChild = spawn(first.executable, ['--console-pipe-denial', nonce], {
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const unreadStdout = [];
      const unreadStderr = [];
      unreadChild.stdout.on('data', (chunk) => unreadStdout.push(chunk));
      unreadChild.stderr.on('data', (chunk) => unreadStderr.push(chunk));
      const unreadExit = waitForExit(unreadChild);
      const unreadSocket = await connectAndPause(nonce);
      const unreadStartedAt = Date.now();
      try {
        assert.deepEqual(await unreadExit, { code: 15, signal: null });
      } finally {
        unreadSocket.destroy();
      }
      assert.equal(Buffer.concat(unreadStdout).length, 0);
      assert.equal(Buffer.concat(unreadStderr).length, 0);
      assert.ok(Date.now() - unreadStartedAt >= 1000);
      assert.ok(Date.now() - unreadStartedAt < 5000);

      const noClientStartedAt = Date.now();
      await assert.rejects(
        execFileAsync(first.executable, ['--console-pipe-denial', nonce], {
          windowsHide: true, timeout: 5000, maxBuffer: 4096, encoding: 'utf8',
        }),
        (error) => error.code === 11 && error.stdout === '' && error.stderr === '',
      );
      assert.ok(Date.now() - noClientStartedAt >= 1000);
      assert.ok(Date.now() - noClientStartedAt < 5000);

      const occupyingServer = net.createServer();
      await new Promise((resolve, reject) => {
        occupyingServer.once('error', reject);
        occupyingServer.listen(PIPE_PATH, resolve);
      });
      try {
        await assert.rejects(
          execFileAsync(first.executable, ['--console-pipe-denial', nonce], {
            windowsHide: true, timeout: 10000, maxBuffer: 4096, encoding: 'utf8',
          }),
          (error) => error.code === 10 && error.stdout === '' && error.stderr === '',
        );
      } finally {
        await new Promise((resolve) => occupyingServer.close(resolve));
      }

      await assert.rejects(
        execFileAsync(first.executable, ['--console-pipe-denial', 'NOT-A-NONCE'], {
          windowsHide: true, timeout: 10000, maxBuffer: 4096, encoding: 'utf8',
        }),
        (error) => error.code === 2 && error.stdout === '' && error.stderr === '',
      );
      await assert.rejects(
        execFileAsync(first.executable, ['unexpected'], {
          windowsHide: true, timeout: 10000, maxBuffer: 4096, encoding: 'utf8',
        }),
        (error) => error.code === 2 && error.stdout === '' && error.stderr === '',
      );
      await assert.rejects(
        execFileAsync(first.executable, [], {
          windowsHide: true, timeout: 10000, maxBuffer: 4096, encoding: 'utf8',
        }),
        (error) => error.code === 3 && error.stdout === '' && error.stderr === '',
      );
    } finally {
      await fs.rm(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    }
  });
});
