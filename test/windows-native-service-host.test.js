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
const SERVICE_SID = 'S-1-5-80-4161497498-1516966145-968308051-418532793-1299382607';

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
}

async function runPipePair(executable, nonce, mode, serverMode = 'normal') {
  const client = spawn(executable, ['--self-test-pipe-client', mode, nonce], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const serverArgs = serverMode === 'normal'
    ? ['--console-pipe-denial', nonce]
    : ['--self-test-pipe-server', serverMode, nonce];
  const server = spawn(executable, serverArgs, {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const serverStdout = [];
  const serverStderr = [];
  const clientStdout = [];
  const clientStderr = [];
  server.stdout.on('data', (chunk) => serverStdout.push(chunk));
  server.stderr.on('data', (chunk) => serverStderr.push(chunk));
  client.stdout.on('data', (chunk) => clientStdout.push(chunk));
  client.stderr.on('data', (chunk) => clientStderr.push(chunk));
  const [serverResult, clientResult] = await Promise.all([waitForExit(server), waitForExit(client)]);
  return {
    serverResult,
    clientResult,
    serverStdout: Buffer.concat(serverStdout).toString('utf8'),
    serverStderr: Buffer.concat(serverStderr).toString('utf8'),
    clientStdout: Buffer.concat(clientStdout).toString('utf8'),
    clientStderr: Buffer.concat(clientStderr).toString('utf8'),
  };
}

async function publishOnce(root, mutateSource = null) {
  const projectDir = path.join(root, 'project');
  const outputDir = path.join(root, 'publish');
  await fs.cp(SOURCE, projectDir, { recursive: true, force: false, errorOnExist: true });
  if (mutateSource !== null) await mutateSource(projectDir);
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
      [PROJECT, 'DenialPipeProbe.cs', 'NativeDenialPipeClient.cs', 'NativeServerIdentityVerifier.cs', 'PipeSecurity.cs', 'Program.cs', 'global.json', 'NuGet.Config'].sort(),
    );
    const project = await fs.readFile(path.join(SOURCE, PROJECT), 'utf8');
    assert.equal(project.includes('PackageReference'), false);
    const pipeSecurity = await fs.readFile(path.join(SOURCE, 'PipeSecurity.cs'), 'utf8');
    const serverVerifier = await fs.readFile(path.join(SOURCE, 'NativeServerIdentityVerifier.cs'), 'utf8');
    const program = await fs.readFile(path.join(SOURCE, 'Program.cs'), 'utf8');
    const denialProbe = await fs.readFile(path.join(SOURCE, 'DenialPipeProbe.cs'), 'utf8');
    assert.ok(pipeSecurity.includes(
      '"D:P(A;;GA;;;SY)(A;;GA;;;" + ServiceSid + ")(A;;0x12018b;;;AU)"',
    ));
    assert.ok(pipeSecurity.includes(`ServiceSid = "${SERVICE_SID}"`));
    assert.ok(serverVerifier.includes(`ServiceSid = "${SERVICE_SID}"`));
    assert.ok(serverVerifier.includes('LocalServiceSid = "S-1-5-19"'));
    assert.ok(serverVerifier.includes('ServiceName = "BitwardenAgentCredentialBridgeHelper"'));
    assert.equal(serverVerifier.includes('WriteFile'), false);
    assert.equal(serverVerifier.includes('nonce'), false);
    assert.ok(serverVerifier.includes('CurrentProcessHasExpectedServiceIdentity()'));
    const identityGate = program.indexOf('CurrentProcessHasExpectedServiceIdentity()');
    const runningStatus = program.indexOf('ReportStatus(ServiceRunning');
    const serviceLoop = program.indexOf('RunServiceLoop(StopEvent)');
    assert.ok(identityGate > 0 && runningStatus > identityGate && serviceLoop > runningStatus);
    assert.ok(denialProbe.includes('if (!NativeServerIdentityVerifier.CurrentProcessHasExpectedServiceIdentity())'));
    assert.ok(denialProbe.includes('int createResult = TryCreateProtectedPipe(out IntPtr pipe);'));
    assert.equal(denialProbe.includes('RunCore(null, "service"'), false);
    assert.ok(denialProbe.includes('OpenProcess(ProcessQueryLimitedInformation | Synchronize'));
    assert.ok(denialProbe.includes('WaitForSingleObject(clientProcess, 0) == WaitTimeout'));
    assert.ok(denialProbe.includes('ImpersonateNamedPipeClient(pipe)'));
    assert.ok(denialProbe.includes('TryEqualTokenUsers(callerToken, clientProcessToken'));
    assert.ok(denialProbe.includes('if (!RevertToSelf()) ExitProcess(16)'));
    assert.ok(denialProbe.includes('\\"authorization_denied\\":true'));
    assert.ok(denialProbe.includes('\\"manifest_executor_absent\\":true'));
    for (const forbiddenTrustee of [';;;WD)', ';;;AN)', ';;;NU)', ';;;BA)', ';;;OW)']) {
      assert.equal(pipeSecurity.includes(forbiddenTrustee), false, forbiddenTrustee);
    }
    const source = `${program}\n${denialProbe}\n${await fs.readFile(path.join(SOURCE, 'NativeDenialPipeClient.cs'), 'utf8')}\n${serverVerifier}\n${await fs.readFile(path.join(SOURCE, 'PipeSecurity.cs'), 'utf8')}`;
    assert.equal(source.match(/CreateFile\(/g)?.length, 2);
    assert.ok(source.includes('GenericRead | FileWriteData | FileWriteAttributes'));
    for (const forbidden of [
      'System.Net', 'HttpClient', 'Socket', 'TcpListener', 'WinHttp', 'WSAStartup',
      'Process.Start', 'CreateProcess', 'System.Diagnostics', 'System.IO.',
      'Microsoft.Win32', 'Registry.',
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

      const systemRoot = process.env.SystemRoot;
      assert.equal(typeof systemRoot, 'string');
      const sc = path.join(systemRoot, 'System32', 'sc.exe');
      const serviceSidResult = await execFileAsync(sc, [
        'showsid', 'BitwardenAgentCredentialBridgeHelper',
      ], { windowsHide: true, timeout: 10000, maxBuffer: 4096, encoding: 'utf8' });
      assert.ok(serviceSidResult.stdout.includes(SERVICE_SID));

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
        explicit_pipe_dacl_compiled: true,
        server_identity_verifier_compiled: true,
        service_identity_self_check_compiled: true,
        service_pipe_activation_compiled: true,
        service_pipe_activation_live_verified: false,
        manifest_executor_absent: true,
        network_stack_absent: true,
        vault_client_absent: true,
        install_gate_eligible: false,
      });

      const nonce = 'a'.repeat(64);
      const identityClient = spawn(first.executable, ['--verify-fixed-server-identity'], {
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const identityServer = spawn(first.executable, ['--console-pipe-denial', nonce], {
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const identityClientStdout = [];
      const identityClientStderr = [];
      const identityServerStdout = [];
      const identityServerStderr = [];
      identityClient.stdout.on('data', (chunk) => identityClientStdout.push(chunk));
      identityClient.stderr.on('data', (chunk) => identityClientStderr.push(chunk));
      identityServer.stdout.on('data', (chunk) => identityServerStdout.push(chunk));
      identityServer.stderr.on('data', (chunk) => identityServerStderr.push(chunk));
      const [identityClientResult, identityServerResult] = await Promise.all([
        waitForExit(identityClient), waitForExit(identityServer),
      ]);
      assert.deepEqual(identityClientResult, { code: 31, signal: null });
      assert.deepEqual(identityServerResult, { code: 12, signal: null });
      assert.equal(Buffer.concat(identityClientStderr).length, 0);
      assert.equal(Buffer.concat(identityServerStdout).length, 0);
      assert.equal(Buffer.concat(identityServerStderr).length, 0);
      assert.deepEqual(JSON.parse(Buffer.concat(identityClientStdout).toString('utf8')), {
        schema_version: 1,
        local_pipe_connected: true,
        server_pid_bound: true,
        scm_service_running: false,
        scm_server_pid_match: false,
        server_token_bound: true,
        server_token_user_local_service: false,
        service_sid_group_enabled: false,
        server_identity_verified: false,
        request_sent: false,
        authorization_denied: true,
      });

      const valid = await runPipePair(first.executable, nonce, 'valid');
      assert.deepEqual(valid.clientResult, { code: 0, signal: null });
      assert.deepEqual(valid.serverResult, { code: 0, signal: null });
      assert.equal(valid.serverStdout, '');
      assert.equal(valid.serverStderr, '');
      assert.equal(valid.clientStderr, '');
      assert.deepEqual(JSON.parse(valid.clientStdout), {
        schema_version: 1,
        narrow_pipe_rights: true,
        create_pipe_instance_right_absent: true,
        response_schema_exact: true,
        server_identity_verified: false,
        authorization_denied: true,
      });

      for (const mode of ['mismatch', 'partial', 'crlf', 'oversize']) {
        const malformed = await runPipePair(first.executable, nonce, mode);
        assert.deepEqual(malformed.serverResult, { code: 12, signal: null });
        assert.deepEqual(malformed.clientResult, { code: 0, signal: null });
        assert.equal(malformed.serverStdout, '');
        assert.equal(malformed.serverStderr, '');
        assert.equal(malformed.clientStdout, '');
        assert.equal(malformed.clientStderr, '');
      }

      const idleStartedAt = Date.now();
      const idle = await runPipePair(first.executable, nonce, 'idle');
      assert.deepEqual(idle.serverResult, { code: 12, signal: null });
      assert.deepEqual(idle.clientResult, { code: 0, signal: null });
      assert.equal(idle.serverStdout + idle.serverStderr + idle.clientStdout + idle.clientStderr, '');
      assert.ok(Date.now() - idleStartedAt >= 1000);
      assert.ok(Date.now() - idleStartedAt < 5000);

      for (const mode of ['no-ack', 'unread']) {
        const stalledStartedAt = Date.now();
        const stalled = await runPipePair(first.executable, nonce, mode);
        assert.deepEqual(stalled.serverResult, { code: 15, signal: null });
        assert.deepEqual(stalled.clientResult, { code: 0, signal: null });
        assert.equal(stalled.serverStdout + stalled.serverStderr + stalled.clientStdout + stalled.clientStderr, '');
        assert.ok(Date.now() - stalledStartedAt >= 1000);
        assert.ok(Date.now() - stalledStartedAt < 5000);
      }

      const noClientStartedAt = Date.now();
      await assert.rejects(
        execFileAsync(first.executable, ['--console-pipe-denial', nonce], {
          windowsHide: true, timeout: 5000, maxBuffer: 4096, encoding: 'utf8',
        }),
        (error) => error.code === 11 && error.stdout === '' && error.stderr === '',
      );
      assert.ok(Date.now() - noClientStartedAt >= 1000);
      assert.ok(Date.now() - noClientStartedAt < 5000);

      for (const serverMode of ['stall', 'trailing']) {
        const fakeStartedAt = Date.now();
        const fake = await runPipePair(first.executable, nonce, 'valid', serverMode);
        assert.deepEqual(fake.serverResult, { code: 0, signal: null });
        assert.deepEqual(fake.clientResult, { code: 23, signal: null });
        assert.equal(fake.serverStdout + fake.serverStderr + fake.clientStdout + fake.clientStderr, '');
        assert.ok(Date.now() - fakeStartedAt < 5000);
        if (serverMode === 'stall') assert.ok(Date.now() - fakeStartedAt >= 1000);
      }

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

      const mutant = await publishOnce(path.join(root, 'mutant'), async (projectDir) => {
        const securityPath = path.join(projectDir, 'PipeSecurity.cs');
        const original = await fs.readFile(securityPath, 'utf8');
        const mutated = original.replace(
          ')(A;;0x12018b;;;AU)"',
          ')(A;;0x12018b;;;AU)(A;;GR;;;WD)"',
        );
        assert.notEqual(mutated, original);
        await fs.writeFile(securityPath, mutated, 'utf8');
      });
      await assert.rejects(
        execFileAsync(mutant.executable, ['--console-pipe-denial', nonce], {
          windowsHide: true, timeout: 10000, maxBuffer: 4096, encoding: 'utf8',
        }),
        (error) => error.code === 18 && error.stdout === '' && error.stderr === '',
      );

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
