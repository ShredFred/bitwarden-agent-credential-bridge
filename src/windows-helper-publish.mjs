import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  WINDOWS_HELPER_PACKAGE_DIGEST,
  WINDOWS_HELPER_TOOLCHAIN_PIN,
  brandWindowsHelperPublishBinding,
  verifyWindowsHelperReviewedSources,
  WindowsHelperPackageBindingError,
} from './windows-helper-package-binding.mjs';

const execFileAsync = promisify(execFile);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = path.join(ROOT, 'native', 'windows-helper-service');
const PROJECT = WINDOWS_HELPER_TOOLCHAIN_PIN.project_file;
const EXE = WINDOWS_HELPER_TOOLCHAIN_PIN.executable_name;
const ILLINK_VERSION = WINDOWS_HELPER_TOOLCHAIN_PIN.illink_version;
const ILLINK_NUPKG_SHA256 = WINDOWS_HELPER_TOOLCHAIN_PIN.illink_nupkg_sha256;

export class WindowsHelperPublishError extends Error {
  constructor(code) {
    super(`Windows helper publish failed: ${code}`);
    this.name = 'WindowsHelperPublishError';
    this.code = code;
  }
}

/**
 * Publish the reviewed helper into an OS-temporary workspace and return a
 * branded bytes + digest binding. Performs no service install and writes
 * nothing under normal user profile roots.
 *
 * Fail-closed Phase 9f package binding runs before restore/publish.
 */
export async function publishWindowsHelperServiceBinary() {
  if (process.platform !== 'win32') {
    throw new WindowsHelperPublishError('unsupported_platform');
  }

  let packageReport;
  try {
    packageReport = await verifyWindowsHelperReviewedSources(SOURCE);
  } catch (error) {
    if (error instanceof WindowsHelperPackageBindingError) {
      throw new WindowsHelperPublishError(error.code);
    }
    throw error;
  }
  if (packageReport.package_digest !== WINDOWS_HELPER_PACKAGE_DIGEST ||
      packageReport.package_binding_verified !== true) {
    throw new WindowsHelperPublishError('package_binding_mismatch');
  }

  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-service-build-'));
  try {
    const projectDir = path.join(root, 'project');
    const outputDir = path.join(root, 'publish');
    await fs.cp(SOURCE, projectDir, { recursive: true, force: false, errorOnExist: true });
    // Re-verify the copied tree so publish cannot silently use drifted sources.
    await verifyWindowsHelperReviewedSources(projectDir);

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
    if (createHash('sha256').update(packageBytes).digest('hex') !== ILLINK_NUPKG_SHA256) {
      throw new WindowsHelperPublishError('illink_digest_mismatch');
    }
    await fs.copyFile(cachedPackage, path.join(localFeed, path.basename(cachedPackage)));

    const systemRoot = process.env.SystemRoot;
    const programFiles = process.env.ProgramFiles;
    if (typeof systemRoot !== 'string' || typeof programFiles !== 'string') {
      throw new WindowsHelperPublishError('invalid_build_environment');
    }
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
    ], {
      cwd: projectDir, env: buildEnv, windowsHide: true, timeout: 180000,
      maxBuffer: 1024 * 1024, encoding: 'utf8',
    });
    await execFileAsync('dotnet', [
      'publish', PROJECT, '--no-restore', '--configuration', 'Release',
      '--runtime', WINDOWS_HELPER_TOOLCHAIN_PIN.runtime_identifier,
      '--output', outputDir, '--nologo',
      '--disable-build-servers',
    ], {
      cwd: projectDir, env: buildEnv, windowsHide: true, timeout: 180000,
      maxBuffer: 1024 * 1024, encoding: 'utf8',
    });
    const entries = await fs.readdir(outputDir);
    if (entries.length !== 1 || entries[0] !== EXE) {
      throw new WindowsHelperPublishError('unexpected_publish_layout');
    }
    const bytes = await fs.readFile(path.join(outputDir, EXE));
    return brandWindowsHelperPublishBinding({
      bytes,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      byteLength: bytes.byteLength,
      package_digest: WINDOWS_HELPER_PACKAGE_DIGEST,
      package_binding_verified: true,
      authorization_ready: false,
    });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}
