import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { publishWindowsHelperServiceBinary } from '../src/windows-helper-publish.mjs';
import { buildWindowsServiceBoundaryPlan } from '../src/windows-service-boundary-plan.mjs';
import { buildWindowsHelperLayoutPlan } from '../src/windows-helper-layout-plan.mjs';
import { buildWindowsServiceLifecycleGate } from '../src/windows-service-lifecycle-gate.mjs';
import { evaluateWindowsServiceInstallGate } from '../src/windows-service-install-gate.mjs';
import {
  buildWindowsPersistentServiceLifecyclePlan,
  buildWindowsPersistentServiceUninstallPlan,
  evaluateWindowsPersistentServiceLifecycleReport,
} from '../src/windows-persistent-service-lifecycle.mjs';

const execFileAsync = promisify(execFile);
const SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'windows-persistent-service-lifecycle-collector.ps1',
);

function fail(code) {
  process.stdout.write(`${JSON.stringify({ ok: false, code, authorization_ready: false })}\n`);
  process.exit(1);
}

const operation = process.argv[2];
if (operation !== 'install' && operation !== 'uninstall') {
  fail('invalid_operation');
}

const published = await publishWindowsHelperServiceBinary();
const boundary = buildWindowsServiceBoundaryPlan({
  platform: 'win32',
  binarySha256: published.sha256,
  binaryByteLength: published.byteLength,
});
const layout = buildWindowsHelperLayoutPlan(boundary, { layout_mode: 'persistent' });

let plan;
if (operation === 'install') {
  const lifecycleGate = buildWindowsServiceLifecycleGate(boundary);
  const { runOperatorApprovedWindowsServiceLifecycleLiveTest } = await import(
    '../src/windows-service-lifecycle-live.mjs'
  );
  const live = await runOperatorApprovedWindowsServiceLifecycleLiveTest();
  const installGate = evaluateWindowsServiceInstallGate(lifecycleGate, live, {
    schema_version: 1,
    service_present: false,
    account_local_service: false,
    demand_start: false,
    win32_own_process: false,
    service_sid_unrestricted: false,
    caller_service_control_denied: false,
    binary_binding_verified: false,
    binary_chain_reparse_free: false,
    binary_owner_trusted: false,
    caller_binary_control_denied: false,
    snapshot_matches_plan: false,
    authorization_ready: false,
  });
  plan = buildWindowsPersistentServiceLifecyclePlan(layout, installGate);
} else {
  plan = buildWindowsPersistentServiceUninstallPlan(layout);
}

const staging = await fs.mkdtemp(path.join(os.tmpdir(), 'bridge-persistent-'));
const nonce = randomBytes(32).toString('hex');
await fs.writeFile(path.join(staging, 'marker'), nonce, { encoding: 'ascii', flag: 'wx' });
await fs.writeFile(path.join(staging, 'payload.exe'), published.bytes, { flag: 'wx' });
await fs.writeFile(path.join(staging, 'params.json'), `${JSON.stringify({
  marker_nonce: nonce,
  expected_sha256: published.sha256,
  expected_byte_length: published.byteLength,
})}\n`, { flag: 'wx' });

const systemRoot = process.env.SystemRoot;
if (typeof systemRoot !== 'string' || systemRoot.length < 1) {
  fail('invalid_system_root');
}
const powershell = path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const argLine = [
  '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
  '-File', `"${SCRIPT}"`,
  '-StagingRoot', `"${staging}"`,
  '-Operation', operation,
  '-ExpectedBinarySha256', published.sha256,
  '-ExpectedBinaryByteLength', String(published.byteLength),
  '-MarkerNonce', nonce,
].join(' ');
const vbs = `Set sh = CreateObject("Shell.Application")\r\nsh.ShellExecute "${powershell}", "${argLine.replace(/"/g, '""')}", "", "runas", 1\r\n`;
await fs.writeFile(path.join(staging, 'elevate.vbs'), vbs, { flag: 'wx' });
await execFileAsync(path.join(systemRoot, 'System32', 'wscript.exe'), [
  '//B', '//Nologo', path.join(staging, 'elevate.vbs'),
], { windowsHide: false });

const resultPath = path.join(staging, 'result.json');
const deadline = Date.now() + 300000;
let resultReady = false;
while (Date.now() < deadline) {
  try {
    await fs.access(resultPath);
    resultReady = true;
    break;
  } catch {
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}
if (!resultReady) {
  await fs.rm(staging, { recursive: true, force: true }).catch(() => {});
  fail('elevation_timeout');
}

let raw;
try {
  const text = await fs.readFile(resultPath, 'utf8');
  if (text.length > 64 * 1024) {
    fail('collector_result_too_large');
  }
  raw = JSON.parse(text);
} catch {
  await fs.rm(staging, { recursive: true, force: true }).catch(() => {});
  fail('collector_result_invalid');
}

const report = evaluateWindowsPersistentServiceLifecycleReport(plan, raw);
await fs.rm(staging, { recursive: true, force: true }).catch(() => {});
process.stdout.write(`${JSON.stringify(report)}\n`);
process.exit(report.ok ? 0 : 1);
