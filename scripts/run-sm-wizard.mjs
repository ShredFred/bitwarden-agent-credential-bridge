#!/usr/bin/env node
/**
 * Platform dispatcher for the same-user SM first-run wizard.
 * Windows: WinForms. macOS: StandardAdditions displayDialog (Cmd-V works).
 * Linux: zenity/kdialog when a display is present. Token never printed.
 *
 * --self-test: no GUI, fake token, temp allow path. Never a live SM token.
 */
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  checkBwsAvailable,
  defaultSecretsManagerMachineId,
  uninstallSecretsManagerLocalState,
} from '../src/secrets-manager-local-lifecycle.mjs';
import { withBwsDiagnostic } from '../src/secrets-manager-bws-adapter.mjs';
import { parseOsascriptJson } from '../src/macos-osascript-json.mjs';
import {
  MACOS_WIZARD_SELF_TEST_MACHINE_ID,
  MACOS_WIZARD_SELF_TEST_TOKEN,
  applySecretsManagerWizardSetup,
  interpretMacosWizardDialog,
} from '../src/macos-sm-wizard.mjs';
import {
  LINUX_WIZARD_SELF_TEST_MACHINE_ID,
  LINUX_WIZARD_SELF_TEST_TOKEN,
  collectLinuxWizardAnswers,
} from '../src/linux-sm-wizard.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(withBwsDiagnostic(payload))}\n`);
  process.exitCode = code;
}

function machineIdFromArgv(argv) {
  const index = argv.indexOf('--machine-id');
  const value = index >= 0 ? argv[index + 1] : undefined;
  if (typeof value === 'string' && /^[a-z][a-z0-9_-]{0,63}$/.test(value)) {
    return value;
  }
  return defaultSecretsManagerMachineId();
}

function argvHas(flag) {
  return process.argv.slice(2).includes(flag);
}

function spawnCaptured(command, args, options, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      resolve({ code: 1, stdout, stderr: 'timeout' });
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve({ code: 1, stdout, stderr: 'spawn_failed' });
    });
  });
}

function replaceStuckMacosWizard() {
  try {
    execFileSync('/usr/bin/pkill', ['-f', 'macos-sm-first-run-wizard.jxa'], {
      timeout: 3000,
      stdio: 'ignore',
    });
  } catch {
    // pkill exits 1 when nothing matched
  }
}

async function applyFromDialog(parsed) {
  const interpreted = interpretMacosWizardDialog(parsed);
  if (interpreted.ok !== true) {
    emit({
      ok: false,
      code: interpreted.code,
      authorization_ready: false,
      helper_vault_free: true,
    }, 1);
    return;
  }
  try {
    const applied = await applySecretsManagerWizardSetup({
      machineId: interpreted.machineId,
      token: interpreted.token,
      serverUrl: interpreted.serverUrl,
    });
    emit({
      ok: true,
      setup_complete: applied.setup_complete,
      machine_id: applied.machine_id,
      project_count: applied.project_count,
      cloud_default: applied.cloud_default,
      projects_listed: applied.projects_listed,
      allowed_projects_visible: applied.allowed_projects_visible,
      authorization_ready: false,
      helper_vault_free: true,
    });
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error
      ? String(error.code)
      : 'setup_failed';
    emit({ ok: false, code, authorization_ready: false, helper_vault_free: true }, 1);
  }
}

async function runMacosDialog({ selfTest, machineId, bwsOk, timeoutMs }) {
  const script = path.join(root, 'scripts', 'macos-sm-first-run-wizard.jxa');
  const args = [
    '-l', 'JavaScript',
    script,
    '--',
    '--machine-id', machineId,
    '--bws-ok', bwsOk ? '1' : '0',
  ];
  if (selfTest) args.push('--self-test');
  return spawnCaptured('/usr/bin/osascript', args, {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env,
  }, timeoutMs);
}

if (process.platform === 'win32') {
  const windows = path.join(root, 'scripts', 'run-windows-sm-wizard.mjs');
  const child = spawn(process.execPath, [windows, ...process.argv.slice(2)], {
    cwd: root,
    stdio: 'inherit',
    env: process.env,
  });
  child.on('close', (code) => {
    process.exit(code ?? 1);
  });
} else if (process.platform === 'linux') {
  if (argvHas('--self-test')) {
    const interpreted = await collectLinuxWizardAnswers({
      selfTest: true,
      machineId: LINUX_WIZARD_SELF_TEST_MACHINE_ID,
      bwsOk: true,
    });
    if (interpreted.ok !== true) {
      emit({
        ok: false,
        code: interpreted.code,
        authorization_ready: false,
        helper_vault_free: true,
      }, 1);
    } else if (interpreted.token !== LINUX_WIZARD_SELF_TEST_TOKEN) {
      emit({ ok: false, code: 'self_test_token_mismatch', authorization_ready: false }, 1);
    } else {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-wiz-self-'));
      const allowPath = path.join(dir, 'sm-machine.allow.json');
      const tokenPath = path.join(dir, 'sm-machine.token');
      try {
        const applied = await applySecretsManagerWizardSetup({
          machineId: interpreted.machineId,
          token: interpreted.token,
          serverUrl: interpreted.serverUrl,
        }, {
          allowPath,
          skipVerify: true,
          storeToken: async (value) => {
            await fs.writeFile(tokenPath, value, { encoding: 'utf8', mode: 0o600 });
          },
        });
        const removed = await uninstallSecretsManagerLocalState({
          allowPath,
          tokenPath,
          machine_id: interpreted.machineId,
        });
        emit({
          ok: true,
          self_test: true,
          setup_complete: applied.setup_complete === true,
          cleanup_complete: removed.uninstall_complete === true,
          machine_id: applied.machine_id,
          authorization_ready: false,
          helper_vault_free: true,
        });
      } catch (error) {
        await uninstallSecretsManagerLocalState({
          allowPath,
          tokenPath,
          machine_id: interpreted.machineId,
        }).catch(() => {});
        const code = error && typeof error === 'object' && 'code' in error
          ? String(error.code)
          : 'self_test_failed';
        emit({ ok: false, code, authorization_ready: false, helper_vault_free: true }, 1);
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    }
  } else {
    const bws = await checkBwsAvailable();
    const interpreted = await collectLinuxWizardAnswers({
      machineId: machineIdFromArgv(process.argv.slice(2)),
      bwsOk: bws.bws_available === true,
      timeoutMs: 3600000,
    });
    if (interpreted.ok !== true) {
      emit({
        ok: false,
        code: interpreted.code,
        authorization_ready: false,
        helper_vault_free: true,
      }, 1);
    } else {
      await applyFromDialog({
        ok: true,
        machine_id: interpreted.machineId,
        token: interpreted.token,
        server_url: interpreted.serverUrl,
      });
    }
  }
} else if (process.platform !== 'darwin') {
  emit({ ok: false, code: 'unsupported_platform', authorization_ready: false }, 1);
} else if (argvHas('--self-test')) {
  replaceStuckMacosWizard();
  const dialog = await runMacosDialog({
    selfTest: true,
    machineId: MACOS_WIZARD_SELF_TEST_MACHINE_ID,
    bwsOk: true,
    timeoutMs: 15000,
  });
  const trimmed = dialog.stdout.trim();
  if (!trimmed) {
    const scriptError = /execution error/i.test(dialog.stderr);
    emit({
      ok: false,
      code: scriptError ? 'wizard_script_error' : (
        dialog.code === 0 ? 'empty_wizard_output' : 'wizard_failed'
      ),
      authorization_ready: false,
      helper_vault_free: true,
    }, 1);
  } else {
    let parsed;
    try {
      parsed = parseOsascriptJson(trimmed);
    } catch {
      emit({ ok: false, code: 'wizard_output_invalid', authorization_ready: false }, 1);
      parsed = null;
    }
    if (parsed) {
      const interpreted = interpretMacosWizardDialog(parsed);
      if (interpreted.ok !== true) {
        emit({
          ok: false,
          code: interpreted.code,
          authorization_ready: false,
          helper_vault_free: true,
        }, 1);
      } else if (interpreted.token !== MACOS_WIZARD_SELF_TEST_TOKEN) {
        emit({ ok: false, code: 'self_test_token_mismatch', authorization_ready: false }, 1);
      } else {
        const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bw-sm-wiz-self-'));
        const allowPath = path.join(dir, 'sm-machine.allow.json');
        try {
          const applied = await applySecretsManagerWizardSetup({
            machineId: interpreted.machineId,
            token: interpreted.token,
            serverUrl: interpreted.serverUrl,
          }, { allowPath, skipVerify: true });
          const removed = await uninstallSecretsManagerLocalState({
            allowPath,
            machine_id: interpreted.machineId,
          });
          emit({
            ok: true,
            self_test: true,
            setup_complete: applied.setup_complete === true,
            cleanup_complete: removed.uninstall_complete === true,
            machine_id: applied.machine_id,
            authorization_ready: false,
            helper_vault_free: true,
          });
        } catch (error) {
          await uninstallSecretsManagerLocalState({
            allowPath,
            machine_id: interpreted.machineId,
          }).catch(() => {});
          const code = error && typeof error === 'object' && 'code' in error
            ? String(error.code)
            : 'self_test_failed';
          emit({ ok: false, code, authorization_ready: false, helper_vault_free: true }, 1);
        } finally {
          await fs.rm(dir, { recursive: true, force: true });
        }
      }
    }
  }
} else {
  replaceStuckMacosWizard();
  const bws = await checkBwsAvailable();
  const dialog = await runMacosDialog({
    selfTest: false,
    machineId: machineIdFromArgv(process.argv.slice(2)),
    bwsOk: bws.bws_available === true,
    timeoutMs: 3600000,
  });
  const trimmed = dialog.stdout.trim();
  if (!trimmed) {
    const scriptError = /execution error/i.test(dialog.stderr);
    emit({
      ok: false,
      code: scriptError ? 'wizard_script_error' : (
        dialog.stderr === 'timeout' ? 'wizard_timeout' : (
          dialog.code === 0 ? 'empty_wizard_output' : 'wizard_failed'
        )
      ),
      authorization_ready: false,
      helper_vault_free: true,
    }, 1);
  } else {
    let parsed;
    try {
      parsed = parseOsascriptJson(trimmed);
    } catch {
      emit({ ok: false, code: 'wizard_output_invalid', authorization_ready: false }, 1);
      parsed = null;
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      await applyFromDialog(parsed);
    }
  }
}
