#!/usr/bin/env node
/**
 * Agent-callable dialog to paste secrets into Secrets Manager.
 *
 * The agent supplies only a value-free form (title/info/fields/keys).
 * The operator pastes values in a native window (WinForms or macOS NSAlert).
 * Secrets go to SM via live:sm-write stdin. Agent stdout is value-free.
 *
 * Usage:
 *   node scripts/run-sm-secret-entry.mjs --i-approve-secrets-manager-machine-write \
 *     --form-json '{"version":1,"project":"mivia","title":"...","info":"...","fields":[...]}'
 *
 *   node scripts/run-sm-secret-entry.mjs --i-approve-secrets-manager-machine-write \
 *     --form-file path/to/form.json
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { SM_WRITE_APPROVAL_FLAG } from '../src/secrets-manager-defaults.mjs';
import { parseOsascriptJson } from '../src/macos-osascript-json.mjs';
import {
  parseSmSecretEntryForm,
  sanitizeSmSecretEntryPublicValues,
  validateSmSecretEntryValues,
  SmSecretEntryFormError,
} from '../src/sm-secret-entry-form.mjs';
import { collectLinuxSecretEntryValues } from '../src/linux-sm-secret-entry.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const dialogScript = path.join(root, 'scripts', 'windows-sm-secret-entry-dialog.ps1');
const macosDialogScript = path.join(root, 'scripts', 'macos-sm-secret-entry-dialog.jxa');
const writeScriptRel = 'scripts/run-secrets-manager-write.mjs';

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function argValue(name) {
  const idx = process.argv.indexOf(name);
  if (idx < 0 || idx + 1 >= process.argv.length) return null;
  return process.argv[idx + 1];
}

function emitSafePayload(form, payload, stderrPresent, code) {
  const publicValues = sanitizeSmSecretEntryPublicValues(form, payload.public_values);
  const safe = {
    ok: payload.ok === true,
    cancelled: payload.cancelled === true,
    code: typeof payload.code === 'string' ? payload.code : undefined,
    project: typeof payload.project === 'string' ? payload.project : form.project,
    title: typeof payload.title === 'string' ? payload.title : form.title,
    written: Array.isArray(payload.written)
      ? payload.written.filter((k) => typeof k === 'string')
      : [],
    actions:
      payload.actions && typeof payload.actions === 'object' && !Array.isArray(payload.actions)
        ? Object.fromEntries(
          Object.entries(payload.actions).filter(
            ([k, v]) => typeof k === 'string' && typeof v === 'string',
          ),
        )
        : {},
    public_values: publicValues,
    secret_keys: form.fields.filter((f) => f.secret).map((f) => f.sm_key)
      .filter((k) => Array.isArray(payload.written) && payload.written.includes(k)),
    field_meta: form.fields.map((f) => ({
      sm_key: f.sm_key,
      label: f.label,
      secret: f.secret,
      kind: f.kind,
    })),
    field_count: form.fields.length,
    live_secret_written: payload.live_secret_written === true,
    authorization_ready: false,
    helper_vault_free: true,
    agent_secret_visible: false,
    env_inject_forbidden: true,
  };
  if (stderrPresent && safe.ok !== true) {
    safe.stderr_present = true;
  }
  emit(safe, code);
}

function spawnCaptured(command, args, options) {
  return new Promise((resolve) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
    child.on('error', () => {
      resolve({ code: 1, stdout, stderr: 'spawn_failed' });
    });
  });
}

function writeSmSecretValue(project, key, value) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [
      path.join(root, writeScriptRel),
      SM_WRITE_APPROVAL_FLAG,
      '--project', project,
      '--key', key,
    ], {
      cwd: root,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });
    let stdout = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', () => {});
    child.on('close', (code) => {
      let action = 'written';
      let failCode = 'write_failed';
      try {
        const parsed = JSON.parse(stdout.trim());
        if (typeof parsed.action === 'string') action = parsed.action;
        if (typeof parsed.code === 'string') failCode = parsed.code;
      } catch {
        // keep defaults
      }
      resolve({
        ok: code === 0,
        action,
        code: failCode,
      });
    });
    child.stdin.write(value);
    child.stdin.end();
  });
}

async function writeCollectedValues(form, values) {
  const check = validateSmSecretEntryValues(form, values);
  if (check.ok !== true) {
    return {
      ok: false,
      cancelled: false,
      code: check.code || 'invalid_values',
      written: [],
      actions: {},
      public_values: {},
      live_secret_written: false,
    };
  }
  const written = [];
  const actions = {};
  for (const field of form.fields) {
    const value = values[field.sm_key];
    if (typeof value !== 'string' || value.length < 1) continue;
    const result = await writeSmSecretValue(form.project, field.sm_key, value);
    if (!result.ok) {
      return {
        ok: false,
        cancelled: false,
        code: result.code,
        written,
        actions,
        public_values: {},
        live_secret_written: false,
      };
    }
    written.push(field.sm_key);
    actions[field.sm_key] = result.action;
  }
  return {
    ok: true,
    cancelled: false,
    project: form.project,
    title: form.title,
    written,
    actions,
    public_values: Object.fromEntries(
      form.fields
        .filter((f) => !f.secret && typeof values[f.sm_key] === 'string' && values[f.sm_key].length > 0)
        .map((f) => [f.sm_key, values[f.sm_key]]),
    ),
    live_secret_written: written.length > 0,
  };
}

function loadForm() {
  const formJson = argValue('--form-json');
  const formFile = argValue('--form-file');
  if (formJson && formFile) {
    throw new SmSecretEntryFormError('form_source_ambiguous');
  }
  if (formJson) {
    let parsed;
    try {
      parsed = JSON.parse(formJson);
    } catch {
      throw new SmSecretEntryFormError('form_json_invalid');
    }
    return parseSmSecretEntryForm(parsed);
  }
  if (formFile) {
    const text = fs.readFileSync(formFile, 'utf8');
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new SmSecretEntryFormError('form_file_invalid');
    }
    return parseSmSecretEntryForm(parsed);
  }
  throw new SmSecretEntryFormError('form_required');
}

function cleanupFormTemp(tmpDir) {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // best-effort cleanup of value-free form temp
  }
}

if (!process.argv.includes(SM_WRITE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_WRITE_APPROVAL_FLAG,
    authorization_ready: false,
    helper_vault_free: true,
    agent_secret_visible: false,
  }, 1);
} else if (process.platform !== 'win32' && process.platform !== 'darwin' && process.platform !== 'linux') {
  emit({
    ok: false,
    code: 'unsupported_platform',
    authorization_ready: false,
    helper_vault_free: true,
    agent_secret_visible: false,
  }, 1);
} else {
  let form;
  try {
    form = loadForm();
  } catch (error) {
    emit({
      ok: false,
      code: error instanceof SmSecretEntryFormError ? error.code : 'form_invalid',
      authorization_ready: false,
      helper_vault_free: true,
      agent_secret_visible: false,
    }, 1);
    process.exit();
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bw-sm-entry-'));
  const formPath = path.join(tmpDir, 'form.json');
  fs.writeFileSync(formPath, `${JSON.stringify(form)}\n`, { encoding: 'utf8', mode: 0o600 });

  if (process.platform === 'darwin') {
    const dialog = await spawnCaptured('/usr/bin/osascript', [
      '-l', 'JavaScript',
      macosDialogScript,
      '--',
      '--form-path', formPath,
    ], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    cleanupFormTemp(tmpDir);
    const trimmed = dialog.stdout.trim();
    if (!trimmed) {
      emit({
        ok: false,
        code: dialog.code === 0 ? 'empty_dialog_output' : 'dialog_failed',
        authorization_ready: false,
        helper_vault_free: true,
        agent_secret_visible: false,
      }, 1);
    } else {
      let parsed;
      try {
        parsed = parseOsascriptJson(trimmed);
      } catch {
        emit({
          ok: false,
          code: 'dialog_output_invalid',
          authorization_ready: false,
          helper_vault_free: true,
          agent_secret_visible: false,
        }, 1);
        parsed = null;
      }
      if (parsed) {
        if (parsed.ok !== true) {
          emitSafePayload(form, {
            ok: false,
            cancelled: parsed.cancelled === true,
            code: typeof parsed.code === 'string' ? parsed.code : 'dialog_failed',
            written: [],
            public_values: {},
            live_secret_written: false,
          }, Boolean(dialog.stderr && dialog.stderr.trim()), 1);
        } else {
          const values = parsed.values && typeof parsed.values === 'object' && !Array.isArray(parsed.values)
            ? parsed.values
            : {};
          parsed.values = null;
          const writtenPayload = await writeCollectedValues(form, values);
          emitSafePayload(form, writtenPayload, false, writtenPayload.ok ? 0 : 1);
        }
      }
    }
  } else if (process.platform === 'linux') {
    const collected = await collectLinuxSecretEntryValues({ form });
    cleanupFormTemp(tmpDir);
    if (collected.ok !== true) {
      emitSafePayload(form, {
        ok: false,
        cancelled: collected.cancelled === true,
        code: typeof collected.code === 'string' ? collected.code : 'dialog_failed',
        written: [],
        public_values: {},
        live_secret_written: false,
      }, false, 1);
    } else {
      const writtenPayload = await writeCollectedValues(form, collected.values);
      emitSafePayload(form, writtenPayload, false, writtenPayload.ok ? 0 : 1);
    }
  } else {
    const systemRoot = process.env.SystemRoot || 'C:\\Windows';
    const powershell = path.join(
      systemRoot,
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe',
    );
    const localBwsDir = path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Bitwarden');
    const env = { ...process.env };
    if (localBwsDir && fs.existsSync(localBwsDir)) {
      env.Path = `${localBwsDir};${env.Path || env.PATH || ''}`;
    }

    const child = spawn(powershell, [
      '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
      '-File', dialogScript,
      '-FormPath', formPath,
      '-BridgeRoot', root,
      '-WriteApprovalFlag', SM_WRITE_APPROVAL_FLAG,
    ], {
      cwd: root,
      windowsHide: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => {
      cleanupFormTemp(tmpDir);
      const trimmed = stdout.trim();
      if (!trimmed) {
        emit({
          ok: false,
          code: code === 0 ? 'empty_dialog_output' : 'dialog_failed',
          authorization_ready: false,
          helper_vault_free: true,
          agent_secret_visible: false,
        }, 1);
        return;
      }
      let payload;
      try {
        payload = JSON.parse(trimmed);
      } catch {
        emit({
          ok: false,
          code: 'dialog_output_invalid',
          authorization_ready: false,
          helper_vault_free: true,
          agent_secret_visible: false,
        }, 1);
        return;
      }
      emitSafePayload(
        form,
        payload,
        Boolean(stderr && stderr.trim().length > 0),
        payload.ok === true ? 0 : 1,
      );
    });
  }
}
