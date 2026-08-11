#!/usr/bin/env node
/**
 * Agent-callable Windows dialog to paste secrets into Secrets Manager.
 *
 * The agent supplies only a value-free form (title/info/fields/keys).
 * The operator pastes values in a WinForms window. Secrets go to SM via
 * live:sm-write stdin. Agent stdout is value-free.
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
import {
  parseSmSecretEntryForm,
  sanitizeSmSecretEntryPublicValues,
  SmSecretEntryFormError,
} from '../src/sm-secret-entry-form.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const dialogScript = path.join(root, 'scripts', 'windows-sm-secret-entry-dialog.ps1');

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function argValue(name) {
  const idx = process.argv.indexOf(name);
  if (idx < 0 || idx + 1 >= process.argv.length) return null;
  return process.argv[idx + 1];
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

if (!process.argv.includes(SM_WRITE_APPROVAL_FLAG)) {
  emit({
    ok: false,
    code: 'approval_flag_required',
    required_flag: SM_WRITE_APPROVAL_FLAG,
    authorization_ready: false,
    helper_vault_free: true,
    agent_secret_visible: false,
  }, 1);
} else if (process.platform !== 'win32') {
  emit({
    ok: false,
    code: 'unsupported_platform',
    hint: 'Secret-entry dialog is Windows WinForms only in this slice',
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
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup of value-free form temp
    }

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

    // Defense in depth: only forward allow-listed public_values (usernames/labels).
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
    if (stderr && stderr.trim().length > 0 && safe.ok !== true) {
      // Do not echo stderr content (may contain paths); only mark presence.
      safe.stderr_present = true;
    }
    emit(safe, safe.ok ? 0 : 1);
  });
}
