#!/usr/bin/env node
/**
 * Tiny operator/agent CLI for Secrets Manager presence + secret entry.
 *
 * Fast paths (value-free stdout always):
 *   bw-sm exists mivia mivia_klicktipp_user
 *   bw-sm exists mivia prefix:mivia_klicktipp_
 *   bw-sm ask klicktipp --approve
 *   bw-sm ask-pair --project mivia --service demo --approve
 *   bw-sm presets
 *
 * --approve expands to the required SM write/resolve approval flag.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  SM_RESOLVE_APPROVAL_FLAG,
  SM_WRITE_APPROVAL_FLAG,
} from '../src/secrets-manager-defaults.mjs';
import { parseSmSecretEntryForm } from '../src/sm-secret-entry-form.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const presetsPath = path.join(
  root,
  'samples',
  'operational',
  'sm-secret-entry-presets.json',
);

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function hasApprove(argv) {
  return argv.includes('--approve') ||
    argv.includes('-y') ||
    argv.includes(SM_WRITE_APPROVAL_FLAG) ||
    argv.includes(SM_RESOLVE_APPROVAL_FLAG);
}

function loadPresets() {
  const raw = JSON.parse(fs.readFileSync(presetsPath, 'utf8'));
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('presets_invalid');
  }
  return raw;
}

function runNode(scriptRel, args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(root, scriptRel), ...args], {
      cwd: root,
      windowsHide: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

function usage() {
  emit({
    ok: false,
    code: 'usage',
    commands: [
      'bw-sm presets',
      'bw-sm exists <mivia|private-hq> <key|prefix:foo_>',
      'bw-sm ask <preset> --approve',
      'bw-sm ask-pair --project mivia --service klicktipp --approve',
      'bw-sm ask-pair --project mivia --service x --title "..." --info "..." --approve',
    ],
    hint: 'Use --approve (or -y) instead of the long approval flags.',
    agent_secret_visible: false,
  }, 1);
}

const argv = process.argv.slice(2);
const cmd = argv[0];

if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
  usage();
} else if (cmd === 'presets') {
  const presets = loadPresets();
  emit({
    ok: true,
    presets: Object.keys(presets).sort(),
    agent_secret_visible: false,
  });
} else if (cmd === 'exists') {
  if (!hasApprove(argv)) {
    emit({
      ok: false,
      code: 'approval_required',
      hint: 'Pass --approve',
      required_flag: SM_RESOLVE_APPROVAL_FLAG,
      agent_secret_visible: false,
    }, 1);
  } else {
    const project = argv[1];
    const target = argv[2];
    if (!project || !target) {
      usage();
    } else {
      const args = [SM_RESOLVE_APPROVAL_FLAG, '--project', project];
      if (target.startsWith('prefix:')) {
        args.push('--prefix', target.slice('prefix:'.length));
      } else {
        args.push('--key', target);
      }
      const result = await runNode('scripts/run-sm-secret-exists.mjs', args);
      process.stdout.write(result.stdout.endsWith('\n') ? result.stdout : `${result.stdout.trim()}\n`);
      process.exitCode = result.code;
    }
  }
} else if (cmd === 'ask') {
  if (!hasApprove(argv)) {
    emit({
      ok: false,
      code: 'approval_required',
      hint: 'Pass --approve',
      required_flag: SM_WRITE_APPROVAL_FLAG,
      agent_secret_visible: false,
    }, 1);
  } else {
    const name = argv[1];
    if (!name || name.startsWith('-')) {
      usage();
    } else {
      const presets = loadPresets();
      const form = presets[name];
      if (!form) {
        emit({
          ok: false,
          code: 'unknown_preset',
          preset: name,
          presets: Object.keys(presets).sort(),
          agent_secret_visible: false,
        }, 1);
      } else {
        parseSmSecretEntryForm(form);
        const result = await runNode('scripts/run-sm-secret-entry.mjs', [
          SM_WRITE_APPROVAL_FLAG,
          '--form-json',
          JSON.stringify(form),
        ]);
        process.stdout.write(result.stdout.endsWith('\n') ? result.stdout : `${result.stdout.trim()}\n`);
        process.exitCode = result.code;
      }
    }
  }
} else if (cmd === 'ask-pair') {
  if (!hasApprove(argv)) {
    emit({
      ok: false,
      code: 'approval_required',
      hint: 'Pass --approve',
      required_flag: SM_WRITE_APPROVAL_FLAG,
      agent_secret_visible: false,
    }, 1);
  } else {
    const idx = (flag) => {
      const i = argv.indexOf(flag);
      return i >= 0 ? argv[i + 1] : null;
    };
    const project = idx('--project');
    const service = idx('--service');
    const title = idx('--title') || `${service || 'service'} Zugang`;
    const info = idx('--info') ||
      `Benutzername und Passwort für ${service || 'service'} (kein API-Key). Werte nur in Secrets Manager.`;
    if (!project || !service || !/^[a-z][a-z0-9_-]{0,32}$/.test(service)) {
      emit({
        ok: false,
        code: 'usage',
        hint: 'ask-pair --project mivia|private-hq --service <slug> --approve',
        agent_secret_visible: false,
      }, 1);
    } else {
      const prefix = project === 'private-hq' || project === 'private_hq' ? 'phq' : 'mivia';
      const form = {
        version: 1,
        project: project === 'private_hq' ? 'private-hq' : project,
        title,
        info,
        fields: [
          {
            sm_key: `${prefix}_${service}_user`,
            label: 'Benutzername',
            kind: 'text',
            secret: false,
            required: true,
            hint: 'Public for the agent (account binding)',
          },
          {
            sm_key: `${prefix}_${service}_pass`,
            label: 'Passwort',
            kind: 'password',
            secret: true,
            required: true,
            min_length: 8,
            hint: 'Secret — not returned to the agent',
          },
        ],
      };
      parseSmSecretEntryForm(form);
      const result = await runNode('scripts/run-sm-secret-entry.mjs', [
        SM_WRITE_APPROVAL_FLAG,
        '--form-json',
        JSON.stringify(form),
      ]);
      process.stdout.write(result.stdout.endsWith('\n') ? result.stdout : `${result.stdout.trim()}\n`);
      process.exitCode = result.code;
    }
  }
} else {
  usage();
}
