#!/usr/bin/env node
/**
 * Install user-PATH wrappers so setup-sm-wizard / bw-sm work outside the repo.
 * Writes only to ~/.local/bin on macOS and Linux. Never prints tokens.
 */
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

function emit(payload, code = 0) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = code;
}

function wrapperBody(relScript) {
  const target = path.join(root, relScript);
  return `#!/bin/sh
cd ${JSON.stringify(root)} || exit 1
exec ${JSON.stringify(process.execPath)} ${JSON.stringify(target)} "$@"
`;
}

if (process.platform !== 'darwin' && process.platform !== 'linux') {
  emit({ ok: false, code: 'unsupported_platform' }, 1);
} else {
  const destDir = path.join(os.homedir(), '.local', 'bin');
  await fs.mkdir(destDir, { recursive: true, mode: 0o755 });
  const files = {
    'setup-sm-wizard': wrapperBody('scripts/run-sm-wizard.mjs'),
    'bw-sm': wrapperBody('bin/bw-sm.mjs'),
  };
  for (const [name, body] of Object.entries(files)) {
    const dest = path.join(destDir, name);
    await fs.writeFile(dest, body, { encoding: 'utf8', mode: 0o755 });
  }
  emit({
    ok: true,
    installed: Object.keys(files),
    dest: '~/.local/bin',
    hint: 'Run setup-sm-wizard from any directory. Token paste stays in the GUI.',
  });
}
