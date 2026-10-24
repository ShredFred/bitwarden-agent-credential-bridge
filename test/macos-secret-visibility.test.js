import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

test('native secret toggle preserves edits, clears inactive fields, and hides again', { skip: process.platform !== 'darwin' }, () => {
  const source = readFileSync(new URL('../scripts/macos-sm-secret-entry-dialog.jxa', import.meta.url), 'utf8');
  const dir = mkdtempSync(path.join(tmpdir(), 'bridge-toggle-test-'));
  try {
    const script = path.join(dir, 'toggle.jxa');
    writeFileSync(script, source.slice(0, source.indexOf('const opts = parseArgs()')) + `
const secure = $.NSSecureTextField.alloc.initWithFrame($.NSMakeRect(0, 0, 200, 30))
const plain = $.NSTextField.alloc.initWithFrame(secure.frame)
const button = $.NSButton.alloc.init
secure.stringValue = 'generated-fake-demo-only'
plain.hidden = true
const row = { box: secure, secureBox: secure, plainBox: plain, button: button, caption: 'Demo', revealed: false }
visibilityRows.push(row)
button.tag = 0
visibilityTarget.toggleSecret(button)
const shown = row.revealed && !plain.hidden && secure.hidden && unwrap(plain.stringValue) === 'generated-fake-demo-only' && unwrap(secure.stringValue) === ''
plain.stringValue = 'generated-fake-edited-only'
visibilityTarget.toggleSecret(button)
const hidden = !row.revealed && plain.hidden && !secure.hidden && unwrap(secure.stringValue) === 'generated-fake-edited-only' && unwrap(plain.stringValue) === ''
const icon = makeDialogIcon()
writeJson({ shown: shown, hidden: hidden, iconAvailable: Boolean(icon) })
`);
    const result = spawnSync('/usr/bin/osascript', ['-l', 'JavaScript', script], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.includes('generated-fake'), false);
    assert.deepEqual(JSON.parse(result.stdout), { shown: true, hidden: true, iconAvailable: true });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
