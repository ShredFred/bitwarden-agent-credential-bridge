/**
 * Linux agent-blind SM secret-entry: zenity/kdialog per field, or injected prompts.
 * Never logs secret values.
 */
import { resolveLinuxGuiTool, spawnLinuxDialog } from './linux-sm-dialog.mjs';

/**
 * @param {{
 *   form: { title: string, info?: string, fields: Array<{ sm_key: string, label: string, secret: boolean }> },
 *   timeoutMs?: number,
 *   promptField?: (field: { sm_key: string, label: string, secret: boolean }) => Promise<string | null>,
 * }} options
 */
export async function collectLinuxSecretEntryValues(options) {
  const form = options.form;
  if (typeof options.promptField === 'function') {
    /** @type {Record<string, string>} */
    const values = {};
    for (const field of form.fields) {
      const got = await options.promptField(field);
      if (got === null) {
        return Object.freeze({ ok: false, cancelled: true, code: 'cancelled', values: {} });
      }
      values[field.sm_key] = got;
    }
    return Object.freeze({ ok: true, cancelled: false, values });
  }
  const gui = resolveLinuxGuiTool();
  if (!gui) {
    return Object.freeze({ ok: false, cancelled: false, code: 'dialog_display_unavailable', values: {} });
  }
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : 3600000;
  /** @type {Record<string, string>} */
  const values = {};
  for (const field of form.fields) {
    const text = `${form.title}\n${field.label}`;
    const dialog = gui.kind === 'zenity'
      ? await spawnLinuxDialog(gui.bin, field.secret
        ? ['--password', '--title', 'Bitwarden Agent Bridge', '--text', text]
        : ['--entry', '--title', 'Bitwarden Agent Bridge', '--text', text], timeoutMs)
      : await spawnLinuxDialog(gui.bin, field.secret
        ? ['--password', text]
        : ['--inputbox', text, ''], timeoutMs);
    if (dialog.code !== 0) {
      return Object.freeze({
        ok: false,
        cancelled: dialog.stderr !== 'timeout' && dialog.stderr !== 'output_overflow',
        code: dialog.stderr === 'timeout'
          ? 'dialog_timeout'
          : (dialog.stderr === 'output_overflow' ? 'dialog_overflow' : 'cancelled'),
        values: {},
      });
    }
    values[field.sm_key] = dialog.stdout.replace(/\n$/, '');
  }
  return Object.freeze({ ok: true, cancelled: false, values });
}
