/**
 * Linux same-user SM first-run wizard. Token never logged.
 * Prefers zenity/kdialog when a display is set. Headless hosts use
 * `npm run setup:sm` (hidden TTY), not this GUI path.
 */
import { interpretMacosWizardDialog } from './macos-sm-wizard.mjs';
import { resolveLinuxGuiTool, spawnLinuxDialog } from './linux-sm-dialog.mjs';

export const LINUX_WIZARD_SELF_TEST_TOKEN = '0.fake-linux-wizard-self-test==';
export const LINUX_WIZARD_SELF_TEST_MACHINE_ID = 'pc-selftest-wizard';

const MACHINE_ID = /^[a-z][a-z0-9_-]{0,63}$/;

async function promptGui(gui, { machineId, bwsOk, timeoutMs }) {
  const idDialog = await spawnLinuxDialog(gui.bin, [
    '--entry',
    '--title', 'Bitwarden Agent Bridge',
    '--text', bwsOk
      ? 'Confirm local machine id (not the Bitwarden secret key):'
      : 'bws CLI missing. Confirm machine id anyway, then install bws:',
    '--entry-text', machineId,
  ], timeoutMs);
  if (idDialog.code !== 0) {
    return { ok: false, code: idDialog.stderr === 'timeout' ? 'wizard_timeout' : 'cancelled' };
  }
  const nextId = idDialog.stdout.trim().toLowerCase();
  if (!MACHINE_ID.test(nextId)) {
    return { ok: false, code: 'invalid_machine_id' };
  }
  const tokenDialog = gui.kind === 'zenity'
    ? await spawnLinuxDialog(gui.bin, [
      '--password',
      '--title', 'Bitwarden Agent Bridge',
      '--text', 'Paste the Secrets Manager machine access token. Do not paste it into chat.',
    ], timeoutMs)
    : await spawnLinuxDialog(gui.bin, [
      '--password',
      'Paste the Secrets Manager machine access token. Do not paste it into chat.',
    ], timeoutMs);
  if (tokenDialog.code !== 0) {
    return { ok: false, code: tokenDialog.stderr === 'timeout' ? 'wizard_timeout' : 'cancelled' };
  }
  return interpretMacosWizardDialog({
    ok: true,
    machine_id: nextId,
    token: tokenDialog.stdout.trim(),
    server_url: '',
  });
}

/**
 * @param {{
 *   selfTest?: boolean,
 *   machineId: string,
 *   bwsOk?: boolean,
 *   timeoutMs?: number,
 *   promptToken?: () => Promise<string>,
 *   promptMachineId?: () => Promise<string>,
 * }} options
 */
export async function collectLinuxWizardAnswers(options) {
  if (options.selfTest === true) {
    return interpretMacosWizardDialog({
      ok: true,
      machine_id: options.machineId || LINUX_WIZARD_SELF_TEST_MACHINE_ID,
      token: LINUX_WIZARD_SELF_TEST_TOKEN,
      server_url: '',
    });
  }
  if (typeof options.promptToken === 'function') {
    const machineId = typeof options.promptMachineId === 'function'
      ? await options.promptMachineId()
      : options.machineId;
    const token = await options.promptToken();
    return interpretMacosWizardDialog({
      ok: true,
      machine_id: machineId,
      token,
      server_url: '',
    });
  }
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : 3600000;
  const gui = resolveLinuxGuiTool();
  if (gui) {
    return promptGui(gui, {
      machineId: options.machineId,
      bwsOk: options.bwsOk === true,
      timeoutMs,
    });
  }
  return Object.freeze({ ok: false, code: 'wizard_display_unavailable' });
}
