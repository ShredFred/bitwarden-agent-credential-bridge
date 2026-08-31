import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  LINUX_DIALOG_MAX_OUTPUT,
  resolveLinuxGuiTool,
  spawnLinuxDialog,
} from '../src/linux-sm-dialog.mjs';

describe('linux SM dialog runner', () => {
  it('refuses non-system binaries and reports no display without leaking env', async () => {
    const previousDisplay = process.env.DISPLAY;
    const previousWayland = process.env.WAYLAND_DISPLAY;
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    try {
      assert.equal(resolveLinuxGuiTool(), null);
      const blocked = await spawnLinuxDialog('/bin/echo', ['nope'], 1000);
      assert.equal(blocked.code, 1);
      assert.equal(blocked.stderr, 'spawn_failed');
      assert.equal(blocked.stdout, '');
      assert.equal(LINUX_DIALOG_MAX_OUTPUT, 16 * 1024);
    } finally {
      if (previousDisplay !== undefined) process.env.DISPLAY = previousDisplay;
      else delete process.env.DISPLAY;
      if (previousWayland !== undefined) process.env.WAYLAND_DISPLAY = previousWayland;
      else delete process.env.WAYLAND_DISPLAY;
    }
  });
});
