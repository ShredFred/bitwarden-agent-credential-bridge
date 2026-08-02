import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateFakeSentinel } from '../src/constants.js';
import { startFakeLoginSite } from '../src/fake-login-site.mjs';

describe('fake login site', () => {
  it('issues a session cookie for the exact runtime credentials only', async () => {
    const username = 'user_abcdefgh';
    const password = generateFakeSentinel();
    const site = await startFakeLoginSite({
      credentials: { username, password },
      hiddenFields: { csrf: 'token-1' },
    });
    try {
      const form = await fetch(`${site.baseUrl}/login`);
      assert.equal(form.status, 200);
      const html = await form.text();
      assert.match(html, /name="csrf"/);
      assert.equal(html.includes(password), false);

      const bad = await fetch(`${site.baseUrl}/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'username=wronguserx&password=wrongpassx&csrf=token-1',
        redirect: 'manual',
      });
      assert.equal(bad.status, 401);
      assert.equal((await bad.text()).includes(password), false);

      const ok = await fetch(`${site.baseUrl}/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&csrf=token-1`,
        redirect: 'manual',
      });
      assert.equal(ok.status, 302);
      const setCookie = ok.headers.getSetCookie?.() ?? [ok.headers.get('set-cookie')];
      assert.ok(setCookie.some((line) => String(line).startsWith(`${site.sessionCookieName}=`)));
      const cookie = String(setCookie.find((line) => String(line).startsWith(`${site.sessionCookieName}=`)))
        .split(';', 1)[0];
      const home = await fetch(`${site.baseUrl}/home`, { headers: { cookie } });
      assert.equal(home.status, 200);
      const me = await fetch(`${site.baseUrl}/api/me`, { headers: { cookie } });
      assert.equal(me.status, 200);
      const body = await me.text();
      assert.equal(body.includes(password), false);
      assert.equal(body.includes(username), false);
    } finally {
      await site.close();
    }
  });
});
