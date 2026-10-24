// Local fallback runtime assertions, not live-observed Auth0 parity.
import { test, expect } from '@playwright/test';
import { ManagementClient } from 'auth0';
const m = new ManagementClient({ domain: 'localhost:8443', clientId: 'e2e-m17-admin', clientSecret: 'e2e-m17-admin-secret-not-for-production' });
test('settings, automatic blocks, breach refusal and hosted challenge replay', async ({ page, browser }) => {
  test.setTimeout(120_000);
  test.skip(process.env.E2E_M19_HARNESS !== '1', 'Use run-m19.sh for the local-only protection fixture');
  const saved = await m.tenants.settings.get();
  const brute = await m.attackProtection.bruteForceProtection.get();
  const breach = await m.attackProtection.breachedPasswordDetection.get();
  const bot = await m.attackProtection.botDetection.get();
  const captcha = await m.attackProtection.captcha.get();
  expect(captcha.active_provider_id).toBe('auth_challenge'); // fresh disposable fixture has no provider credentials
  let user;
  const contexts = [];
  async function login(password, proof) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true }); contexts.push(context);
    // Never request real provider assets. This replaces only the widget; the
    // form still submits to the real hosted handler and shared proof store.
    await context.route('https://www.google.com/**', route => route.fulfill({ contentType: 'application/javascript', body: '' }));
    const p = await context.newPage();
    await p.goto('https://localhost:8443/authorize?' + new URLSearchParams({ client_id: 'e2e-spa', response_type: 'code', redirect_uri: 'https://localhost:3443/', scope: 'openid', state: 'm19', code_challenge: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ', code_challenge_method: 'S256' }));
    await p.fill('#username', 'm19-browser@e2e.local'); await p.fill('#password', password);
    if (proof) await p.locator('form').evaluate((form, value) => { const input = document.createElement('input'); input.type = 'hidden'; input.name = 'g-recaptcha-response'; input.value = value; form.append(input); }, proof);
    await p.click('button[type=submit]'); return p;
  }
  try {
    user = await m.users.create({ connection: 'Username-Password-Authentication', email: 'm19-browser@e2e.local', password: 'M19-Breached-Password!', email_verified: true });
    await page.goto(process.env.E2E_ADMIN_SETUP_URL_M19);
    await page.fill('#password', 'Operator-Password-2026'); await page.fill('#password_confirm', 'Operator-Password-2026'); await page.click('button[type=submit]');
    await expect(page.locator('h1')).toHaveText('Password changed');
    await page.goto('https://system.localhost:8443/admin/'); await page.waitForURL(/\/u\/login/);
    await page.fill('#username', 'operator-m19@e2e.local'); await page.fill('#password', 'Operator-Password-2026'); await page.click('button[type=submit]'); await page.waitForURL(/\/admin\/t\/e2e\/$/);
    await page.goto('https://system.localhost:8443/admin/t/e2e/settings');
    await page.fill('#friendly_name', 'M19 Browser'); await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('saved');
    await page.getByRole('tab', { name: 'Sessions', exact: true }).click();
    await page.fill('#ephemeral_session_lifetime', '24'); await page.selectOption('#session_cookie-mode', 'non-persistent'); await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(async () => (await m.tenants.settings.get()).session_cookie.mode).toBe('non-persistent');
    await page.getByRole('tab', { name: /Language/ }).click();
    await page.fill('#enabled_locales', 'fr\nen'); await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect.poll(async () => (await m.tenants.settings.get()).enabled_locales).toEqual(['fr', 'en']);
    const hosted = await login('wrong');
    await expect(hosted.locator('html')).toHaveAttribute('lang', 'fr');
    await expect(hosted.locator('body')).toContainText('M19 Browser');
    await m.tenants.settings.update({ enabled_locales: ['en'] });
    await m.userBlocks.delete(user.user_id);
    await page.goto('https://system.localhost:8443/admin/t/e2e/attack-protection');
    await page.fill('#max_attempts', '1'); await page.getByRole('button', { name: 'Save', exact: true }).click();
    await m.attackProtection.bruteForceProtection.update({ enabled: true, shields: ['block'] });
    await login('wrong');
    expect((await m.userBlocks.list(user.user_id)).blocked_for.length).toBeGreaterThan(0);
    const denied = await login('M19-Breached-Password!'); await expect(denied).toHaveURL(/\/u\/login/);
    await page.goto(`https://system.localhost:8443/admin/t/e2e/users/${encodeURIComponent(user.user_id)}`);
    await page.getByRole('button', { name: 'View login blocks' }).click();
    await expect(page.locator('body')).toContainText('m19-browser@e2e.local');
    await page.getByRole('button', { name: 'Clear login blocks', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Clear login blocks', exact: true }).click();
    await expect.poll(async () => (await m.userBlocks.list(user.user_id)).blocked_for).toEqual([]);
    const success = await login('M19-Breached-Password!'); await success.waitForURL('https://localhost:3443/**');
    const cookie = (await success.context().cookies()).find(c => c.name === 'za_session'); expect(cookie?.expires).toBe(-1);
    await m.attackProtection.breachedPasswordDetection.update({ enabled: true, shields: ['block'] });
    const leaked = await login('M19-Breached-Password!'); await expect(leaked.locator('body')).toContainText('data breach'); await expect(leaked).toHaveURL(/\/u\/login/);
    await m.attackProtection.breachedPasswordDetection.update({ enabled: false });
    await page.goto('https://system.localhost:8443/admin/t/e2e/attack-protection'); await page.getByRole('tab', { name: 'CAPTCHA', exact: true }).click();
    await page.selectOption('#active_provider_id', 'recaptcha_v2'); await page.fill('#recaptcha_v2-site_key', 'm19-site'); await page.fill('#recaptcha_v2-secret', 'm19-private-credential'); await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.locator('#recaptcha_v2-secret')).toHaveValue(''); expect(await page.content()).not.toContain('m19-private-credential');
    await m.attackProtection.botDetection.update({ challenge_password_policy: 'always', monitoring_mode_enabled: false });
    const invalid = await login('M19-Breached-Password!', 'invalid'); await expect(invalid).toHaveURL(/\/u\/login/); await expect(invalid.locator('#captcha-help')).toBeVisible();
    const passed = await login('M19-Breached-Password!', 'm19-valid-browser'); await passed.waitForURL('https://localhost:3443/**');
    const replay = await login('M19-Breached-Password!', 'm19-valid-browser'); await expect(replay).toHaveURL(/\/u\/login/); await expect(replay.locator('#captcha-help')).toBeVisible();
    const fresh = await login('M19-Breached-Password!', 'm19-valid-browser-new'); await fresh.waitForURL('https://localhost:3443/**');
    // Hold a genuine tenant GET response while switching within the SPA.
    let release;
    const held = new Promise(resolve => { release = resolve; });
    let received;
    const started = new Promise(resolve => { received = resolve; });
    await page.route('https://localhost:8443/api/v2/tenants/settings', async route => {
      if (route.request().method() !== 'GET') return route.continue();
      const response = await route.fetch(); received(); await held;
      await route.fulfill({ response });
    });
    await page.getByRole('navigation', { name: 'Sections' }).getByRole('link', { name: 'Settings', exact: true }).click();
    await started;
    await page.route('https://cli.e2e.test/api/v2/tenants/settings', async route => {
      const response = await route.fetch({ url: 'https://localhost:8443/api/v2/tenants/settings', headers: { ...route.request().headers(), host: 'cli.e2e.test' } });
      await route.fulfill({ response });
    });
    await page.getByRole('button', { name: 'Switch tenant' }).click();
    await page.getByRole('menuitem').filter({ hasText: 'cli' }).click();
    await page.getByRole('navigation', { name: 'Sections' }).getByRole('link', { name: 'Settings', exact: true }).click();
    await expect(page.locator('#friendly_name')).not.toHaveValue('M19 Browser');
    const otherName = await page.locator('#friendly_name').inputValue();
    release(); await page.unroute('https://localhost:8443/api/v2/tenants/settings');
    await expect(page.locator('#friendly_name')).toHaveValue(otherName);

  } finally {
    await m.attackProtection.botDetection.update(bot); await m.attackProtection.breachedPasswordDetection.update(breach); await m.attackProtection.bruteForceProtection.update(brute);
    await m.tenants.settings.update({ friendly_name: saved.friendly_name, enabled_locales: saved.enabled_locales, ephemeral_session_lifetime: saved.ephemeral_session_lifetime, session_cookie: saved.session_cookie });
    await m.attackProtection.captcha.update({ active_provider_id: captcha.active_provider_id, recaptcha_v2: { site_key: '', secret: '' } });
    if (user) await m.users.delete(user.user_id);
    await Promise.all(contexts.map(c => c.close()));
  }
});
