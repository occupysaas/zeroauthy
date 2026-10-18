// tests/e2e/m13-console.spec.mjs: the admin console in Chromium (Plan 13,
// Review Focus 5). An operator created with `zeroauthy admin create` (run
// by run-browser.sh, E2E_ADMIN_SETUP_URL) opens the setup link in a fresh
// browser, chooses a password, signs in at /admin, manages an application,
// reloads a deep link, switches tenant and signs out. Without a base domain
// the system host comes from server.system_host (system.localhost:8443).
import { test, expect } from '@playwright/test';

const ADMIN = 'https://system.localhost:8443/admin/';
const EMAIL = 'operator@e2e.local';
const PASSWORD = 'Operator-Password-2026';

test('an operator manages applications in the console', async ({ page }) => {
  const setup = process.env.E2E_ADMIN_SETUP_URL;
  test.skip(!setup, 'E2E_ADMIN_SETUP_URL is set by run-browser.sh');

  const cspViolations = [];
  page.on('console', (m) => {
    if (/Content Security Policy|Refused to (load|execute|apply)/i.test(m.text())) cspViolations.push(m.text());
  });

  // 1. The one-time setup link: choose a password.
  await page.goto(setup);
  await page.fill('#password', PASSWORD);
  await page.fill('#password_confirm', PASSWORD);
  await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Password changed');

  // 2. Sign in at /admin: the silent attempt fails, then the login page.
  await page.goto(ADMIN);
  await page.waitForURL(/\/u\/login/);
  await page.fill('#username', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL(/\/admin\/t\/e2e\/$/);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('E2E');
  await expect(page.getByRole('button', { name: 'Account' })).toContainText(EMAIL);
  await expect(page.getByText('The seed file defines this tenant')).toBeVisible();

  // 3. Create an application.
  await page.getByRole('navigation', { name: 'Sections' }).getByRole('link', { name: 'Applications' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/applications$/);
  await expect(page.getByRole('link', { name: 'E2E SPA' })).toBeVisible();
  await page.getByRole('link', { name: 'Create application' }).click();
  await page.fill('#app-name', 'Console app');
  await page.getByRole('radio', { name: /Regular web app/ }).check();
  await page.getByRole('button', { name: 'Create application' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/applications\/[A-Za-z0-9]{32}$/);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Console app');
  const detailURL = page.url();

  // 4. Edit its callbacks; a bad one is reported on the field.
  await page.fill('#app-callbacks', 'not a url');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.locator('#app-callbacks-error')).toContainText('not a url');
  await page.fill('#app-callbacks', 'https://console-app.e2e.test/callback');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved' })).toBeVisible();

  // 5. Reveal the secret, then rotate it.
  await page.getByRole('button', { name: 'Reveal' }).click();
  const secret = page.getByTestId('secret');
  await expect(secret).toHaveText(/^[A-Za-z0-9]{64}$/);
  const before = await secret.textContent();
  await page.getByRole('tab', { name: 'Danger zone' }).click();
  await page.getByRole('button', { name: 'Rotate secret' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Rotate secret' }).click();
  await expect(page.getByRole('tab', { name: 'Settings' })).toHaveAttribute('data-state', 'active');
  await page.getByRole('button', { name: 'Reveal' }).click();
  await expect(secret).toHaveText(/^[A-Za-z0-9]{64}$/);
  expect(await secret.textContent()).not.toBe(before);

  // 6. A hard refresh on the deep link loads through the history fallback
  //    and signs in again silently.
  await page.reload();
  await page.waitForURL(detailURL);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Console app');
  await expect(page.locator('#app-callbacks')).toHaveValue('https://console-app.e2e.test/callback');

  // 7. Delete it by typing its name.
  await page.getByRole('tab', { name: 'Danger zone' }).click();
  await page.getByRole('button', { name: 'Delete application' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: 'Delete application' })).toBeDisabled();
  await dialog.locator('#delete-confirm').fill('Console app');
  await dialog.getByRole('button', { name: 'Delete application' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/applications$/);
  await expect(page.getByRole('link', { name: 'E2E SPA' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Console app' })).toHaveCount(0);

  // 8. Switch tenant, keeping the section: the system tenant answers on
  //    the console's own host (cli.e2e.test is not resolvable here).
  await page.getByRole('button', { name: 'Switch tenant' }).click();
  await page.getByRole('menuitem', { name: /^system/ }).click();
  await page.waitForURL(/\/admin\/t\/system\/applications$/);
  await expect(page.getByRole('link', { name: 'zeroauthy console' })).toBeVisible();

  // 9. Sign out: the session ends, so /admin asks for a login again.
  await page.getByRole('button', { name: 'Account' }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await page.waitForURL(/\/u\/login/);

  expect(cspViolations).toEqual([]);
});
