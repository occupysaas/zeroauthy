// Plan 18: a real console operator imports hashes, examines errors, exports
// a file and sends verification mail; imported users sign in through the SPA.
import { test, expect } from '@playwright/test';
import { readFile, readdir } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';

const fixtureURL = new URL('fixtures/import-users.json', import.meta.url);
const fixture = JSON.parse(await readFile(fixtureURL));

test('an operator imports and exports users and sends verification email', async ({ page, browser }) => {
  const setup = process.env.E2E_ADMIN_SETUP_URL_M18;
  expect(setup, 'run-browser.sh creates the Plan 18 operator').toBeTruthy();
  await page.goto(setup);
  await page.fill('#password', 'Operator-Password-2026');
  await page.fill('#password_confirm', 'Operator-Password-2026');
  await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Password changed');
  await page.goto('https://system.localhost:8443/admin/');
  await page.waitForURL(/\/u\/login/);
  await page.fill('#username', 'operator-m18@e2e.local');
  await page.fill('#password', 'Operator-Password-2026');
  await page.click('button[type=submit]');
  await page.waitForURL(/\/admin\/t\/e2e\/$/);
  await page.getByRole('navigation', { name: 'Sections' }).getByRole('link', { name: 'Users' }).click();
  await page.getByRole('link', { name: 'Import and export' }).click();
  await page.locator('#import-file').setInputFiles(fixtureURL.pathname);
  await page.selectOption('#import-connection', { label: 'Username-Password-Authentication' });
  await page.getByRole('button', { name: 'Start import', exact: true }).click();
  const imported = page.locator('tr[data-job]').filter({ hasText: 'Import' });
  await expect(imported).toContainText('4 added, 0 updated, 1 failed of 5', { timeout: 15000 });
  await imported.getByRole('button', { name: 'Errors', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('PATTERN');
  await expect(dialog).toContainText('*****');
  await expect(dialog).not.toContainText('invalid-secret-hash');
  await page.keyboard.press('Escape');

  for (const record of fixture.slice(0, 2)) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    try {
      const app = await context.newPage();
      await app.goto('https://localhost:3443/');
      await expect(app.locator('body')).toHaveAttribute('data-ready', 'true');
      await app.click('#login');
      await app.waitForURL(/\/u\/login/);
      await app.fill('#username', record.email);
      await app.fill('#password', 'Pa55w0rd!');
      await app.click('button[type=submit]');
      await app.waitForURL('https://localhost:3443/');
      await expect(app.locator('body')).toHaveAttribute('data-ready', 'true');
      expect((await app.evaluate(() => window.__za.client.getUser())).email).toBe(record.email);
    } finally { await context.close(); }
  }

  await page.selectOption('#export-connection', { label: 'Username-Password-Authentication' });
  for (const checkbox of await page.locator('fieldset input[type=checkbox]').all()) {
    const label = await checkbox.locator('..').innerText();
    await checkbox.setChecked(['email', 'email_verified'].includes(label.trim()));
  }
  await page.getByRole('button', { name: 'Start export', exact: true }).click();
  const exported = page.locator('tr[data-job]').filter({ hasText: 'Export' });
  await expect(exported.getByRole('button', { name: 'Download' })).toBeVisible({ timeout: 15000 });
  const pendingDownload = page.waitForEvent('download');
  await exported.getByRole('button', { name: 'Download' }).click();
  const download = await pendingDownload;
  const csv = gunzipSync(await readFile(await download.path())).toString();
  expect(csv.split(/\r?\n/)[0]).toBe('email,email_verified');
  for (const record of fixture.slice(0, 4)) expect(csv).toContain(record.email);
  expect(csv).not.toContain('$2a$');

  await page.getByRole('navigation', { name: 'Sections' }).getByRole('link', { name: 'Users' }).click();
  await page.getByRole('link', { name: fixture[0].email, exact: true }).click();
  await page.getByRole('button', { name: 'Send verification email', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Verification email queued' })).toBeVisible();
  await expect.poll(async () => {
    const dir = process.env.E2E_MAIL_DIR;
    const messages = await Promise.all((await readdir(dir)).filter(f => f.endsWith('.eml')).map(f => readFile(`${dir}/${f}`, 'utf8')));
    return messages.some(m => m.includes(fixture[0].email) && m.includes('/u/email-verification'));
  }).toBe(true);
});
