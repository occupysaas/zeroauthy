// Black-box test: the hosted forgot-password flow, reading the reset email
// written by zeroauthy's dir email driver.
import { test, expect } from '@playwright/test';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const SPA = 'https://localhost:3443/';

async function newestEmail(since) {
  const dir = process.env.E2E_MAIL_DIR;
  for (let i = 0; i < 50; i++) {
    const files = (await readdir(dir)).filter((f) => f.endsWith('.eml'));
    const fresh = [];
    for (const f of files) {
      const s = await stat(path.join(dir, f));
      if (s.mtimeMs >= since) fresh.push([s.mtimeMs, f]);
    }
    // Only a reset email: signups elsewhere send verification emails.
    fresh.sort((a, b) => b[0] - a[0]);
    for (const [, f] of fresh) {
      const mail = await readFile(path.join(dir, f), 'utf8');
      if (mail.includes('/u/reset-password?ticket')) return mail;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('no reset email arrived');
}

// decodeQP undoes quoted-printable encoding (soft breaks, =XX escapes).
const decodeQP = (s) => s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

test('forgot password: email link, new password, sign in', async ({ page }) => {
  await page.goto(SPA);
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true', { timeout: 20_000 });
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  const since = Date.now() - 1000;
  await page.click('text=Forgot password?');
  await page.fill('#email', 'reset-me@e2e.local');
  await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Check your email');

  const mail = decodeQP(await newestEmail(since));
  const link = mail.match(/https:\/\/localhost:8443\/u\/reset-password\?ticket=[A-Za-z0-9]{43}/)[0];
  await page.goto(link);
  await page.fill('#password', 'Brand-New-Password-7');
  await page.fill('#password_confirm', 'Brand-New-Password-7');
  await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Password changed');

  await page.goto(SPA);
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'reset-me@e2e.local');
  await page.fill('#password', 'Brand-New-Password-7');
  await page.click('button[type=submit]');
  await page.waitForURL(SPA);
});
