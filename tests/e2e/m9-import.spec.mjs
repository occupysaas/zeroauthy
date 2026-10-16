// Black-box test: hosted login on an import-mode custom database connection
// with auth0-spa-js. Two logins, one call to the legacy store.
import { test, expect } from '@playwright/test';

const SPA = 'https://localhost:3443/';
const LEGACY = 'http://127.0.0.1:8099';

async function legacyLogins(page) {
  const res = await page.request.get(`${LEGACY}/stats`, { headers: { authorization: 'Bearer e2e-legacy-token' } });
  expect(res.status()).toBe(200);
  return (await res.json()).login;
}

async function ready(page) {
  await expect(page.locator('body')).toHaveAttribute('data-ready', /true|error/, { timeout: 20_000 });
  if ((await page.locator('body').getAttribute('data-ready')) !== 'true') {
    throw new Error('SPA failed: ' + (await page.locator('#out').textContent()));
  }
}

async function loginOnImportConnection(page) {
  await page.goto(SPA);
  await ready(page);
  await page.evaluate(() => window.__za.client.loginWithRedirect({ authorizationParams: { connection: 'import-users' } }));
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'import-user@e2e.local');
  await page.fill('#password', 'Import-Password-1');
  await page.click('button[type=submit]');
  await page.waitForURL(SPA);
  await ready(page);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
  const user = await page.evaluate(() => window.__za.client.getUser());
  expect(user.sub).toBe('auth0|L-1002');
  expect(user.email).toBe('import-user@e2e.local');
}

test('import-mode login migrates the legacy user once', async ({ page }) => {
  const before = await legacyLogins(page);
  await loginOnImportConnection(page);

  await page.evaluate(() => window.__za.client.logout({ logoutParams: { returnTo: window.location.origin + '/' } }));
  await page.waitForURL(SPA);
  await ready(page);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(false);

  await loginOnImportConnection(page);
  expect(await legacyLogins(page) - before).toBe(1);
});
