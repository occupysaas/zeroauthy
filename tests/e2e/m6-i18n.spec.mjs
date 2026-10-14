// Black-box test (CLEAN_ROOM.md): auth0-spa-js passes ui_locales through
// its public API; zeroauthy renders the login page in French.
import { test, expect } from '@playwright/test';

const SPA = 'https://localhost:3443/';

async function ready(page) {
  await expect(page.locator('body')).toHaveAttribute('data-ready', /true|error/, { timeout: 20_000 });
}

test('ui_locales=fr renders a French login page, then login completes', async ({ page }) => {
  await page.goto(SPA);
  await ready(page);
  await page.evaluate(() => window.__za.client.loginWithRedirect({ authorizationParams: { ui_locales: 'fr' } }));
  await page.waitForURL(/localhost:8443\/u\/login/);
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  await expect(page.locator('h1')).toHaveText('Connexion à E2E');
  await expect(page.locator('button[type=submit]')).toHaveText('Continuer');
  await expect(page.locator('label[for=password]')).toHaveText('Password'); // English fallback
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
  await page.waitForURL(SPA);
  await ready(page);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
});

test.describe('browser language', () => {
  test.use({ locale: 'fr-FR' });
  test('Accept-Language fr-FR selects the enabled fr', async ({ page }) => {
    await page.goto(SPA);
    await ready(page);
    await page.click('#login');
    await page.waitForURL(/localhost:8443\/u\/login/);
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  });
});
