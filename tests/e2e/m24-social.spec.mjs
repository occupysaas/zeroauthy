import { test, expect } from '@playwright/test';
import { createHash, randomBytes } from 'node:crypto';
test.use({ proxy: { server: 'http://127.0.0.1:9198' } });

const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
function authorize(extra = {}) {
 const q = new URLSearchParams({ client_id: 'm24-spa', redirect_uri: 'https://callback.e2e.test/', response_type: 'code', scope: 'openid profile email',
  state: 'app-state', nonce: 'app-nonce', code_challenge: challenge, code_challenge_method: 'S256', ...extra });
 return `https://sdk.e2e.test/authorize?${q}`;
}
async function signInUpstream(page, flavor, subject, decision = 'Allow') {
 await expect(page).toHaveTitle(`Mock ${flavor} sign-in`);
 await page.fill('#subject', subject);
 await page.getByRole('button', { name: decision, exact: true }).click();
}
async function backAtApp(page) {
 await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);
 const u = new URL(page.url());
 expect(u.searchParams.get('code')).toBeTruthy();
 expect(u.searchParams.get('state')).toBe('app-state');
}

test.describe('social federation through real code exchange', () => {
 test.skip(!process.env.E2E_M24, 'Run make e2e-social');
 for (const [connection, flavor, subject] of [['google-oauth2', 'google', 'alice'], ['acme-oauth', 'oauth2', 'bob'], ['corp', 'oidc', 'carol']]) {
  test(`${connection}: explicit selection, first and repeat login`, async ({ page }) => {
   for (let i = 0; i < 2; i++) {
    await page.context().clearCookies();
    await page.goto(authorize({ connection }));
    await signInUpstream(page, flavor, subject);
    await backAtApp(page);
   }
  });
 }

 test('login page buttons on a mixed application', async ({ page }) => {
  await page.goto(authorize());
  await expect(page.locator('#password')).toBeVisible();
  await page.getByRole('button', { name: 'Continue with Corp SSO', exact: true }).click();
  await signInUpstream(page, 'oidc', 'carol');
  await backAtApp(page);
 });

 test('keyboard: social buttons follow the password form', async ({ page }) => {
  await page.goto(authorize());
  await page.locator('#password').focus();
  let found = false;
  for (let i = 0; i < 6 && !found; i++) {
   await page.keyboard.press('Tab');
   found = (await page.evaluate(() => document.activeElement?.getAttribute('formaction'))) === '/u/login/social';
  }
  expect(found).toBe(true);
 });

 test('provider denial and callback replay fail safely', async ({ page }) => {
  await page.goto(authorize({ connection: 'corp' }));
  await signInUpstream(page, 'oidc', 'carol', 'Deny');
  await expect(page.locator('body')).toContainText('cancelled or refused');
  await expect(page.locator('body')).not.toContainText('mock user denied');

  let callback = '';
  page.on('request', (r) => { if (r.url().includes('/login/callback?')) callback = r.url(); });
  await page.goto(authorize({ connection: 'corp' }));
  await signInUpstream(page, 'oidc', 'carol');
  await backAtApp(page);
  expect(callback).toContain('code=');
  const replay = await page.goto(callback);
  expect(replay.status()).toBe(400);
  await expect(page.locator('body')).not.toContainText('upstream');
 });
});
