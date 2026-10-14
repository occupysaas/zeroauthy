// Black-box test (CLEAN_ROOM.md): @auth0/auth0-react in a real browser
// against zeroauthy, using rotating refresh tokens, then logging out.
import { test, expect } from '@playwright/test';

const APP = 'https://localhost:3443/react/';
const TOKEN = 'https://localhost:8443/oauth/token';

const isTokenCall = (r) => r.url() === TOKEN && r.request().method() === 'POST';

async function ready(page) {
  await expect(page.locator('[data-ready]')).toHaveAttribute('data-ready', /true|error/, { timeout: 20_000 });
  const err = page.locator('#error');
  if (await err.count()) throw new Error('React app failed: ' + (await err.textContent()));
}

// replay posts a refresh token directly, as an attacker holding it would.
async function replay(refreshToken) {
  const r = await fetch(TOKEN, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'refresh_token', client_id: 'e2e-react', refresh_token: refreshToken }),
  });
  return { status: r.status, body: await r.json() };
}

test('auth0-react rotates refresh tokens, detects reuse and logs out', async ({ page }) => {
  await page.goto(APP);
  await ready(page);
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  const [codeExchange] = await Promise.all([page.waitForResponse(isTokenCall), page.click('button[type=submit]')]);
  await page.waitForURL(APP);
  await ready(page);
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');

  const first = await codeExchange.json();
  expect(first.refresh_token).toBeTruthy();
  expect(first.scope.split(' ')).toContain('offline_access');

  // Bypassing the cache makes the SDK use its refresh token.
  const [refreshCall] = await Promise.all([
    page.waitForResponse(isTokenCall),
    page.evaluate(() => window.__za.getAccessTokenSilently({ cacheMode: 'off' })),
  ]);
  expect(refreshCall.request().postData()).toContain('refresh_token');
  const second = await refreshCall.json();
  expect(refreshCall.status()).toBe(200);
  expect(second.refresh_token).toBeTruthy();
  expect(second.refresh_token).not.toBe(first.refresh_token);

  // With localStorage caching, a reload keeps the user signed in.
  await page.reload();
  await ready(page);
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');

  // Replaying the rotated token is reuse: it fails, and so does its successor.
  const reused = await replay(first.refresh_token);
  expect(reused.status).toBe(400);
  expect(reused.body.error).toBe('invalid_grant');
  expect((await replay(second.refresh_token)).status).toBe(400);

  // Logout goes through zeroauthy's /v2/logout and ends its session:
  // logging in again shows the form.
  const logoutCalls = [];
  page.on('request', (r) => {
    if (/localhost:8443\/(oidc|v2)\/logout/.test(r.url())) logoutCalls.push(r.url());
  });
  await page.click('#logout');
  await page.waitForURL(APP);
  await ready(page);
  await expect(page.locator('#login')).toBeVisible();
  expect(logoutCalls).toHaveLength(1);
  const logout = new URL(logoutCalls[0]);
  expect(logout.pathname).toBe('/v2/logout');
  expect(logout.searchParams.get('client_id')).toBe('e2e-react');
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
});
