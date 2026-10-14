// Black-box test (CLEAN_ROOM.md): @auth0/auth0-spa-js in a real browser
// against zeroauthy, and express-oauth2-jwt-bearer validating the token.
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';

const SPA = 'https://localhost:3443/';

async function ready(page) {
  await expect(page.locator('body')).toHaveAttribute('data-ready', /true|error/, { timeout: 20_000 });
  const state = await page.locator('body').getAttribute('data-ready');
  if (state !== 'true') throw new Error('SPA failed: ' + (await page.locator('#out').textContent()));
}

test('auth0-spa-js logs in with zeroauthy and calls an API', async ({ page }) => {
  await page.goto(SPA);
  await ready(page);
  // createAuth0Client's silent check must get an answer (login_required)
  // rather than wait for its timeout.
  expect(await page.evaluate(() => window.__za.initMs)).toBeLessThan(5_000);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(false);

  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'not the password');
  await page.click('button[type=submit]');
  await expect(page.locator('[role=alert]')).toContainText('Incorrect');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
  await page.waitForURL(SPA);
  await ready(page);

  const user = await page.evaluate(() => window.__za.client.getUser());
  expect(user.email).toBe('alice@e2e.local');
  expect(user.name).toBe('Alice Example');
  const token = await page.evaluate(() => window.__za.client.getTokenSilently());

  const api = express();
  api.get('/me', auth({ issuerBaseURL: 'https://localhost:8443', audience: 'https://api.e2e.local' }), (req, res) =>
    res.json(req.auth.payload));
  const server = api.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/me`, { headers: { authorization: `Bearer ${token}` } });
    expect(r.status).toBe(200);
    const payload = await r.json();
    expect(payload.sub).toBe(user.sub);
    expect(payload.scope.split(' ')).toContain('read:things');
  } finally {
    server.close();
  }

  // After a reload the in-memory cache is gone; the SDK restores the
  // login through silent authentication with the session cookie.
  await page.reload();
  await ready(page);
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
  expect((await page.evaluate(() => window.__za.client.getUser())).email).toBe('alice@e2e.local');
});
