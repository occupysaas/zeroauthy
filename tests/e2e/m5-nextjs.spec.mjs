// Black-box test (CLEAN_ROOM.md): @auth0/nextjs-auth0 server-side against
// zeroauthy: login, session, access token, logout.
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';

const APP = 'http://localhost:3000/';

test('nextjs-auth0 logs in, gets an access token and logs out', async ({ page }) => {
  const logoutCalls = [];
  page.on('request', (r) => {
    if (/localhost:8443\/(oidc|v2)\/logout/.test(r.url())) logoutCalls.push(r.url());
  });

  await page.goto(APP);
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
  await page.waitForURL(APP);
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');

  // The SDK returns the access token held in its session.
  const r = await page.request.get(APP + 'api/token');
  expect(r.status()).toBe(200);
  const { token } = await r.json();
  const api = express();
  api.get('/me', auth({ issuerBaseURL: 'https://localhost:8443', audience: 'https://api.e2e.local' }), (req, res) =>
    res.json(req.auth.payload));
  const server = api.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const me = await fetch(`http://127.0.0.1:${server.address().port}/me`, { headers: { authorization: `Bearer ${token}` } });
    expect(me.status).toBe(200);
    expect((await me.json()).scope.split(' ')).toContain('read:things');
  } finally {
    server.close();
  }

  // Logout goes through zeroauthy (end_session_endpoint is advertised) and back.
  await page.click('#logout');
  await page.waitForURL(APP);
  await expect(page.locator('#login')).toBeVisible();
  expect(logoutCalls).toHaveLength(1);
  const logout = new URL(logoutCalls[0]);
  expect(logout.pathname).toBe('/oidc/logout');
  expect(logout.searchParams.get('id_token_hint')).toBeTruthy();

  // The zeroauthy session is gone too: logging in again shows the form.
  await page.click('#login');
  await page.waitForURL(/localhost:8443\/u\/login/);
});
