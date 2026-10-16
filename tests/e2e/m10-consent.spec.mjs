// Black-box test (CLEAN_ROOM.md): Auth0's SDKs against zeroauthy's consent,
// third-party and confirmation flows. Clients come from Auth0's most-starred
// repositories: express-openid-connect, auth0-spa-js, express-jwt with
// jwks-rsa (on node-jsonwebtoken).
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import express from 'express';
import oidcSdk from 'express-openid-connect'; // CommonJS: no named exports under ESM
const { auth: oidc, requiresAuth } = oidcSdk;
import { expressjwt } from 'express-jwt';
import jwksRsa from 'jwks-rsa';

const IDP = 'https://localhost:8443';

async function login(page) {
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
}

test('express-openid-connect: a third-party web app gets consent once', async ({ page }) => {
  const app = express();
  app.use(oidc({
    issuerBaseURL: IDP, baseURL: 'http://localhost:3001', clientID: 'e2e-3p-web',
    clientSecret: 'e2e-3p-web-secret-not-for-production', secret: randomBytes(32).toString('hex'),
    authRequired: false, authorizationParams: { response_type: 'code', scope: 'openid profile email' },
  }));
  app.get('/me', requiresAuth(), (req, res) => res.json(req.oidc.user));
  const server = app.listen(3001, '127.0.0.1');
  await once(server, 'listening');
  try {
    await page.goto('http://localhost:3001/me');
    await login(page);
    await page.waitForURL(/localhost:8443\/u\/consent/);
    await expect(page.locator('[role=note]')).toContainText('localhost'); // external-app notice names the callback domain
    await page.click('button[value=accept]');
    await page.waitForURL('http://localhost:3001/me');
    expect(JSON.parse(await page.locator('body').innerText()).email).toBe('alice@e2e.local');

    // express-openid-connect's /logout ends only the app session when the
    // issuer is not an Auth0 domain (idpLogout is off), so the zeroauthy
    // session survives. The next login must not show consent again.
    await page.goto('http://localhost:3001/logout');
    const seen = [];
    page.on('framenavigated', (f) => { if (f === page.mainFrame()) seen.push(f.url()); });
    await page.goto('http://localhost:3001/me');
    await page.waitForURL('http://localhost:3001/me');
    expect(seen.filter((u) => u.includes('/u/'))).toEqual([]);
  } finally {
    server.close();
  }
});

test('strict third-party: consent, decline page, and a token express-jwt accepts', async ({ page }) => {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const authorize = (extra = {}) => `${IDP}/authorize?` + new URLSearchParams({
    client_id: 'e2e-3p-strict', redirect_uri: 'https://localhost:3443/strict/', response_type: 'code',
    audience: 'https://api.e2e.local', scope: 'openid read:things', state: 's1',
    code_challenge: challenge, code_challenge_method: 'S256', ...extra,
  });

  // Decline: open_redirect_protection shows an error page and never redirects.
  await page.goto(authorize());
  await login(page);
  await page.waitForURL(/\/u\/consent/);
  await page.click('button[value=decline]');
  await expect(page).toHaveURL(/localhost:8443\/u\/consent/);
  await expect(page.locator('main')).toBeVisible();

  // Accept.
  await page.goto(authorize());
  await page.waitForURL(/\/u\/consent/);
  await page.click('button[value=accept]');
  await page.waitForURL(/localhost:3443\/strict\/\?code=/);
  const code = new URL(page.url()).searchParams.get('code');
  const r = await fetch(`${IDP}/oauth/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'e2e-3p-strict', code,
      code_verifier: verifier, redirect_uri: 'https://localhost:3443/strict/' }),
  });
  expect(r.status).toBe(200);
  const tok = await r.json();
  expect(tok.id_token).toBeUndefined(); // strict: no OIDC
  expect(tok.scope).toBe('read:things');

  const api = express();
  api.get('/me', expressjwt({
    secret: jwksRsa.expressJwtSecret({ jwksUri: `${IDP}/.well-known/jwks.json`, cache: true }),
    audience: 'https://api.e2e.local', issuer: `${IDP}/`, algorithms: ['RS256'],
  }), (req, res) => res.json(req.auth));
  const server = api.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const me = await fetch(`http://127.0.0.1:${server.address().port}/me`, { headers: { authorization: `Bearer ${tok.access_token}` } });
    expect(me.status).toBe(200);
    expect((await me.json()).azp).toBe('e2e-3p-strict');
  } finally {
    server.close();
  }

  // The grant is remembered: prompt=none now succeeds.
  await page.goto(authorize({ prompt: 'none', state: 's2' }));
  await page.waitForURL(/localhost:3443\/strict\/\?code=.*state=s2/);
});

test('auth0-spa-js: a localhost callback needs confirmation on session reuse', async ({ page }) => {
  await page.goto('https://localhost:3443/confirm/');
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true', { timeout: 20_000 });

  // A fresh login shows the login page, so no confirmation follows (D-0027).
  await page.click('#login');
  await login(page);
  await page.waitForURL('https://localhost:3443/confirm/');
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);

  // Silent authentication cannot show the confirmation: consent_required (O5).
  await page.reload();
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(false);
  const err = await page.evaluate(() => window.__za.client.getTokenSilently().then(() => null, (e) => e.error));
  expect(err).toBe('consent_required');

  // An interactive login that reuses the session shows the confirmation.
  await page.click('#login');
  await page.waitForURL(/\/u\/consent/);
  await expect(page.locator('ul.scopes')).toHaveCount(0); // confirmation, not consent
  await page.click('button[value=accept]');
  await page.waitForURL('https://localhost:3443/confirm/');
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
});
