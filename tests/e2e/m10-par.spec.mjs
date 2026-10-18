// Black-box test (CLEAN_ROOM.md): Auth0's SDKs against zeroauthy's pushed
// authorization requests. Every client here requires PAR, so a login that
// succeeds proves the SDK pushed its request.
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import express from 'express';
import oidcSdk from 'express-openid-connect'; // CommonJS: no named exports under ESM
const { auth: oidc, requiresAuth } = oidcSdk;
import { AuthClient } from '@auth0/auth0-auth-js';

const IDP = 'https://localhost:8443';
const CALLBACK = 'https://localhost:3443/par-cb';

async function login(page) {
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
}

// The callback is a blank page on the SPA server, so the redirect ends on
// a real page. A made-up host left the browser on its
// network-error page, which could commit after the test's next goto had
// started and interrupt it. The redirect request carries the code.
function callbackRequest(page) {
  return page.waitForRequest((r) => r.url().startsWith(CALLBACK));
}

function authorizeRequests(page) {
  const seen = [];
  page.on('request', (r) => { if (r.url().startsWith(`${IDP}/authorize`)) seen.push(new URL(r.url())); });
  return seen;
}

test('discovery advertises the PAR endpoint', async () => {
  const d = await (await fetch(`${IDP}/.well-known/openid-configuration`)).json();
  expect(d.pushed_authorization_request_endpoint).toBe(`${IDP}/oauth/par`);
});

test('express-openid-connect logs in through PAR', async ({ page }) => {
  const app = express();
  app.use(oidc({
    issuerBaseURL: IDP, baseURL: 'http://localhost:3004', clientID: 'e2e-par-web',
    clientSecret: 'e2e-par-web-secret-not-for-production', secret: randomBytes(32).toString('hex'),
    authRequired: false, pushedAuthorizationRequests: true,
    authorizationParams: { response_type: 'code', scope: 'openid profile email' },
  }));
  app.get('/me', requiresAuth(), (req, res) => res.json(req.oidc.user));
  const server = app.listen(3004, '127.0.0.1');
  await once(server, 'listening');
  try {
    const seen = authorizeRequests(page);
    await page.goto('http://localhost:3004/me');
    await login(page);
    await page.waitForURL('http://localhost:3004/me');
    expect(JSON.parse(await page.locator('body').innerText()).email).toBe('alice@e2e.local');
    expect(seen[0].searchParams.get('request_uri')).toMatch(/^urn:ietf:params:oauth:request_uri:/);
  } finally {
    server.close();
  }
});

test('nextjs-auth0 logs in through PAR', async ({ page }) => {
  const seen = authorizeRequests(page);
  await page.goto('http://localhost:3002/');
  await page.click('#login');
  await login(page);
  await page.waitForURL('http://localhost:3002/');
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');
  expect(seen[0].searchParams.get('request_uri')).toMatch(/^urn:ietf:params:oauth:request_uri:/);
});

test('auth0-auth-js: PAR URL, code exchange, and a used request_uri is refused', async ({ page }) => {
  const client = new AuthClient({
    domain: 'localhost:8443', clientId: 'e2e-par-authjs', clientSecret: 'e2e-par-authjs-secret-not-for-production',
    authorizationParams: { redirect_uri: CALLBACK, scope: 'openid profile email' },
  });
  const { authorizationUrl, codeVerifier } = await client.buildAuthorizationUrl({ pushedAuthorizationRequests: true });
  expect(authorizationUrl.searchParams.get('request_uri')).toMatch(/^urn:ietf:params:oauth:request_uri:/);

  const callback = callbackRequest(page);
  await page.goto(authorizationUrl.toString());
  await login(page);
  const callbackURL = new URL((await callback).url());
  await page.waitForURL((u) => u.href.startsWith(CALLBACK));
  const tokens = await client.getTokenByCode(callbackURL, { codeVerifier });
  expect(tokens.idToken).toBeTruthy();

  // The same request_uri a second time: an error page at zeroauthy, no redirect.
  const r = await page.goto(authorizationUrl.toString());
  expect(r.status()).toBe(400);
  expect(page.url()).toContain('localhost:8443/authorize');
});

test('a client that requires PAR cannot use a plain /authorize', async ({ page }) => {
  const callback = callbackRequest(page);
  await page.goto(`${IDP}/authorize?` + new URLSearchParams({
    client_id: 'e2e-par-authjs', redirect_uri: CALLBACK, response_type: 'code', scope: 'openid', state: 's1',
  }));
  const u = new URL((await callback).url());
  expect(u.searchParams.get('error')).toBe('invalid_request');
  expect(u.searchParams.get('state')).toBe('s1');
});
