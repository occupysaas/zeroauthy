// examples/testing/login.spec.mjs: a real browser login through zeroauthy's
// hosted login page, then the code exchange and ID token checks.
//
//   cd examples/testing && npm install && npx playwright install chromium
//   NODE_EXTRA_CA_CERTS=./zeroauthy-ca.pem npx playwright test
//
// The browser ignores the self-signed certificate (playwright.config.mjs);
// Node's fetch, used for the token exchange, trusts the CA through
// NODE_EXTRA_CA_CERTS. No app has to run on localhost:3000: the test catches
// the redirect to the callback URL in the browser.
import { test, expect } from '@playwright/test';
import { createHash, createPublicKey, createVerify, randomBytes } from 'node:crypto';

const BASE = process.env.ZEROAUTHY_URL ?? 'https://localhost:8443';
const CLIENT_ID = 'test-web';
const CLIENT_SECRET = 'test-web-secret-not-for-production';
const CALLBACK = 'http://localhost:3000/callback';

async function verifyJWT(token) {
  const [h, p, s] = token.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const { keys } = await (await fetch(`${BASE}/.well-known/jwks.json`)).json();
  const jwk = keys.find((k) => k.kid === header.kid);
  expect(jwk, `JWKS key ${header.kid}`).toBeTruthy();
  const valid = createVerify('RSA-SHA256').update(`${h}.${p}`)
    .verify(createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'));
  expect(valid, 'ID token signature').toBe(true);
  return JSON.parse(Buffer.from(p, 'base64url'));
}

test('a seeded user signs in on the hosted login page', async ({ page }) => {
  // Answer the callback in the browser so the redirect ends on a real page.
  await page.route(`${CALLBACK}**`, (route) => route.fulfill({ status: 200, body: 'ok' }));

  const state = randomBytes(16).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const authorize = new URL(`${BASE}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: CALLBACK,
    scope: 'openid profile email', state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256',
  }).toString();

  const callback = page.waitForRequest((r) => r.url().startsWith(CALLBACK));
  await page.goto(authorize.toString());
  await expect(page).toHaveURL(/\/u\/login/);
  await page.fill('#username', 'alice@example.test');
  await page.fill('#password', 'Test-Password-Alice-1');
  await page.click('button[type=submit]');

  const redirect = new URL((await callback).url());
  expect(redirect.searchParams.get('state')).toBe(state);
  const code = redirect.searchParams.get('code');
  expect(code).toBeTruthy();

  // The back-channel exchange a regular web app's server makes
  // (client_secret_post, the client's token endpoint method in seed.yaml).
  const res = await fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: CALLBACK, code_verifier: verifier,
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    }),
  });
  const tokens = await res.json();
  expect(res.status, JSON.stringify(tokens)).toBe(200);

  const claims = await verifyJWT(tokens.id_token);
  expect(claims).toMatchObject({
    iss: `${BASE}/`,
    aud: CLIENT_ID,
    nonce,
    email: 'alice@example.test',
    email_verified: true,
    name: 'Alice Tester',
  });
  expect(claims.sub).toMatch(/^auth0\|/);
});

test('a wrong password stays on the login page', async ({ page }) => {
  const authorize = new URL(`${BASE}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: CALLBACK,
    scope: 'openid', state: randomBytes(8).toString('hex'),
  }).toString();
  await page.goto(authorize.toString());
  await page.fill('#username', 'alice@example.test');
  await page.fill('#password', 'not-the-password');
  await page.click('button[type=submit]');
  await expect(page).toHaveURL(/\/u\/login/);
  await expect(page.locator('#password')).toBeVisible();
});
