// Plan 41b: an application registered through /oidc/register signs a user in
// with @auth0/auth0-spa-js 2.28.3, and an application identified by its
// Client ID Metadata Document URL completes a PKCE code flow.
import {test, expect} from '@playwright/test';
import {fileURLToPath} from 'node:url';
import {createHash, randomBytes} from 'node:crypto';
import {origin, app, API, docs, secrets, secret, register, fixtureFetch} from './m41b-dcr.mjs';

test.skip(!process.env.E2E_M41B_WORK, 'Run make e2e-dcr');
test.use({trace: 'off'});

const bundle = fileURLToPath(new URL('./node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', import.meta.url));
const claims = t => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());

async function context(browser) {
  const ctx = await browser.newContext({proxy: {server: 'http://127.0.0.1:9198'}, ignoreHTTPSErrors: true});
  await ctx.route(app + '/**', r => r.fulfill({status: 200, contentType: 'text/html', body: '<!doctype html><title>Plan41b app</title>'}));
  return ctx;
}

// login fills the hosted login page and accepts the consent every
// third-party application gets.
async function login(page) {
  await page.waitForURL(u => u.origin === origin);
  await page.fill('#username', 'user@dcr.e2e.local');
  await page.fill('#password', secrets().password);
  await page.locator('button[type=submit]').first().click();
  await page.locator('button[name=action][value=accept]').click();
  await page.waitForURL(u => u.href.startsWith(app + '/?'));
}

test('a dynamically registered application signs a user in with auth0-spa-js', async ({browser}) => {
  const reg = await register({client_name: 'Plan41b SPA', redirect_uris: [app + '/'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code']});
  expect(reg.status).toBe(201);
  expect(reg.body.client_secret).toBeUndefined();
  const ctx = await context(browser);
  try {
    const page = await ctx.newPage();
    const init = async () => {
      await page.addScriptTag({path: bundle});
      await page.evaluate(o => { window.client = new auth0.Auth0Client(o); }, {
        domain: new URL(origin).hostname, clientId: reg.body.client_id, cacheLocation: 'memory',
        authorizationParams: {redirect_uri: app + '/', audience: API, scope: 'openid profile email read:things'},
      });
    };
    await page.goto(app + '/');
    await init();
    await page.evaluate(() => window.client.loginWithRedirect());
    await login(page);
    await init();
    await page.evaluate(() => window.client.handleRedirectCallback());
    const token = await secret(await page.evaluate(() => window.client.getTokenSilently()), 'access_token');
    const c = claims(token);
    expect(c.aud).toEqual(expect.arrayContaining([API]));
    expect(c.scope.split(' ')).toContain('read:things'); // from the default third-party grant
    expect(c.azp).toBe(reg.body.client_id);
    const user = await page.evaluate(() => window.client.getUser());
    expect(user.email).toBe('user@dcr.e2e.local');
  } finally {
    await ctx.close();
  }
});

test('a Client ID Metadata Document URL is a client_id', async ({browser}) => {
  const clientID = docs + '/dynamic.json';
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const q = new URLSearchParams({client_id: clientID, redirect_uri: app + '/', response_type: 'code', scope: 'openid read:things', audience: API,
    code_challenge: challenge, code_challenge_method: 'S256', state: randomBytes(8).toString('hex')});
  const ctx = await context(browser);
  try {
    const page = await ctx.newPage();
    await page.goto(`${origin}/authorize?${q}`);
    await login(page);
    const back = new URL(page.url());
    expect(back.searchParams.get('state')).toBe(q.get('state'));
    const code = await secret(back.searchParams.get('code'), 'authorization_code');
    const r = await fixtureFetch(`${origin}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({grant_type: 'authorization_code', client_id: clientID, code, code_verifier: verifier, redirect_uri: app + '/'}).toString()});
    const b = await r.json();
    expect(r.status, JSON.stringify(b)).toBe(200);
    await secret(b.access_token, 'access_token');
    expect(claims(b.access_token).scope.split(' ')).toContain('read:things');
    expect(b.id_token).toBeUndefined(); // CIMD clients are strict third party: no OIDC scopes (D-0025)
  } finally {
    await ctx.close();
  }
});
