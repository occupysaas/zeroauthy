// Plan 42a: a browser application signs in with @auth0/auth0-spa-js 2.28.3
// for the My Account API audience, then enrolls TOTP and a passkey (virtual
// authenticator), renames and deletes methods through /me/v1.
import {test, expect} from '@playwright/test';
import {createHmac} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {origin, app, ME, email, scopes, secrets, secret} from './m42a-my-account.mjs';

test.skip(!process.env.E2E_M42A_WORK, 'Run make e2e-my-account');
test.use({trace: 'off'});

const bundle = fileURLToPath(new URL('./node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', import.meta.url));

function totp(secretB32, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secretB32.replace(/=+$/, '')) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const h = createHmac('sha1', key).update(counter).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}

async function signedIn(browser) {
  const ctx = await browser.newContext({proxy: {server: 'http://127.0.0.1:9198'}, ignoreHTTPSErrors: true});
  await ctx.route(app + '/**', r => r.fulfill({status: 200, contentType: 'text/html', body: '<!doctype html><title>Plan42a app</title>'}));
  const page = await ctx.newPage();
  const init = async () => {
    await page.addScriptTag({path: bundle});
    await page.evaluate(o => { window.client = new auth0.Auth0Client(o); }, {
      domain: new URL(origin).hostname, clientId: 'm42a-spa', cacheLocation: 'memory',
      authorizationParams: {redirect_uri: app + '/', audience: ME, scope: 'openid profile email ' + scopes.join(' ')},
    });
  };
  await page.goto(app + '/');
  await init();
  await page.evaluate(() => window.client.loginWithRedirect());
  await page.waitForURL(u => u.origin === origin);
  await page.fill('#username', email);
  await page.locator('form[action="/u/login"] button[type=submit]').click();
  await page.fill('#password', secrets().password);
  await page.locator('button[type=submit]').first().click();
  await page.waitForURL(u => u.href.startsWith(app + '/?'));
  await init();
  await page.evaluate(() => window.client.handleRedirectCallback());
  const token = await page.evaluate(() => window.client.getTokenSilently());
  await secret(token, 'access_token');
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  expect(claims.aud).toContain(ME);
  expect(claims.scope.split(' ')).toEqual(expect.arrayContaining(scopes));
  // The application calls the API cross-origin with fetch, as a SPA does.
  const call = (method, path, body) => page.evaluate(async ([m, p, b, t, base]) => {
    const r = await fetch(base + '/me/v1' + p, {method: m, headers: {authorization: 'Bearer ' + t, ...(b ? {'content-type': 'application/json'} : {})}, body: b ? JSON.stringify(b) : undefined});
    const text = await r.text();
    return {status: r.status, location: r.headers.get('location'), body: text ? JSON.parse(text) : null};
  }, [method, path, body, token, origin]);
  return {ctx, page, call};
}

test('TOTP and passkey enrollment, rename and delete through the My Account API', async ({browser}) => {
  const {ctx, page, call} = await signedIn(browser);
  try {
    const factors = await call('GET', '/factors');
    expect(factors.status).toBe(200);
    expect(factors.body.factors.map(f => f.type)).toEqual(expect.arrayContaining(['password', 'passkey', 'totp']));

    let list = await call('GET', '/authentication-methods');
    expect(list.body.authentication_methods.map(m => m.type)).toEqual(['password']);
    const password = list.body.authentication_methods[0].id;
    // The only way to sign in cannot be deleted.
    expect((await call('DELETE', '/authentication-methods/' + encodeURIComponent(password))).status).toBe(409);
    expect((await call('POST', '/authentication-methods', {type: 'push-notification'})).body.type).toBe('factor_not_enabled');

    // TOTP: start, then verify with the authenticator app's code.
    const start = await call('POST', '/authentication-methods', {type: 'totp'});
    expect(start.status).toBe(202);
    await secret(start.body.manual_input_code, 'totp_secret');
    await secret(start.body.auth_session, 'auth_session');
    expect(start.body.barcode_uri).toMatch(/^otpauth:\/\/totp\//);
    const code = totp(start.body.manual_input_code);
    const done = await call('POST', `/authentication-methods/${encodeURIComponent(start.body.id)}/verify`, {auth_session: start.body.auth_session, otp_code: code});
    expect(done.status).toBe(201);
    expect(done.body).toMatchObject({id: start.body.id, type: 'totp', confirmed: true});
    // Spent: the same auth_session cannot be used again.
    expect((await call('POST', `/authentication-methods/${encodeURIComponent(start.body.id)}/verify`, {auth_session: start.body.auth_session, otp_code: code})).body.type).toBe('invalid_auth_session');

    // Passkey with a virtual platform authenticator.
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable', {enableUI: false});
    await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true}});
    const pk = await call('POST', '/authentication-methods', {type: 'passkey'});
    expect(pk.status).toBe(202);
    expect(pk.location).toBe(`${origin}/me/v1/authentication-methods/passkey%7Cnew`);
    await secret(pk.body.auth_session, 'auth_session');
    expect(pk.body.authn_params_public_key.rp.id).toBe('acct.e2e.test');
    const attestation = await page.evaluate(async o => {
      const b = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      const e = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const cred = await navigator.credentials.create({publicKey: {...o, challenge: b(o.challenge), user: {...o.user, id: b(o.user.id)}, excludeCredentials: (o.excludeCredentials ?? []).map(c => ({...c, id: b(c.id)}))}});
      return {id: cred.id, rawId: e(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment, clientExtensionResults: {},
        response: {clientDataJSON: e(cred.response.clientDataJSON), attestationObject: e(cred.response.attestationObject), transports: cred.response.getTransports()}};
    }, pk.body.authn_params_public_key);
    await secret(attestation.response.attestationObject, 'attestation');
    const created = await call('POST', '/authentication-methods/passkey%7Cnew/verify', {auth_session: pk.body.auth_session, authn_response: attestation});
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({type: 'passkey', relying_party_id: 'acct.e2e.test'});

    // Rename the TOTP method, then delete it.
    const renamed = await call('PATCH', '/authentication-methods/' + encodeURIComponent(start.body.id), {name: 'Plan42a phone'});
    expect(renamed.body.name).toBe('Plan42a phone');
    expect((await call('DELETE', '/authentication-methods/' + encodeURIComponent(start.body.id))).status).toBe(204);
    list = await call('GET', '/authentication-methods');
    expect(list.body.authentication_methods.map(m => m.type).sort()).toEqual(['passkey', 'password']);
  } finally {
    await ctx.close();
  }
});
