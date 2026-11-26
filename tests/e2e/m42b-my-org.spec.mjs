// Plan 42b: organization administrators sign in through @auth0/auth0-spa-js
// 2.28.3 in their organization and manage it through /my-org/v1.
import {test, expect} from '@playwright/test';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {origin, app, ORG, scopes, secrets, secret, orgs, publishTXT, fixtureFetch} from './m42b-my-org.mjs';

test.skip(!process.env.E2E_M42B_WORK, 'Run make e2e-my-org');
test.use({trace: 'off'});

const bundle = fileURLToPath(new URL('./node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', import.meta.url));

async function signedIn(browser, email, organization) {
  const ctx = await browser.newContext({proxy: {server: 'http://127.0.0.1:9198'}, ignoreHTTPSErrors: true});
  await ctx.route(app + '/**', r => r.fulfill({status: 200, contentType: 'text/html', body: '<!doctype html><title>Plan42b portal</title>'}));
  const page = await ctx.newPage();
  const init = async () => {
    await page.addScriptTag({path: bundle});
    await page.evaluate(o => { window.client = new auth0.Auth0Client(o); }, {
      domain: new URL(origin).hostname, clientId: 'm42b-spa', cacheLocation: 'memory',
      authorizationParams: {redirect_uri: app + '/', audience: ORG, organization, scope: 'openid profile email ' + scopes.join(' ')},
    });
  };
  await page.goto(app + '/');
  await init();
  await page.evaluate(() => window.client.loginWithRedirect());
  await page.waitForURL(u => u.origin === origin);
  await page.fill('#username', email);
  await page.fill('#password', secrets().password);
  await page.locator('button[type=submit]').first().click();
  await page.waitForURL(u => u.href.startsWith(app + '/?'));
  await init();
  await page.evaluate(() => window.client.handleRedirectCallback());
  const token = await secret(await page.evaluate(() => window.client.getTokenSilently()), 'access_token');
  const call = (method, path, body) => page.evaluate(async ([m, p, b, t, base]) => {
    const r = await fetch(base + '/my-org/v1' + p, {method: m, headers: {authorization: 'Bearer ' + t, ...(b ? {'content-type': 'application/json'} : {})}, body: b ? JSON.stringify(b) : undefined});
    const text = await r.text();
    return {status: r.status, body: text ? JSON.parse(text) : null};
  }, [method, path, body, token, origin]);
  return {ctx, page, token, call};
}

const claims = t => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());

test('an administrator manages the organization; others are kept out', async ({browser}) => {
  const ids = await orgs();
  const admin = await signedIn(browser, 'alice@acme.e2e.local', ids.acme);
  try {
    const c = claims(admin.token);
    expect(c.org_id).toBe(ids.acme);
    expect(c.exp - c.iat).toBe(600);
    expect(c.scope.split(' ')).toEqual(expect.arrayContaining(scopes));

    const details = await admin.call('GET', '/details');
    expect(details.body).toMatchObject({id: ids.acme, name: 'acme', display_name: 'Acme'});
    expect((await admin.call('PATCH', '/details', {display_name: 'Acme Inc'})).body.display_name).toBe('Acme Inc');

    const members = await admin.call('GET', '/members?include_totals=true');
    expect(members.body.total).toBe(2);
    const bob = members.body.members.find(m => m.email === 'bob@acme.e2e.local');
    expect(members.body.members.find(m => m.email === 'alice@acme.e2e.local').roles.map(r => r.name)).toEqual(['Org Admin']);

    const roles = (await admin.call('GET', '/roles')).body.roles;
    const adminRole = roles.find(r => r.name === 'Org Admin');
    expect(roles.map(r => r.name).sort()).toEqual(['Member', 'Org Admin']);
    expect((await admin.call('POST', `/members/${encodeURIComponent(bob.user_id)}/roles`, {role_ids: [adminRole.id]})).status).toBe(204);
    expect((await admin.call('GET', `/members/${encodeURIComponent(bob.user_id)}/roles`)).body.roles.map(r => r.name)).toContain('Org Admin');
    expect((await admin.call('POST', `/members/${encodeURIComponent(bob.user_id)}/unassign-roles`, {role_ids: [adminRole.id]})).status).toBe(204);

    const stores = (await admin.call('GET', '/user-stores')).body.user_stores;
    expect(stores).toHaveLength(1);
    const created = await admin.call('POST', '/member-invitations', {invitees: [{email: 'dana@acme.e2e.local', roles: [roles.find(r => r.name === 'Member').id]}], user_store_id: stores[0].id});
    expect(created.status).toBe(201);
    await secret(created.body[0].invitation_url, 'invitation_url');
    expect(created.body[0]).toMatchObject({organization_id: ids.acme, invitee: {email: 'dana@acme.e2e.local'}});
    expect((await admin.call('GET', '/member-invitations')).body.invitations).toHaveLength(1);
    expect((await admin.call('POST', '/delete-member-invitations', {invitations: [created.body[0].id]})).status).toBe(204);

    // The organization keeps an administrator.
    const self = encodeURIComponent(claims(admin.token).sub);
    expect((await admin.call('POST', `/members/${self}/unassign-roles`, {role_ids: [adminRole.id]})).status).toBe(409);

    // A member without administrator roles has no my_org scopes.
    const member = await signedIn(browser, 'bob@acme.e2e.local', ids.acme);
    try {
      expect(claims(member.token).scope.split(' ').filter(s => s.includes(':my_org:'))).toEqual([]);
      expect((await member.call('GET', '/members')).status).toBe(403);
    } finally {
      await member.ctx.close();
    }

    // The other organization's administrator sees only their organization.
    const other = await signedIn(browser, 'carol@other.e2e.local', ids.other);
    try {
      const theirs = await other.call('GET', '/members');
      expect(theirs.body.members.map(m => m.email)).toEqual(['carol@other.e2e.local']);
      expect((await other.call('GET', `/members/${encodeURIComponent(bob.user_id)}`)).status).toBe(404);
      expect((await other.call('GET', '/details')).body.id).toBe(ids.other);
    } finally {
      await other.ctx.close();
    }
  } finally {
    await admin.ctx.close();
  }
});

// Phase B: the administrator verifies a domain through DNS, creates an
// identity provider, links the domain and provisions users through SCIM.
test('an administrator verifies a domain, adds an identity provider and provisions it', async ({browser}) => {
  const ids = await orgs();
  const admin = await signedIn(browser, 'alice@acme.e2e.local', ids.acme);
  try {
    const claimed = await admin.call('POST', '/domains', {domain: 'acme.e2e.test'});
    expect(claimed.status).toBe(201);
    expect(claimed.body).toMatchObject({status: 'pending', verification_host: '_zeroauthy-org.acme.e2e.test', identity_provider_association: 'unassociated'});
    expect((await admin.call('POST', `/domains/${claimed.body.id}/verify`)).body.status).toBe('failed');
    await publishTXT('_zeroauthy-org.acme.e2e.test', ['unrelated', claimed.body.verification_txt]);
    const verified = await admin.call('POST', `/domains/${claimed.body.id}/verify`);
    expect(verified.status).toBe(202);
    expect(verified.body.status).toBe('verified');

    const cfg = (await admin.call('GET', '/config/identity-providers')).body;
    expect(cfg.domain_aliases_config.domain_verification).toBe('optional');
    expect(Object.keys(cfg.strategies)).toEqual(['oidc']);

    const clientSecret = await secret('upstream-' + randomBytes(18).toString('base64url'), 'client_secret');
    const created = await admin.call('POST', '/identity-providers', {name: 'acme-sso', strategy: 'oidc', display_name: 'Acme SSO',
      options: {type: 'back_channel', client_id: 'acme-upstream', client_secret: clientSecret, discovery_url: 'https://idp.acme.e2e.test/.well-known/openid-configuration'}});
    expect(created.status).toBe(201);
    expect(JSON.stringify(created.body)).not.toContain(clientSecret);
    const idp = created.body.id;
    expect(created.body).toMatchObject({access_level: 'full', is_enabled: true, strategy: 'oidc'});
    expect((await admin.call('POST', `/identity-providers/${idp}/domains`, {domain: 'acme.e2e.test'})).status).toBe(201);
    expect((await admin.call('GET', `/domains/${claimed.body.id}`)).body.identity_provider_association).toBe('associated');
    expect((await admin.call('GET', `/domains/${claimed.body.id}/identity-providers`)).body.identity_providers.map(p => p.id)).toEqual([idp]);

    expect((await admin.call('POST', `/identity-providers/${idp}/provisioning`)).status).toBe(201);
    const minted = await admin.call('POST', `/identity-providers/${idp}/provisioning/scim-tokens`, {token_lifetime: 3600});
    expect(minted.status).toBe(201);
    const scimToken = await secret(minted.body.token, 'scim_token');
    expect(JSON.stringify((await admin.call('GET', `/identity-providers/${idp}/provisioning/scim-tokens`)).body)).not.toContain(scimToken);
    const scim = (method, path, body) => fixtureFetch(`${origin}/scim/v2/connections/${idp}${path}`, {method, headers: {authorization: 'Bearer ' + scimToken, 'content-type': 'application/scim+json'}, body: body && JSON.stringify(body)});
    const user = await scim('POST', '/Users', {schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], externalId: 'dana-acme-1', userName: 'dana@acme.e2e.test', emails: [{value: 'dana@acme.e2e.test', primary: true}], active: true});
    expect(user.status, await user.clone().text()).toBe(201);
    expect((await admin.call('DELETE', `/identity-providers/${idp}/provisioning/scim-tokens/${minted.body.token_id}`)).status).toBe(204);
    expect((await scim('GET', '/Users')).status).toBe(401);

    // Another organization's administrator cannot reach the provider or the domain.
    const other = await signedIn(browser, 'carol@other.e2e.local', ids.other);
    try {
      expect((await other.call('GET', `/identity-providers/${idp}`)).status).toBe(404);
      expect((await other.call('GET', `/domains/${claimed.body.id}`)).status).toBe(404);
      expect((await other.call('POST', '/domains', {domain: 'acme.e2e.test'})).status).toBe(409);
    } finally {
      await other.ctx.close();
    }
  } finally {
    await admin.ctx.close();
  }
});
