// Plan 24 with the real pinned node-auth0 7.4.0: social connection CRUD,
// secret write-only reads, then (verify) federated users, the scoped token
// projection and explicit linking.
import assert from 'node:assert/strict';
import { ManagementClient } from 'auth0';
import { setGlobalDispatcher } from 'undici';
import { ADMIN, READER, api, exchanges, fixtureDispatcher, noSecret, oauthScript, primary, replicaDispatcher, token, upstream } from './social/client.mjs';
setGlobalDispatcher(fixtureDispatcher);
const make = async (client = ADMIN, scope) => new ManagementClient({ domain: primary, token: await token(client, scope), maxRetries: 0 });
const m = await make();
const mode = process.argv[2] ?? 'setup';
const idp = 'https://idp.e2e.test';

if (mode === 'setup') {
 const google = await m.connections.create({ name: 'google-oauth2', strategy: 'google-oauth2', enabled_clients: ['m24-spa'],
  options: { client_id: upstream.id, client_secret: upstream.secret, email: true, profile: true } });
 noSecret(google); assert.equal(google.strategy, 'google-oauth2');
 const oauth = await m.connections.create({ name: 'acme-oauth', strategy: 'oauth2', display_name: 'Acme OAuth', enabled_clients: ['m24-spa'],
  options: { client_id: upstream.id, client_secret: upstream.secret, authorizationURL: `${idp}/oauth2/authorize`, tokenURL: `${idp}/oauth2/token`, scope: 'profile', scripts: { fetchUserProfile: oauthScript } } });
 noSecret(oauth);
 const corp = await m.connections.create({ name: 'corp', strategy: 'oidc', display_name: 'Corp SSO', enabled_clients: ['m24-spa'],
  options: { type: 'back_channel', client_id: upstream.id, client_secret: upstream.secret, discovery_url: `${idp}/oidc/.well-known/openid-configuration`, scopes: 'openid email' } });
 noSecret(corp);
 for (const c of [google, oauth, corp]) noSecret(await m.connections.get(c.id));
 noSecret((await m.connections.list({ strategy: ['oidc'] })).data);
 // PATCH options whole without the secret keeps it (the browser login proves it).
 const opts = (await m.connections.get(corp.id)).options;
 const patched = await m.connections.update(corp.id, { options: { ...opts, scopes: 'openid email profile' } });
 noSecret(patched); assert.equal(patched.options.scopes, 'openid email profile');
 // Rejected: front channel, private endpoints, an immutable change, an empty secret.
 for (const [what, body] of [
  ['front channel', { name: 'front', strategy: 'oidc', options: { type: 'front_channel', client_id: 'c', client_secret: 's', discovery_url: `${idp}/oidc/.well-known/openid-configuration`, scopes: 'openid' } }],
  ['private endpoint', { name: 'private', strategy: 'oauth2', options: { client_id: 'c', client_secret: 's', authorizationURL: 'https://10.0.0.1/a', tokenURL: 'https://10.0.0.1/t', scope: 'x', scripts: { fetchUserProfile: oauthScript } } }],
 ]) await assert.rejects(m.connections.create(body), (e) => e.statusCode === 400, what);
 await assert.rejects(m.connections.update(corp.id, { options: { ...opts, client_id: 'other' } }), (e) => e.statusCode === 400);
 await assert.rejects(m.connections.update(corp.id, { options: { ...opts, client_secret: '' } }), (e) => e.statusCode === 400);
 // Node two sees the same configuration through its own SQL handle.
 const second = await fetch(`https://${primary}/api/v2/connections/${corp.id}`, { dispatcher: replicaDispatcher, headers: { authorization: `Bearer ${await token()}` } });
 assert.equal(second.status, 200); noSecret(await second.json());
 console.log('m24 setup: three social connections created');
} else {
 const users = (await m.users.list({ q: 'identities.provider:"google-oauth2" OR identities.provider:"oauth2" OR identities.provider:"oidc"', search_engine: 'v3' })).data;
 const ids = users.map((u) => u.user_id).sort();
 assert.deepEqual(ids, ['google-oauth2|alice', 'oauth2|acme-oauth|bob', 'oidc|corp|carol'], JSON.stringify(ids));
 const bob = await m.users.get('oauth2|acme-oauth|bob');
 assert.equal(bob.email, 'bob@oauth2.e2e.test'); assert.equal(bob.identities[0].isSocial, true);
 assert.equal((await m.users.get('oidc|corp|carol')).identities[0].isSocial, false);
 // Token projection: only read:users → absent; with read:user_idp_tokens → present, no-store.
 const plain = await make(READER, 'read:users');
 assert.equal((await plain.users.get('google-oauth2|alice')).identities[0].access_token, undefined);
 const scoped = await api('users/' + encodeURIComponent('google-oauth2|alice'), 'GET', undefined, await token(READER, 'read:users read:user_idp_tokens'));
 assert.equal(scoped.status, 200); assert.equal(typeof scoped.body.identities[0].access_token, 'string');
 assert.equal(scoped.body.identities[0].refresh_token, 'refresh-alice'); assert.equal(scoped.headers.get('cache-control'), 'no-store');
 const listed = await api('users?q=' + encodeURIComponent('user_id:"google-oauth2|alice"'), 'GET', undefined, await token(READER, 'read:users read:user_idp_tokens'));
 assert.ok(!JSON.stringify(listed.body).includes('access_token'));
 // Explicit linking moves the identity; unlinking recreates it.
 const primaryUser = await m.users.create({ connection: 'Username-Password-Authentication', email: 'linker@e2e.test', password: 'Linker-Password-2026!' });
 const linked = await m.users.identities.link(primaryUser.user_id, { provider: 'oauth2', user_id: 'acme-oauth|bob' });
 assert.equal(linked.length, 2); assert.ok(!JSON.stringify(linked).includes('access_token'));
 await assert.rejects(m.users.get('oauth2|acme-oauth|bob'), (e) => e.statusCode === 404);
 const unlinked = await m.users.identities.delete(primaryUser.user_id, 'oauth2', 'acme-oauth|bob');
 assert.equal(unlinked.length, 1);
 assert.equal((await m.users.get('oauth2|acme-oauth|bob')).identities[0].provider, 'oauth2');
 const counts = await exchanges();
 assert.ok(counts.google >= 2 && counts.oauth2 >= 2 && counts.oidc >= 2, JSON.stringify(counts));
 console.log('m24 verify: users, token scope and linking', JSON.stringify(counts));
}
