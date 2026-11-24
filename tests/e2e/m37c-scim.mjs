// Plan 37c acceptance: the pinned node-auth0 SDK manages SCIM configuration,
// tokens and groups; an in-house RFC 7644 client provisions users and groups
// with the payload shapes Microsoft Entra ID and Okta send.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {ManagementClient} from 'auth0';

const host = 'localhost:9547', base = `https://${host}`, work = process.env.E2E_M37C_WORK;
const SCIM = 'application/scim+json';
const URN = {
  user: 'urn:ietf:params:scim:schemas:core:2.0:User', group: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  enterprise: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User', patch: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  list: 'urn:ietf:params:scim:api:messages:2.0:ListResponse', error: 'urn:ietf:params:scim:api:messages:2.0:Error',
};
const issued = [];

async function adminToken() {
  const r = await fetch(`${base}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({grant_type: 'client_credentials', client_id: 'm37c-admin', client_secret: process.env.E2E_M37C_ADMIN_SECRET, audience: `${base}/api/v2/`})});
  assert.equal(r.status, 200, 'admin token');
  return (await r.json()).access_token;
}
const mgmt = new ManagementClient({domain: host, token: await adminToken(), maxRetries: 0});
const conns = (await mgmt.connections.list({strategy: ['okta']})).data;
const corp = conns.find((c) => c.name === 'corp-okta'), other = conns.find((c) => c.name === 'other-okta');
assert.ok(corp && other, 'seeded okta connections');

// SCIM requests: the RFC 7644 client.
async function scim(conn, token, method, path, body) {
  const r = await fetch(`${base}/scim/v2/connections/${conn.id}${path}`, {method,
    headers: {authorization: `Bearer ${token}`, accept: SCIM, ...(body ? {'content-type': SCIM} : {})}, body: body ? JSON.stringify(body) : undefined});
  const text = await r.text();
  if (text) assert.ok((r.headers.get('content-type') ?? '').startsWith(SCIM), `${method} ${path}: content type ${r.headers.get('content-type')}`);
  return {status: r.status, body: text ? JSON.parse(text) : null};
}
function expectError(res, status, label) {
  assert.equal(res.status, status, label);
  assert.deepEqual(res.body.schemas, [URN.error], `${label}: error schema`);
  assert.equal(res.body.status, String(status), `${label}: status member`);
}

// 1. Configuration through the SDK.
const defaults = await mgmt.connections.scimConfiguration.getDefaultMapping(corp.id);
assert.ok(defaults.mapping.some((m) => m.auth0 === 'email' && m.scim === 'emails[primary eq true].value'), 'default mapping');
await assert.rejects(mgmt.connections.scimConfiguration.get(corp.id), (e) => e.statusCode === 404, 'no configuration yet');
const created = await mgmt.connections.scimConfiguration.create(corp.id, {});
assert.equal(created.user_id_attribute, 'externalId');
assert.equal(created.strategy, 'okta');
const mapping = [...created.mapping, {auth0: 'app_metadata.cost_center', scim: `${URN.enterprise}:costCenter`}];
const updated = await mgmt.connections.scimConfiguration.update(corp.id, {user_id_attribute: 'externalId', mapping});
assert.equal(updated.mapping.length, mapping.length);
await mgmt.connections.scimConfiguration.create(other.id, {});
await assert.rejects(mgmt.connections.scimConfiguration.create(corp.id, {}), (e) => e.statusCode === 400, 'second configuration');
const listed = await mgmt.connections.scimConfiguration.list({take: 10});
assert.equal(listed.data.length, 2);

// 2. Tokens: shown once, scoped, at most two active.
const full = await mgmt.connections.scimConfiguration.tokens.create(corp.id, {token_lifetime: 86400});
const reader = await mgmt.connections.scimConfiguration.tokens.create(corp.id, {scopes: ['get:users', 'get:groups']});
const otherTok = await mgmt.connections.scimConfiguration.tokens.create(other.id, {scopes: ['get:users', 'post:users']});
issued.push(full.token, reader.token, otherTok.token);
await writeFile(`${work}/issued-tokens.json`, JSON.stringify(issued), {mode: 0o600});
assert.ok(full.valid_until && !reader.valid_until, 'lifetime');
await assert.rejects(mgmt.connections.scimConfiguration.tokens.create(corp.id, {}), (e) => e.statusCode === 409, 'third token');
const tokenList = await mgmt.connections.scimConfiguration.tokens.get(corp.id);
assert.equal(tokenList.length, 2);
assert.ok(tokenList.every((t) => t.token === undefined), 'listed tokens never carry the secret');

// 3. Discovery.
const spc = await scim(corp, full.token, 'GET', '/ServiceProviderConfig');
assert.equal(spc.status, 200);
assert.equal(spc.body.patch.supported, true);
assert.equal(spc.body.bulk.supported, false);
assert.equal((await scim(corp, full.token, 'GET', '/ResourceTypes')).body.totalResults, 2);
assert.equal((await scim(corp, full.token, 'GET', '/Schemas')).body.totalResults, 3);
expectError(await scim(corp, 'not-a-token', 'GET', '/Users'), 401, 'bad token');

// 4. Okta-shaped user create, filter, replace.
const oktaUser = {schemas: [URN.user], userName: 'ada@corp.e2e.test', externalId: '00u-ada', active: true,
  name: {givenName: 'Ada', familyName: 'Lovelace'}, emails: [{primary: true, value: 'ada@corp.e2e.test', type: 'work'}], displayName: 'Ada Lovelace'};
const ada = await scim(corp, full.token, 'POST', '/Users', oktaUser);
assert.equal(ada.status, 201);
assert.equal(ada.body.id, 'okta|corp-okta|00u-ada');
assert.equal(ada.body.meta.resourceType, 'User');
expectError(await scim(corp, full.token, 'POST', '/Users', oktaUser), 409, 'duplicate user');
const found = await scim(corp, full.token, 'GET', `/Users?filter=${encodeURIComponent('userName eq "ada@corp.e2e.test"')}`);
assert.deepEqual(found.body.schemas, [URN.list]);
assert.equal(found.body.totalResults, 1);
assert.equal((await scim(corp, full.token, 'GET', `/Users?filter=${encodeURIComponent('externalId eq "nope"')}`)).body.totalResults, 0);
expectError(await scim(corp, full.token, 'GET', `/Users?filter=${encodeURIComponent('userName co "ada"')}`), 400, 'unsupported operator');
const put = await scim(corp, full.token, 'PUT', `/Users/${encodeURIComponent(ada.body.id)}`, {...oktaUser, name: {givenName: 'Augusta', familyName: 'King'}});
assert.equal(put.status, 200);
let stored = await mgmt.users.get(ada.body.id);
assert.equal(stored.given_name, 'Augusta');
assert.equal(stored.email, 'ada@corp.e2e.test');

// 5. Entra-shaped user: enterprise extension and capitalized PATCH ops.
const entra = await scim(corp, full.token, 'POST', '/Users', {schemas: [URN.user, URN.enterprise], externalId: 'entra-grace', userName: 'grace@corp.e2e.test', active: true,
  displayName: 'Grace Hopper', emails: [{primary: true, type: 'work', value: 'grace@corp.e2e.test'}], [URN.enterprise]: {department: 'Navy', costCenter: 'CC-1'}});
assert.equal(entra.status, 201);
stored = await mgmt.users.get(entra.body.id);
assert.equal(stored.app_metadata.department, 'Navy');
assert.equal(stored.app_metadata.cost_center, 'CC-1');
const patched = await scim(corp, full.token, 'PATCH', `/Users/${encodeURIComponent(entra.body.id)}`, {schemas: [URN.patch], Operations: [
  {op: 'Replace', path: 'displayName', value: 'Rear Admiral Hopper'},
  {op: 'Add', path: `${URN.enterprise}:department`, value: 'Computing'},
  {op: 'Replace', value: {'name.familyName': 'Hopper'}}]});
assert.equal(patched.status, 200, JSON.stringify(patched.body));
stored = await mgmt.users.get(entra.body.id);
assert.equal(stored.name, 'Rear Admiral Hopper');
assert.equal(stored.app_metadata.department, 'Computing');
assert.equal(stored.family_name, 'Hopper');

// 6. Groups with members; Entra member removal by value filter.
const team = await scim(corp, full.token, 'POST', '/Groups', {schemas: [URN.group], displayName: 'Analytical Engines', externalId: 'grp-ext-1', members: [{value: ada.body.id}]});
assert.equal(team.status, 201);
assert.match(team.body.id, /^grp_[1-9A-HJ-NP-Za-km-z]{14,22}$/);
const addMember = await scim(corp, full.token, 'PATCH', `/Groups/${team.body.id}`, {schemas: [URN.patch], Operations: [{op: 'Add', path: 'members', value: [{value: entra.body.id}]}]});
assert.equal(addMember.status, 200);
assert.equal(addMember.body.members.length, 2);
const groupsAPI = (await mgmt.groups.list({connection_id: corp.id})).data;
assert.deepEqual(groupsAPI.map((g) => g.name), ['Analytical Engines']);
assert.equal((await mgmt.groups.members.get(team.body.id)).data.length, 2);
const rmMember = await scim(corp, full.token, 'PATCH', `/Groups/${team.body.id}`, {schemas: [URN.patch], Operations: [{op: 'Remove', path: `members[value eq "${ada.body.id}"]`}]});
assert.equal(rmMember.status, 200, JSON.stringify(rmMember.body));
assert.deepEqual(rmMember.body.members.map((m) => m.value), [entra.body.id]);
// Okta's group rename.
assert.equal((await scim(corp, full.token, 'PATCH', `/Groups/${team.body.id}`, {schemas: [URN.patch], Operations: [{op: 'replace', value: {id: team.body.id, displayName: 'Difference Engines'}}]})).status, 200);
assert.equal((await mgmt.groups.get(team.body.id)).name, 'Difference Engines');

// 7. Group roles through the SDK; SCIM cannot assign roles.
const role = await mgmt.roles.create({name: 'engine-operators', description: 'Granted by the group'});
await mgmt.groups.roles.create(team.body.id, {roles: [role.id]});
assert.deepEqual((await mgmt.groups.roles.list(team.body.id)).data.map((r) => r.id), [role.id]);
assert.deepEqual((await mgmt.roles.groups.get(role.id)).data.map((g) => g.id), [team.body.id]);
assert.deepEqual((await mgmt.users.groups.get(entra.body.id)).data.map((g) => g.id), [team.body.id]);
const src = await fetch(`${base}/api/v2/users/${encodeURIComponent(entra.body.id)}/effective-roles/sources/groups?role_id=${role.id}`, {headers: {authorization: `Bearer ${await adminToken()}`}});
assert.equal(src.status, 200);
assert.deepEqual((await src.json()).groups.map((g) => g.id), [team.body.id]);

// 8. Isolation: tokens act only on their own connection.
expectError(await scim(corp, otherTok.token, 'GET', '/Users'), 401, 'other connection token');
expectError(await scim(other, full.token, 'GET', '/Users'), 401, 'token on another connection');
const otherList = await scim(other, otherTok.token, 'GET', '/Users');
assert.equal(otherList.body.totalResults, 0, 'other connection sees none of corp-okta');
expectError(await scim(other, otherTok.token, 'GET', `/Users/${encodeURIComponent(ada.body.id)}`), 404, 'cross-connection read');
expectError(await scim(corp, reader.token, 'POST', '/Users', {userName: 'x', externalId: 'x'}), 403, 'read-only token write');
assert.equal((await scim(corp, reader.token, 'GET', '/Groups')).body.totalResults, 1);

// 9. Deprovisioning: active false blocks; DELETE removes.
const deact = await scim(corp, full.token, 'PATCH', `/Users/${encodeURIComponent(ada.body.id)}`, {schemas: [URN.patch], Operations: [{op: 'Replace', path: 'active', value: false}]});
assert.equal(deact.status, 200);
assert.equal(deact.body.active, false);
assert.equal((await mgmt.users.get(ada.body.id)).blocked, true);
assert.equal((await scim(corp, full.token, 'GET', `/Users?filter=${encodeURIComponent('active eq false')}`)).body.totalResults, 1);
assert.equal((await scim(corp, full.token, 'DELETE', `/Users/${encodeURIComponent(ada.body.id)}`)).status, 204);
await assert.rejects(mgmt.users.get(ada.body.id), (e) => e.statusCode === 404, 'deleted user');
assert.equal((await scim(corp, full.token, 'DELETE', `/Groups/${team.body.id}`)).status, 204);
await assert.rejects(mgmt.groups.get(team.body.id), (e) => e.statusCode === 404, 'deleted group');

// 10. Revocation.
await mgmt.connections.scimConfiguration.tokens.delete(corp.id, reader.token_id);
expectError(await scim(corp, reader.token, 'GET', '/Users'), 401, 'revoked token');
await mgmt.connections.scimConfiguration.delete(other.id);
expectError(await scim(other, otherTok.token, 'GET', '/Users'), 401, 'token of a deleted configuration');
console.log('Plan 37c SCIM: SDK configuration/tokens/groups, Entra and Okta provisioning, isolation, deprovisioning and revocation passed');
