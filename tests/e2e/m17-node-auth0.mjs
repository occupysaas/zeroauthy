// Black-box test (Plan 17): node-auth0 7.4.0's ManagementClient against the
// users API of the e2e tenant (localhost:8443): users create, list with q,
// get, update metadata, delete; listUsersByEmail; tickets changePassword
// and verifyEmail (the verification link is opened like a browser would);
// sessions and refresh tokens of a user; user grants. The client signs in
// with client credentials (e2e-m17-admin) on its own.
import assert from 'node:assert/strict';
import { AuthenticationClient } from 'auth0/legacy';
import { ManagementClient } from 'auth0';

const domain = 'localhost:8443';
const connection = 'Username-Password-Authentication';
const management = new ManagementClient({ domain, clientId: 'e2e-m17-admin', clientSecret: 'e2e-m17-admin-secret-not-for-production' });
const auth = new AuthenticationClient({ domain, clientId: 'e2e-node', clientSecret: 'e2e-node-secret-not-for-production' });

const stamp = Date.now();
const password = 'Node-Password-123';
const mail = (who) => `m17-${who}-${stamp}@e2e.local`;
const ids = (users) => users.map((u) => u.user_id).sort();
// all drains a Page: node-auth0's list calls return one.
async function all(page) {
  const out = [...page.data];
  while (page.hasNextPage()) {
    page = await page.getNextPage();
    out.push(...page.data);
  }
  return out;
}
// status of the error a call raises, or 0.
async function statusOf(promise) {
  try {
    await promise;
    return 0;
  } catch (e) {
    return e.statusCode ?? e.status;
  }
}

// 1. users.create: a name, metadata of both kinds; no password in the answer.
const ada = await management.users.create({ connection, email: mail('ada'), password, name: 'Ada Node', email_verified: false,
  app_metadata: { plan: 'pro', seats: 3 }, user_metadata: { colour: 'green' } });
assert.match(ada.user_id, /^auth0\|[0-9a-f]{24}$/);
assert.equal(ada.email, mail('ada'));
assert.equal(ada.app_metadata.plan, 'pro');
assert.equal(ada.password, undefined);
assert.equal(ada.password_hash, undefined);
const bob = await management.users.create({ connection, email: mail('bob'), password, app_metadata: { plan: 'free', seats: 30 } });
assert.equal(await statusOf(management.users.create({ connection, email: mail('ada'), password })), 409, 'a duplicate email is a 409');

// 2. users.get, with and without fields.
const got = await management.users.get(ada.user_id);
assert.equal(got.user_id, ada.user_id);
assert.equal(got.user_metadata.colour, 'green');
assert.equal(got.identities[0].connection, connection);
const slim = await management.users.get(ada.user_id, { fields: 'user_id,email', include_fields: true });
assert.deepEqual(Object.keys(slim).sort(), ['email', 'user_id']);

// 3. users.list with q (search_engine v3).
const list = (q, extra = {}) => management.users.list({ q, search_engine: 'v3', ...extra }).then(all);
assert.deepEqual(ids(await list(`email:"${mail('ada')}"`)), [ada.user_id]);
assert.deepEqual(ids(await list(`app_metadata.plan:pro AND email:m17-*-${stamp}@e2e.local`)), [ada.user_id]);
assert.deepEqual(ids(await list(`app_metadata.seats:30 AND email:m17-*-${stamp}@e2e.local`)), [bob.user_id]);
assert.deepEqual(await list(`email:"nobody-${stamp}@e2e.local"`), []);
const counted = await management.users.list({ q: `email:m17-*-${stamp}@e2e.local`, search_engine: 'v3', include_totals: true, per_page: 1 });
assert.equal(counted.response.total, 2);
assert.equal(counted.data.length, 1);
assert.equal(await statusOf(management.users.list({ q: 'app_metadata.seats:[10 TO *]', search_engine: 'v3' })), 400, 'ranges are for root fields only');
assert.equal(await statusOf(management.users.list({ q: 'email:("ada', search_engine: 'v3' })), 400, 'a malformed query is a 400');
assert.equal(await statusOf(management.users.list({ q: 'email:x', search_engine: 'v1' })), 400, 'v1 is refused');

// 4. users.listUsersByEmail.
const byEmail = await management.users.listUsersByEmail({ email: mail('ada') });
assert.deepEqual(ids(byEmail), [ada.user_id]);
assert.deepEqual(await management.users.listUsersByEmail({ email: `nobody-${stamp}@e2e.local` }), []);

// 5. users.update: metadata merges at the top level; null removes a key.
const merged = await management.users.update(ada.user_id, { app_metadata: { plan: null, team: 'blue' }, user_metadata: { size: 'L' } });
assert.equal(merged.app_metadata.plan, undefined);
assert.equal(merged.app_metadata.seats, 3, 'a key not sent is kept');
assert.equal(merged.app_metadata.team, 'blue');
assert.deepEqual(merged.user_metadata, { colour: 'green', size: 'L' });
assert.deepEqual(ids(await list(`app_metadata.team:blue`)), [ada.user_id]);
assert.equal((await management.users.update(ada.user_id, { name: 'Ada Renamed' })).name, 'Ada Renamed');

// 6. Sessions and refresh tokens: a password grant with offline_access
//    leaves a refresh token to list and revoke; browser sessions are
//    covered by m17-console.
const tokens = await auth.oauth.passwordGrant({ username: mail('ada'), password, realm: connection,
  audience: 'https://api.e2e.local', scope: 'openid offline_access read:things' });
const t1 = tokens.data ?? tokens;
assert.ok(t1.refresh_token);
const rts = await management.users.refreshToken.list(ada.user_id).then(all);
assert.equal(rts.length, 1);
assert.equal(rts[0].client_id, 'e2e-node');
const one = await management.refreshTokens.get(rts[0].id);
assert.equal(one.user_id, ada.user_id);
assert.equal(JSON.stringify(one).includes(t1.refresh_token), false, 'the token itself is never listed');
assert.deepEqual(await management.users.sessions.list(ada.user_id).then(all), [], 'a password grant makes no browser session');
await management.users.sessions.delete(ada.user_id);
assert.equal(await statusOf(management.sessions.get('sess_nope')), 404);
await management.users.refreshToken.delete(ada.user_id);
assert.deepEqual(await management.users.refreshToken.list(ada.user_id).then(all), []);
await assert.rejects(auth.oauth.refreshTokenGrant({ refresh_token: t1.refresh_token }), (e) => {
  assert.ok([400, 403].includes(e.statusCode ?? e.status), `status ${e.statusCode ?? e.status}`);
  assert.equal(e.error ?? e.body?.error ?? JSON.parse(e.body ?? '{}').error, 'invalid_grant');
  return true;
}, 'a revoked refresh token no longer renews');

// 7. Grants: none yet (first-party applications skip consent); revoking an
//    unknown grant and a user's grants are 204s.
assert.deepEqual(await management.userGrants.list({ user_id: ada.user_id }).then(all), []);
await management.userGrants.delete('no-such-grant');
await management.userGrants.deleteByUserId({ user_id: ada.user_id });

// 8. tickets.changePassword: the link is the hosted reset page.
const reset = await management.tickets.changePassword({ user_id: ada.user_id });
assert.match(reset.ticket, /\/u\/reset-verify\?ticket=[A-Za-z0-9_-]+#$/);
const page = await fetch(reset.ticket);
assert.equal(page.status, 200);
assert.match(await page.text(), /name="csrf"/);
assert.equal(await statusOf(management.tickets.changePassword({ user_id: 'auth0|000000000000000000000000' })), 404);

// 9. tickets.verifyEmail: opening the link verifies the address.
assert.equal((await management.users.get(ada.user_id)).email_verified, false);
const verify = await management.tickets.verifyEmail({ user_id: ada.user_id });
assert.match(verify.ticket, /\/u\/email-verification\?ticket=[A-Za-z0-9_-]+#$/);
const opened = await fetch(verify.ticket);
assert.equal(opened.status, 200);
assert.match(await opened.text(), /Email Verified/);
assert.equal((await management.users.get(ada.user_id)).email_verified, true);

// 10. users.delete: a 204, then the user is 404; the user cannot sign in.
await management.users.delete(bob.user_id);
assert.equal(await statusOf(management.users.get(bob.user_id)), 404);
assert.deepEqual(await management.users.listUsersByEmail({ email: mail('bob') }), []);
await assert.rejects(auth.oauth.passwordGrant({ username: mail('bob'), password, realm: connection, scope: 'openid' }));
await management.users.delete(ada.user_id);
assert.equal(await statusOf(management.users.delete(ada.user_id)), 0, 'deleting twice is a 204 again, as on Auth0');

console.log('m17-node-auth0: node-auth0 7.4.0 managed users, tickets, sessions, refresh tokens and grants on ' + domain);
