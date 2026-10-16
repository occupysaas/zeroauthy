// Black-box test (CLEAN_ROOM.md): custom database connections through
// node-auth0 and @auth0/auth0-auth-js, backed by the stand-in legacy store
// (legacy-store.mjs). Covers legacy mode and import mode.
import assert from 'node:assert/strict';
import { AuthClient } from '@auth0/auth0-auth-js';
import { AuthenticationClient } from 'auth0/legacy';

const LEGACY = 'http://127.0.0.1:8099';
const legacyUser = 'legacy-user@e2e.local';
const legacyPassword = 'Legacy-Password-1';
// Stored user IDs are tenant-wide, so import mode uses its own legacy user.
const importUser = 'import-user@e2e.local';
const importPassword = 'Import-Password-1';

const auth = new AuthenticationClient({
  domain: 'localhost:8443', clientId: 'e2e-node', clientSecret: 'e2e-node-secret-not-for-production',
});

async function stats() {
  const res = await fetch(`${LEGACY}/stats`, { headers: { authorization: 'Bearer e2e-legacy-token' } });
  assert.equal(res.status, 200, 'legacy store stats');
  return res.json();
}
const claims = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
const grant = (realm, password, username = legacyUser) => auth.oauth.passwordGrant({
  username, password, realm, scope: 'openid profile email',
});

// 1. Legacy mode: the legacy store answers every login.
const before = await stats();
const legacyTokens = await grant('legacy-users', legacyPassword);
const lt = legacyTokens.data ?? legacyTokens;
assert.ok(lt.access_token && lt.id_token, 'legacy-users password-realm grant returns tokens');
assert.equal(claims(lt.id_token).sub, 'auth0|L-1001', 'ID token subject is auth0|<legacy user_id>');
await grant('legacy-users', legacyPassword);
assert.equal((await stats()).login - before.login, 2, 'legacy mode calls the login script every time');

// 2. A wrong password is invalid_grant.
await assert.rejects(grant('legacy-users', 'wrong-password'), (err) => {
  const body = err.body ?? err;
  const code = typeof body === 'string' ? JSON.parse(body).error : body.error;
  assert.equal(code, 'invalid_grant');
  return true;
});

// 3. Import mode: the first login migrates the user, later ones stay local.
const importBefore = await stats();
const first = await grant('import-users', importPassword, importUser);
assert.equal(claims((first.data ?? first).id_token).sub, 'auth0|L-1002');
const second = await grant('import-users', importPassword, importUser);
assert.ok((second.data ?? second).access_token, 'second import-mode login succeeds');
assert.equal((await stats()).login - importBefore.login, 1, 'import mode calls the login script once');

// 4. Signup of an address the legacy store already has is a conflict.
await assert.rejects(
  auth.database.signUp({ email: importUser, password: 'Another-Password-9', connection: 'import-users' }),
  (err) => {
    assert.equal(err.statusCode ?? err.status, 409);
    return true;
  },
);

// 5. The current SDK reaches the legacy connection too. Its
// getTokenByPassword sends the plain password grant, which signs in against
// the tenant's default directory (as the Auth0 documentation describes), so
// the custom database is exercised through its signUp instead: get_user,
// create and login all run, and the new user can then sign in.
const modern = new AuthClient({
  domain: 'localhost:8443', clientId: 'e2e-node', clientSecret: 'e2e-node-secret-not-for-production',
});
const newEmail = `auth-js-${Date.now()}@e2e.local`;
const newPassword = 'Modern-Password-123';
const signupBefore = await stats();
await modern.database.signUp({ email: newEmail, password: newPassword, connection: 'legacy-users' });
const signupAfter = await stats();
assert.equal(signupAfter.get_user - signupBefore.get_user, 1, 'signup checks get_user');
assert.equal(signupAfter.create - signupBefore.create, 1, 'signup runs create');
const created = await grant('legacy-users', newPassword, newEmail);
assert.ok((created.data ?? created).access_token, 'a user created through the custom database can sign in');
console.log('e2e m9 custom database: OK');
