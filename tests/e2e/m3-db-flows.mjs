// Black-box test (CLEAN_ROOM.md): node-auth0 AuthenticationClient against
// zeroauthy's database endpoints and password grants.
import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { AuthClient, ChangePasswordError } from '@auth0/auth0-auth-js';
import { AuthenticationClient } from 'auth0/legacy';

const auth = new AuthenticationClient({
  domain: 'localhost:8443', clientId: 'e2e-node', clientSecret: 'e2e-node-secret-not-for-production',
});
const email = `node-${Date.now()}@e2e.local`;
const connection = 'Username-Password-Authentication';

// The calls below follow the documented AuthenticationClient API of the
// pinned auth0 7.4.0. If the response shape differs (for example a .data
// wrapper), adapt the property access only, based on the public docs.
const signedUp = await auth.database.signUp({ email, password: 'Node-Password-123', connection });
assert.ok(signedUp.data?._id ?? signedUp._id, 'signUp returns _id');

const tokens = await auth.oauth.passwordGrant({
  username: email, password: 'Node-Password-123', realm: connection,
  audience: 'https://api.e2e.local', scope: 'openid offline_access read:things',
});
const t1 = tokens.data ?? tokens;
assert.ok(t1.access_token && t1.refresh_token && t1.id_token, 'password-realm grant returns tokens');

const refreshed = await auth.oauth.refreshTokenGrant({ refresh_token: t1.refresh_token });
assert.ok((refreshed.data ?? refreshed).access_token, 'refresh works');

await auth.database.changePassword({ email, connection });
const files = (await readdir(process.env.E2E_MAIL_DIR)).filter((f) => f.endsWith('.eml'));
assert.ok(files.length >= 1, 'a reset email was written');

await assert.rejects(auth.database.changePassword({ email: 'nobody@e2e.local', connection }), 'unknown user is rejected (404)');

// The current SDK, @auth0/auth0-auth-js, documents the same flows in its
// README: database.signUp, getTokenByPassword with realm, and
// database.changePassword (which throws ChangePasswordError on failure).
const modern = new AuthClient({
  domain: 'localhost:8443', clientId: 'e2e-node', clientSecret: 'e2e-node-secret-not-for-production',
});
const modernEmail = `auth-js-${Date.now()}@e2e.local`;
await modern.database.signUp({ email: modernEmail, password: 'Node-Password-123', connection });
const t2 = await modern.getTokenByPassword({
  username: modernEmail, password: 'Node-Password-123', realm: connection,
  audience: 'https://api.e2e.local', scope: 'openid read:things',
});
assert.ok(t2.accessToken, '@auth0/auth0-auth-js password-realm grant returns an access token');
const message = await modern.database.changePassword({ email: modernEmail, connection });
assert.equal(typeof message, 'string', 'changePassword returns the plain-text confirmation');
await assert.rejects(modern.database.changePassword({ email: 'nobody@e2e.local', connection }), ChangePasswordError,
  'unknown user is rejected (404)');
console.log('e2e m3 database flows: OK');
