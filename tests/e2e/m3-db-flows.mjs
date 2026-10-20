// Black-box test (CLEAN_ROOM.md): node-auth0 AuthenticationClient against
// zeroauthy's database endpoints and password grants.
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { AuthClient } from '@auth0/auth0-auth-js';
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

// An API whose user policy is deny_all refuses the password grant (O7).
await assert.rejects(
  auth.oauth.passwordGrant({
    username: email, password: 'Node-Password-123', realm: connection,
    audience: 'https://locked.e2e.local', scope: 'openid',
  }),
  (err) => {
    assert.equal(err.statusCode ?? err.status, 400);
    assert.equal(err.error ?? err.body?.error ?? JSON.parse(err.body ?? '{}').error, 'invalid_request');
    return true;
  },
);

await auth.database.changePassword({ email, connection });
// The server sends emails in the background (D-0018), so poll briefly.
// The signup above also sent a verification email, so look for the reset
// link itself.
async function emailsWith(needle) {
  const dir = process.env.E2E_MAIL_DIR;
  const out = [];
  for (const f of (await readdir(dir)).filter((f) => f.endsWith('.eml'))) {
    // Quoted-printable may break the needle across a soft line break.
    const text = (await readFile(path.join(dir, f), 'utf8')).replace(/=\r?\n/g, '');
    if (text.includes(needle)) out.push(f);
  }
  return out;
}
let files = [];
for (let i = 0; i < 50 && files.length === 0; i++) {
  files = await emailsWith('/u/reset-password?ticket');
  if (files.length === 0) await new Promise((r) => setTimeout(r, 100));
}
assert.ok(files.length >= 1, 'a reset email was written');
assert.ok((await emailsWith('/u/email-verification?ticket')).length >= 1, 'signup sent a verification email');

// An unknown address gets the same success answer (D-0018): the endpoint
// does not reveal which addresses have accounts.
await auth.database.changePassword({ email: 'nobody@e2e.local', connection });

// The current SDK, @auth0/auth0-auth-js, documents the same flows in its
// README: database.signUp, getTokenByPassword with realm, and
// database.changePassword.
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
const unknown = await modern.database.changePassword({ email: 'nobody@e2e.local', connection });
assert.equal(unknown, message, 'an unknown address gets the same confirmation');
console.log('e2e m3 database flows: OK');
