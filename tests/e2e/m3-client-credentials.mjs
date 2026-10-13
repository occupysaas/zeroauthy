// Black-box test: Auth0's open-source SDKs talk to zeroauthy with only the
// domain changed. See CLEAN_ROOM.md: we observe requests to our own server.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';
import { AuthClient } from '@auth0/auth0-auth-js';
import { AuthenticationClient } from 'auth0/legacy';

const domain = process.env.ZA_DOMAIN ?? 'localhost:8443';
const clientId = 'e2e-m2m';
const clientSecret = 'e2e-m2m-secret-not-for-production';
const audience = 'https://api.e2e.local';

// 1. Current SDK: @auth0/auth0-auth-js (uses OIDC discovery).
const modern = new AuthClient({ domain, clientId, clientSecret });
const t1 = await modern.getTokenByClientCredentials({ audience });
assert.ok(t1.accessToken, '@auth0/auth0-auth-js returned an access token');

// 2. Legacy SDK: node-auth0 v4 AuthenticationClient via auth0/legacy.
const legacy = new AuthenticationClient({ domain, clientId, clientSecret });
const { data: t2 } = await legacy.oauth.clientCredentialsGrant({ audience });
assert.ok(t2.access_token, 'auth0/legacy returned an access token');

// 3. Resource server: express-oauth2-jwt-bearer validates both tokens.
const app = express();
app.get('/protected', auth({ issuerBaseURL: `https://${domain}`, audience }), (req, res) => {
  res.json({ sub: req.auth.payload.sub, scope: req.auth.payload.scope });
});
const server = app.listen(0, '127.0.0.1');
await once(server, 'listening');
const base = `http://127.0.0.1:${server.address().port}`;

try {
  for (const [name, token] of [['auth0-auth-js', t1.accessToken], ['auth0/legacy', t2.access_token]]) {
    const res = await fetch(`${base}/protected`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200, `${name} token accepted by express-oauth2-jwt-bearer`);
    const body = await res.json();
    assert.equal(body.sub, `${clientId}@clients`);
    assert.equal(body.scope, 'read:things');
  }
  const anon = await fetch(`${base}/protected`);
  assert.equal(anon.status, 401, 'request without a token is rejected');
  const forged = await fetch(`${base}/protected`, { headers: { authorization: `Bearer ${t1.accessToken.slice(0, -4)}AAAA` } });
  assert.equal(forged.status, 401, 'token with a broken signature is rejected');
} finally {
  server.close();
}
console.log('e2e m3 client credentials: OK');
