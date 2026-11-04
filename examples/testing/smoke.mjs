// examples/testing/smoke.mjs: the fastest check that the test tenant works.
// Plain Node 22+, no dependencies.
//
//   NODE_EXTRA_CA_CERTS=./zeroauthy-ca.pem node examples/testing/smoke.mjs
//
// It signs a seeded user in with the password grant, verifies the ID token's
// signature against the tenant's JWKS and checks its claims, then calls the
// Management API with the M2M client. For a real browser login through the
// hosted login page, see login.spec.mjs.
import { createPublicKey, createVerify } from 'node:crypto';
import assert from 'node:assert/strict';

const BASE = process.env.ZEROAUTHY_URL ?? 'https://localhost:8443';
const ISSUER = `${BASE}/`;
// The Management API audience is the tenant's first domain (seed.yaml),
// whichever host the request goes to.
const MGMT_AUDIENCE = process.env.ZEROAUTHY_MGMT_AUDIENCE ?? 'https://localhost:8443/api/v2/';

async function post(path, form) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form),
  });
  const body = await res.json();
  assert.equal(res.status, 200, `${path}: ${res.status} ${JSON.stringify(body)}`);
  return body;
}

// Verifies an RS256 JWT against the tenant's JWKS and returns its payload.
async function verifyJWT(token, base = BASE) {
  const [h, p, s] = token.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  assert.equal(header.alg, 'RS256');
  const { keys } = await (await fetch(`${base}/.well-known/jwks.json`)).json();
  const jwk = keys.find((k) => k.kid === header.kid);
  assert.ok(jwk, `no JWKS key with kid ${header.kid}`);
  const ok = createVerify('RSA-SHA256').update(`${h}.${p}`)
    .verify(createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'));
  assert.ok(ok, 'signature does not verify');
  return JSON.parse(Buffer.from(p, 'base64url'));
}

// 1. Password grant for the verified seeded user.
const tokens = await post('/oauth/token', {
  grant_type: 'password',
  client_id: 'test-web',
  client_secret: 'test-web-secret-not-for-production',
  username: 'alice@example.test',
  password: 'Test-Password-Alice-1',
  scope: 'openid profile email',
});
const id = await verifyJWT(tokens.id_token);
assert.equal(id.iss, ISSUER);
assert.equal(id.aud, 'test-web');
assert.equal(id.email, 'alice@example.test');
assert.equal(id.email_verified, true);
assert.equal(id.name, 'Alice Tester');
assert.match(id.sub, /^auth0\|/);
assert.ok(id.exp > Date.now() / 1000);
console.log(`password grant: ${id.sub} ${id.email} (iss ${id.iss})`);

// 2. A wrong password is refused.
const bad = await fetch(`${BASE}/oauth/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'password', client_id: 'test-web', client_secret: 'test-web-secret-not-for-production',
    username: 'alice@example.test', password: 'wrong-password', scope: 'openid',
  }),
});
assert.equal(bad.status, 403);
assert.equal((await bad.json()).error, 'invalid_grant');

// 3. Management API token for test setup, then look the user up.
const mgmt = await post('/oauth/token', {
  grant_type: 'client_credentials',
  client_id: 'test-m2m',
  client_secret: 'test-m2m-secret-not-for-production',
  audience: MGMT_AUDIENCE,
});
const res = await fetch(`${BASE}/api/v2/users-by-email?email=${encodeURIComponent('bob@example.test')}`, {
  headers: { authorization: `Bearer ${mgmt.access_token}` },
});
assert.equal(res.status, 200);
const [bob] = await res.json();
assert.equal(bob.email_verified, false);
console.log(`management API: found ${bob.user_id} ${bob.email}`);
console.log('smoke test passed');
