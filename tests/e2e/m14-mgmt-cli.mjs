// Black-box test (Plan 14, Review Focus): the pinned auth0-cli manages a
// zeroauthy tenant's APIs (resource servers) and client grants through the
// Management API, logged in with client credentials against the tenant's
// canonical audience. Then a client-credentials token for the new API
// carries exactly the granted scopes. Needs AUTH0_BIN, E2E_CERT and the
// proxy (connect-proxy.mjs) on PROXY_PORT, like m13-mgmt-cli.mjs.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';

const bin = process.env.AUTH0_BIN;
const cert = process.env.E2E_CERT;
assert.ok(bin && cert, 'AUTH0_BIN and E2E_CERT are required');
const domain = 'cli.e2e.test';

const env = {
  PATH: process.env.PATH,
  HOME: fs.mkdtempSync('/tmp/za-auth0-cli-'),
  HTTPS_PROXY: `http://127.0.0.1:${process.env.PROXY_PORT ?? 8098}`,
  SSL_CERT_FILE: cert,
  AUTH0_CLI_ANALYTICS: 'false',
  AUTH0_CLI_AUTH_MODE: 'env',
  AUTH0_DOMAIN: domain,
  AUTH0_CLIENT_ID: 'e2e-cli-admin',
  AUTH0_CLIENT_SECRET: 'e2e-cli-admin-secret-not-for-production',
};

function auth0(...args) {
  let out;
  try {
    out = execFileSync(bin, [...args, '--no-input'], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 }).toString();
  } catch (e) {
    throw new Error(`auth0 ${args.join(' ')} exited ${e.status}: ${e.stderr}`);
  }
  try {
    return JSON.parse(out);
  } catch {
    return out;
  }
}

// call uses the Management API directly (bulk set-up).
function call(method, path, token, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const req = https.request(
      { host: '127.0.0.1', port: 8443, servername: domain, method, path, ca: fs.readFileSync(cert),
        headers: { host: domain, authorization: `Bearer ${token}`, ...(data ? { 'content-type': 'application/json' } : {}) } },
      (res) => {
        let text = '';
        res.on('data', (c) => (text += c));
        res.on('end', () => resolve({ status: res.statusCode, body: text ? JSON.parse(text) : undefined }));
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

// post sends a form to zeroauthy on the tenant's host.
function post(path, form) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: '127.0.0.1', port: 8443, servername: domain, method: 'POST', path, ca: fs.readFileSync(cert),
        headers: { host: domain, 'content-type': 'application/x-www-form-urlencoded' } },
      (res) => {
        let text = '';
        res.on('data', (c) => (text += c));
        res.on('end', () => resolve({ status: res.statusCode, body: text ? JSON.parse(text) : undefined }));
      },
    );
    req.on('error', reject);
    req.end(new URLSearchParams(form).toString());
  });
}

const audience = 'https://orders.cli.e2e.test';

// 1. apis create with permissions, then show by id and by identifier.
const api = auth0('apis', 'create', '--name', 'Orders API', '--identifier', audience, '--scopes', 'read:orders,write:orders',
  '--token-lifetime', '7200', '--offline-access=false', '--json');
assert.equal(api.identifier, audience);
assert.equal(api.name, 'Orders API');
assert.equal(api.token_lifetime, 7200);
assert.deepEqual(api.scopes.map((s) => s.value).sort(), ['read:orders', 'write:orders']);
const byId = auth0('apis', 'show', api.id, '--json');
assert.equal(byId.identifier, audience);
const byIdentifier = auth0('apis', 'show', audience, '--json');
assert.equal(byIdentifier.id, api.id, 'apis show reads by identifier');

// 2. apis list includes it; apis scopes list shows its permissions.
assert.ok(auth0('apis', 'list', '--number', '100', '--json').some((a) => a.id === api.id));
const scopes = auth0('apis', 'scopes', 'list', audience, '--json');
assert.deepEqual(scopes.map((s) => s.value).sort(), ['read:orders', 'write:orders']);

// 3. apis update: rename and add a permission with --scopes.
const updated = auth0('apis', 'update', api.id, '--name', 'Orders API v2', '--scopes', 'read:orders,write:orders,delete:orders', '--json');
assert.equal(updated.name, 'Orders API v2');
assert.deepEqual(updated.scopes.map((s) => s.value).sort(), ['delete:orders', 'read:orders', 'write:orders']);

// 4. An application, then client-grants create with one scope.
const app = auth0('apps', 'create', '--name', 'cli-orders-m2m', '--type', 'm2m', '--reveal-secrets', '--json');
const grant = auth0('client-grants', 'create', '--client-id', app.client_id, '--audience', audience, '--scopes', 'read:orders', '--json');
assert.equal(grant.client_id, app.client_id);
assert.equal(grant.audience, audience);
assert.deepEqual(grant.scope, ['read:orders']);
assert.equal(auth0('client-grants', 'show', grant.id, '--json').id, grant.id);

// 5. client-grants list pages with checkpoint paging (include_totals, take, next).
for (let i = 0; i < 3; i++) {
  const extra = auth0('apps', 'create', '--name', `cli-grant-${i}`, '--type', 'm2m', '--json');
  auth0('client-grants', 'create', '--client-id', extra.client_id, '--audience', audience, '--scopes', 'read:orders', '--json');
}
const filtered = auth0('client-grants', 'list', '--audience', audience, '--number', '100', '--json');
assert.equal(filtered.length, 4);
assert.ok(filtered.some((g) => g.id === grant.id));
const everything = auth0('client-grants', 'list', '--number', '1000', '--json');
assert.ok(everything.length >= 5);
assert.equal(new Set(everything.map((g) => g.id)).size, everything.length, 'no grant listed twice');

// More than one checkpoint page (take=50): the CLI follows `next`.
const admin = await post('/oauth/token', { grant_type: 'client_credentials', client_id: env.AUTH0_CLIENT_ID,
  client_secret: env.AUTH0_CLIENT_SECRET, audience: `https://${domain}/api/v2/` });
for (let i = 0; i < 55; i++) {
  const c = await call('POST', '/api/v2/clients', admin.body.access_token, { name: `bulk-grant-${i}`, app_type: 'non_interactive' });
  assert.equal(c.status, 201, JSON.stringify(c.body));
  const g = await call('POST', '/api/v2/client-grants', admin.body.access_token, { client_id: c.body.client_id, audience, scope: ['read:orders'] });
  assert.equal(g.status, 201, JSON.stringify(g.body));
}
const paged = auth0('client-grants', 'list', '--audience', audience, '--number', '1000', '--json');
assert.equal(paged.length, 59, 'client-grants list follows next across checkpoint pages');
assert.equal(new Set(paged.map((g) => g.id)).size, 59);

// 6. The token carries exactly the granted scope.
const cc = { grant_type: 'client_credentials', client_id: app.client_id, client_secret: app.client_secret, audience };
let tok = await post('/oauth/token', cc);
assert.equal(tok.status, 200, JSON.stringify(tok.body));
assert.equal(tok.body.scope, 'read:orders');
assert.equal(JSON.parse(Buffer.from(tok.body.access_token.split('.')[1], 'base64url')).aud, audience);

// 7. client-grants update widens it; the next token has both scopes.
const widened = auth0('client-grants', 'update', grant.id, '--scopes', 'read:orders,write:orders', '--json');
assert.deepEqual(widened.scope.sort(), ['read:orders', 'write:orders']);
tok = await post('/oauth/token', cc);
assert.deepEqual(tok.body.scope.split(' ').sort(), ['read:orders', 'write:orders']);

// 8. client-grants delete: the token is refused.
auth0('client-grants', 'delete', grant.id, '--force');
tok = await post('/oauth/token', cc);
assert.equal(tok.status, 403, JSON.stringify(tok.body));
assert.equal(tok.body.error, 'access_denied');

// 9. apis delete removes the API and, with it, its remaining grants.
auth0('apis', 'delete', api.id, '--force');
assert.ok(!auth0('apis', 'list', '--number', '100', '--json').some((a) => a.id === api.id));
assert.equal(auth0('client-grants', 'list', '--audience', audience, '--json').length, 0);

// 10. The tenant's default audience (seed: default_audience) is an API an
//     operator can delete. Deleting it clears the tenant's default audience
//     (D-0041), so audience-less requests behave as for a tenant with none:
//     client credentials need an audience, and /authorize carries on.
const defaultAudience = 'https://default.cli.e2e.test';
const defaultApi = auth0('apis', 'create', '--name', 'Default API', '--identifier', defaultAudience, '--scopes', 'read:default', '--json');
const defaultApp = auth0('apps', 'create', '--name', 'cli-default-m2m', '--type', 'm2m', '--reveal-secrets', '--json');
const webApp = auth0('apps', 'create', '--name', 'cli-default-web', '--type', 'regular', '--callbacks', 'https://app.e2e.test/cb', '--json');
auth0('client-grants', 'create', '--client-id', defaultApp.client_id, '--audience', defaultAudience, '--scopes', 'read:default', '--json');
const noAudience = { grant_type: 'client_credentials', client_id: defaultApp.client_id, client_secret: defaultApp.client_secret };
tok = await post('/oauth/token', noAudience);
assert.equal(tok.status, 200, JSON.stringify(tok.body));
assert.equal(JSON.parse(Buffer.from(tok.body.access_token.split('.')[1], 'base64url')).aud, defaultAudience, 'the default audience applies');
const authorizeURL = '/authorize?' + new URLSearchParams({ client_id: webApp.client_id, response_type: 'code', redirect_uri: 'https://app.e2e.test/cb',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', state: 'abc' });
function get(path) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host: '127.0.0.1', port: 8443, servername: domain, method: 'GET', path, ca: fs.readFileSync(cert), headers: { host: domain } }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location }));
    });
    req.on('error', reject);
    req.end();
  });
}
const before = await get(authorizeURL);
auth0('apis', 'delete', defaultApi.id, '--force');
tok = await post('/oauth/token', noAudience);
assert.equal(tok.status, 400, JSON.stringify(tok.body));
assert.equal(tok.body.error, 'invalid_request');
const after = await get(authorizeURL);
assert.equal(after.status, before.status, `/authorize after deleting the default audience answered ${after.status}`);
assert.ok(after.status < 500);
console.log(`m14-mgmt-cli: /authorize with the default audience present: ${before.status} ${before.location ?? ''}`);
console.log(`m14-mgmt-cli: /authorize with the default audience deleted: ${after.status} ${after.location ?? ''}`);

console.log('m14-mgmt-cli: auth0-cli managed an API and its client grants on ' + domain);
