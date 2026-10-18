// Black-box test (Plan 13, Review Focus 4): the pinned auth0-cli manages a
// zeroauthy tenant's applications through the Management API, logged in
// with client credentials (AUTH0_CLI_AUTH_MODE=env) and the tenant's
// canonical audience https://cli.e2e.test/api/v2/. auth0-cli only speaks to
// https://<domain>:443, so HTTPS_PROXY sends it through connect-proxy.mjs to
// zeroauthy. Needs AUTH0_BIN, E2E_CERT and the proxy on PROXY_PORT.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';

const bin = process.env.AUTH0_BIN;
const cert = process.env.E2E_CERT;
assert.ok(bin && cert, 'AUTH0_BIN and E2E_CERT are required');
const domain = 'cli.e2e.test';
const clientId = 'e2e-cli-admin';
const clientSecret = 'e2e-cli-admin-secret-not-for-production';

const env = {
  PATH: process.env.PATH,
  HOME: fs.mkdtempSync('/tmp/za-auth0-cli-'),
  HTTPS_PROXY: `http://127.0.0.1:${process.env.PROXY_PORT ?? 8098}`,
  SSL_CERT_FILE: cert,
  AUTH0_CLI_ANALYTICS: 'false',
  AUTH0_CLI_AUTH_MODE: 'env',
  AUTH0_DOMAIN: domain,
  AUTH0_CLIENT_ID: clientId,
  AUTH0_CLIENT_SECRET: clientSecret,
};

// auth0 runs the CLI and returns its parsed JSON output (or text).
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

// api calls the Management API directly (bulk set-up), on zeroauthy's
// port with the tenant's host.
function api(method, path, token, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const req = https.request(
      {
        host: '127.0.0.1', port: 8443, servername: domain, method, path, ca: fs.readFileSync(cert),
        headers: { host: domain, ...(token ? { authorization: `Bearer ${token}` } : {}), ...(data ? { 'content-type': 'application/json' } : {}) },
      },
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

// 1. apps create, one per type, with the CLI's own defaults.
const created = {};
for (const type of ['native', 'spa', 'regular', 'm2m']) {
  const app = auth0('apps', 'create', '--name', `cli-${type}`, '--type', type, '--reveal-secrets', '--json');
  assert.equal(app.name, `cli-${type}`);
  assert.match(app.client_id, /^[A-Za-z0-9]{32}$/);
  created[type] = app;
}
assert.equal(created.spa.app_type, 'spa');
assert.equal(created.spa.token_endpoint_auth_method, 'none');
assert.equal(created.spa.client_secret, undefined, 'public apps have no secret');
assert.equal(created.regular.app_type, 'regular_web');
assert.equal(created.m2m.app_type, 'non_interactive');
assert.equal(created.m2m.client_secret?.length, 64, 'a generated secret has 64 characters');

// 2. apps show --reveal-secrets returns the secret; without it, it does not.
const shown = auth0('apps', 'show', created.regular.client_id, '--reveal-secrets', '--json');
assert.equal(shown.client_secret?.length, 64);
assert.equal(auth0('apps', 'show', created.regular.client_id, '--json').client_secret, undefined);

// 3. apps update sends back what it read (refresh_token included).
const updated = auth0('apps', 'update', created.regular.client_id, '--name', 'cli-regular-renamed',
  '--callbacks', 'https://app.e2e.test/cb', '--json');
assert.equal(updated.name, 'cli-regular-renamed');
assert.deepEqual(updated.callbacks, ['https://app.e2e.test/cb']);

// 4. apps list pages: more than 100 applications need two pages.
const token = await new Promise((resolve, reject) => {
  const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, audience: `https://${domain}/api/v2/` }).toString();
  const req = https.request(
    { host: '127.0.0.1', port: 8443, servername: domain, method: 'POST', path: '/oauth/token', ca: fs.readFileSync(cert),
      headers: { host: domain, 'content-type': 'application/x-www-form-urlencoded' } },
    (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => (res.statusCode === 200 ? resolve(JSON.parse(text).access_token) : reject(new Error(text))));
    },
  );
  req.on('error', reject);
  req.end(form);
});
for (let i = 0; i < 101; i++) {
  const r = await api('POST', '/api/v2/clients', token, { name: `bulk-${i}`, app_type: 'non_interactive' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
}
const listed = auth0('apps', 'list', '--number', '1000', '--json');
const total = (await api('GET', '/api/v2/clients?include_totals=true&per_page=1', token)).body.total;
assert.ok(total > 100, `total ${total}`);
assert.equal(listed.length, total, 'apps list returns every application across pages');
assert.equal(new Set(listed.map((a) => a.client_id)).size, total, 'no application listed twice');

// 5. auth0 api get clients: the raw Management API.
const raw = auth0('api', 'get', 'clients', '--query', 'per_page=5');
assert.ok(Array.isArray(raw) && raw.length === 5, 'api get clients returned a page');

// 6. apps delete, then the application is gone.
auth0('apps', 'delete', created.regular.client_id, '--force');
assert.equal((await api('GET', `/api/v2/clients/${created.regular.client_id}`, token)).status, 404);

console.log(`m13-mgmt-cli: auth0-cli managed ${total} applications on ${domain}`);
