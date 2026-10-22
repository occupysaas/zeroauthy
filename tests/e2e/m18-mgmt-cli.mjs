// Plan 18: auth0-cli imports hashes, reports the job and searches imported users.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
  const result = spawnSync(bin, [...args, '--no-input', '--no-color'], { env, encoding: 'utf8', timeout: 60_000 });
  if (result.error || result.status !== 0) {
    throw new Error(`auth0 ${args.slice(0, 2).join(' ')} exited ${result.status}: ${result.error ?? result.stderr}`);
  }
  const out = result.stdout;
  try {
    return JSON.parse(out);
  } catch {
    return out + result.stderr;
  }
}

// request talks to zeroauthy on the tenant's host. Bodies are JSON unless a
// form is given; the answer is parsed as JSON when it is.
function request(method, urlPath, { token, json, form, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = json !== undefined ? JSON.stringify(json) : form ? new URLSearchParams(form).toString() : undefined;
    const h = { host: domain, ...headers };
    if (token) h.authorization = `Bearer ${token}`;
    if (json !== undefined) h['content-type'] = 'application/json';
    if (form) h['content-type'] = 'application/x-www-form-urlencoded';
    const req = https.request({ host: '127.0.0.1', port: 8443, servername: domain, method, path: urlPath, ca: fs.readFileSync(cert), headers: h }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => {
        let body = text;
        try {
          body = text ? JSON.parse(text) : undefined;
        } catch {
          /* HTML */
        }
        resolve({ status: res.statusCode, body, text, headers: res.headers });
      });
    });
    req.on('error', reject);
    req.end(data);
  });
}



const admin = await request('POST', '/oauth/token', { form: { grant_type: 'client_credentials', client_id: env.AUTH0_CLIENT_ID,
  client_secret: env.AUTH0_CLIENT_SECRET, audience: `https://${domain}/api/v2/` } });
assert.equal(admin.status, 200, admin.text);
const token = admin.body.access_token;

const ids = (users) => users.map((u) => u.user_id).sort();
const search = (q) => auth0('users', 'search', '--query', q, '--json');

// 1. A database connection and an application that can sign in through it.
const conn = auth0('connections', 'create', '--name', 'cli-import-db', '--strategy', 'auth0', '--json');
const web = await request('POST', '/api/v2/clients', { token, json: { name: 'cli-import-web', app_type: 'regular_web',
  token_endpoint_auth_method: 'client_secret_post',
  grant_types: ['http://auth0.com/oauth/grant-type/password-realm', 'password'] } });
assert.equal(web.status, 201, web.text);
auth0('connections', 'enabled-clients', 'update', conn.id, '--data', JSON.stringify([{ client_id: web.body.client_id, status: true }]));
const realm = (username, password) => request('POST', '/oauth/token', { form: { grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
  client_id: web.body.client_id, client_secret: web.body.client_secret, username, password, realm: 'cli-import-db' } });

const fixture = JSON.parse(fs.readFileSync(new URL('fixtures/import-users.json', import.meta.url)));
try {
  const result = auth0('users', 'import', '--connection-name', 'cli-import-db', '--users', JSON.stringify(fixture), '--upsert', '--email-results=false');
  const jobID = String(result).match(/job_[A-Za-z0-9]{16}/)?.[0];
  assert.ok(jobID, String(result));
  let job;
  for (let i = 0; i < 100; i++) {
    const response = await request('GET', `/api/v2/jobs/${jobID}`, { token });
    assert.equal(response.status, 200);
    job = response.body;
    if (job.status === 'completed') break;
    assert.notEqual(job.status, 'failed', JSON.stringify(job));
    await new Promise(r => setTimeout(r, 100));
  }
  assert.equal(job.status, 'completed');
  assert.deepEqual(job.summary, { inserted: 4, updated: 0, failed: 1, total: 5 });
  for (const record of fixture.slice(0, 4)) {
    const users = search(`email:"${record.email}"`);
    assert.equal(users.length, 1, JSON.stringify(users));
    const signed = await realm(record.email, 'Pa55w0rd!');
    assert.equal(signed.status, 200, signed.text);
    assert.ok(signed.body.access_token);
  }
  assert.equal(search('email:"m18-invalid@e2e.local"').length, 0);
} finally {
  await request('DELETE', `/api/v2/connections/${conn.id}`, { token });
  await request('DELETE', `/api/v2/clients/${web.body.client_id}`, { token });
  fs.rmSync(env.HOME, { recursive: true, force: true });
}
console.log('m18-mgmt-cli: import, search and original-password sign-in passed');
