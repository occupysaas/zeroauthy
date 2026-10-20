// Black-box test (Plan 17, Review Focus): the pinned auth0-cli manages users
// through the Management API: create, search (by email, by app_metadata, by
// a number-valued metadata key), show, update (profile, app_metadata through
// auth0 api, block, password) and delete. Then the Plan 15 follow-up: deleting
// a connection removes its users, as seen through `users search`. Needs
// AUTH0_BIN, E2E_CERT and the proxy (connect-proxy.mjs) on
// PROXY_PORT, like m15-mgmt-cli.mjs.
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
const conn = auth0('connections', 'create', '--name', 'cli-users-db', '--strategy', 'auth0', '--json');
const web = await request('POST', '/api/v2/clients', { token, json: { name: 'cli-users-web', app_type: 'regular_web',
  token_endpoint_auth_method: 'client_secret_post',
  grant_types: ['http://auth0.com/oauth/grant-type/password-realm', 'password'] } });
assert.equal(web.status, 201, web.text);
auth0('connections', 'enabled-clients', 'update', conn.id, '--data', JSON.stringify([{ client_id: web.body.client_id, status: true }]));
const realm = (username, password) => request('POST', '/oauth/token', { form: { grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
  client_id: web.body.client_id, client_secret: web.body.client_secret, username, password, realm: 'cli-users-db' } });

// 2. users create, with a name; a duplicate email is refused.
const pw = 'Quartz-Lantern-42';
const ada = auth0('users', 'create', '--name', 'Ada Lovelace', '--email', 'ada@cli-users.test', '--connection-name', 'cli-users-db',
  '--password', pw, '--json');
assert.match(ada.user_id, /^auth0\|[0-9a-f]{24}$/);
assert.equal(ada.email, 'ada@cli-users.test');
assert.equal(ada.name, 'Ada Lovelace');
assert.equal(ada.email_verified, false);
// (auth0-cli decodes the answer onto the struct it sent, so it echoes the
// password it was given; the raw answer is checked below.)
assert.equal(ada.password_hash, undefined);
const bob = auth0('users', 'create', '--data', JSON.stringify({ email: 'bob@cli-users.test', connection: 'cli-users-db', password: pw,
  app_metadata: { plan: 'pro', seats: 5 }, user_metadata: { colour: 'green' } }), '--json');
assert.equal(bob.app_metadata.plan, 'pro');
assert.equal(bob.user_metadata.colour, 'green');
const raw = await request('GET', `/api/v2/users/${encodeURIComponent(ada.user_id)}`, { token });
assert.equal(raw.status, 200, raw.text);
assert.equal(raw.body.password, undefined, 'no password in the server answer');
assert.equal(raw.body.password_hash, undefined);
assert.ok(!raw.text.includes(pw), 'the password is nowhere in the answer');
const cyd = auth0('users', 'create', '--data', JSON.stringify({ email: 'cyd@cli-users.test', connection: 'cli-users-db', password: pw,
  app_metadata: { plan: 'free', seats: 12 } }), '--json');
assert.throws(() => auth0('users', 'create', '--email', 'ada@cli-users.test', '--connection-name', 'cli-users-db', '--password', pw),
  /409|already exists/i, 'a duplicate email is refused');

// 3. users show, by ID.
const shown = auth0('users', 'show', ada.user_id, '--json');
assert.equal(shown.user_id, ada.user_id);
assert.equal(shown.email, 'ada@cli-users.test');
assert.equal(shown.identities[0].connection, 'cli-users-db');
assert.equal(shown.password_hash, undefined);

// 4. users search: by email, by app_metadata (string and number), a bare
//    wildcard on the domain, and a query the parser refuses.
assert.deepEqual(ids(search('email:"ada@cli-users.test"')), [ada.user_id]);
assert.deepEqual(ids(search('app_metadata.plan:pro')), [bob.user_id]);
assert.deepEqual(ids(search('app_metadata.seats:12')), [cyd.user_id]);
assert.deepEqual(ids(search('email:*@cli-users.test AND NOT app_metadata.plan:pro')), ids([ada, cyd]));
assert.deepEqual(ids(search('identities.connection:"cli-users-db"')), ids([ada, bob, cyd]));
assert.deepEqual(search('email:"nobody@cli-users.test"'), []);
// The refused queries go through request() so the server's own answer is
// checked: 400, no errorCode, Auth0's "invalid query: " messages.
const badQuery = (q) => request('GET', `/api/v2/users?search_engine=v3&q=${encodeURIComponent(q)}`, { token });
const range = await badQuery('app_metadata.seats:[10 TO *]');
assert.equal(range.status, 400, range.text);
assert.equal(range.body.errorCode, undefined, 'search errors carry no errorCode');
assert.match(range.body.message, /^invalid query: operator 'greater or equal' is not supported on field 'app_metadata\.seats'/);
const malformed = await badQuery('email:("ada');
assert.equal(malformed.status, 400, malformed.text);
assert.equal(malformed.body.errorCode, undefined);
assert.match(malformed.body.message, /^invalid query: /);
assert.throws(() => search('email:("ada'), /invalid query/i, 'auth0-cli surfaces the refusal');

// 5. users update: profile fields, app_metadata merge through auth0 api,
//    block and unblock, password.
const renamed = auth0('users', 'update', ada.user_id, '--name', 'Ada King', '--json');
assert.equal(renamed.name, 'Ada King');
assert.equal(renamed.email, 'ada@cli-users.test', 'fields not sent are kept');
auth0('api', 'patch', `users/${ada.user_id}`, '--data', JSON.stringify({ app_metadata: { plan: 'pro', team: { id: 7 } } }));
assert.deepEqual(ids(search('app_metadata.plan:pro')), ids([ada, bob]));
assert.deepEqual(ids(search('app_metadata.team.id:7')), [ada.user_id]);
auth0('api', 'patch', `users/${ada.user_id}`, '--data', JSON.stringify({ app_metadata: { plan: null } }));
assert.deepEqual(ids(search('app_metadata.plan:pro')), [bob.user_id], 'a null removes the key and the match');
assert.equal((await realm('ada@cli-users.test', pw)).status, 200);
const blocked = auth0('users', 'update', ada.user_id, '--blocked=true', '--json');
assert.equal(blocked.blocked, true);
assert.deepEqual(ids(search('blocked:true')), [ada.user_id]);
const refused = await realm('ada@cli-users.test', pw);
assert.equal(refused.status, 400, refused.text);
assert.equal(refused.body.error, 'invalid_grant');
assert.equal(refused.body.error_description, 'user is blocked');
assert.notEqual(auth0('users', 'update', ada.user_id, '--blocked=false', '--json').blocked, true);
assert.equal((await realm('ada@cli-users.test', pw)).status, 200);
const pw2 = 'Amber-Meadow-77';
auth0('users', 'update', ada.user_id, '--password', pw2, '--json');
assert.equal((await realm('ada@cli-users.test', pw)).status, 400, 'the old password is gone');
assert.equal((await realm('ada@cli-users.test', pw2)).status, 200);

// 6. users delete: one with --force, then it is gone from show and search.
auth0('users', 'delete', cyd.user_id, '--force');
assert.deepEqual(ids(search('email:*@cli-users.test')), ids([ada, bob]));
assert.throws(() => auth0('users', 'show', cyd.user_id, '--json'), /404|not exist|not found/i);
assert.equal((await realm('cyd@cli-users.test', pw)).status, 400, 'a deleted user cannot sign in');

// 7. Plan 15 follow-up: deleting the connection deletes its users, which
//    users search shows.
assert.deepEqual(ids(search('identities.connection:"cli-users-db"')), ids([ada, bob]));
auth0('connections', 'delete', conn.id, '--force');
assert.deepEqual(search('email:*@cli-users.test'), [], 'the connection took its users with it');
assert.throws(() => auth0('users', 'show', ada.user_id, '--json'), /404|not exist|not found/i);
const gone = await request('GET', `/api/v2/users/${encodeURIComponent(bob.user_id)}`, { token });
assert.equal(gone.status, 404, gone.text);

console.log('m17-mgmt-cli: auth0-cli created, searched, updated and deleted users on ' + domain);
