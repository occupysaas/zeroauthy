// Black-box test (Plan 15, Review Focus): the pinned auth0-cli manages a
// zeroauthy tenant's database connections through the Management API:
// create, list, show, update (options are replaced whole), enabled-clients.
// Then users sign up through /dbconnections/signup on the new connection:
// a password the policy refuses (the rule is named in the error), one it
// accepts, and, after password changes through the hosted reset page, an
// earlier password the history refuses. Deleting the connection removes its
// users. Needs AUTH0_BIN, E2E_CERT, E2E_MAIL_DIR and the proxy
// (connect-proxy.mjs) on PROXY_PORT, like m14-mgmt-cli.mjs.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';

const bin = process.env.AUTH0_BIN;
const cert = process.env.E2E_CERT;
const mailDir = process.env.E2E_MAIL_DIR;
assert.ok(bin && cert && mailDir, 'AUTH0_BIN, E2E_CERT and E2E_MAIL_DIR are required');
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const decodeQP = (s) => s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

// resetTicket waits for a reset email newer than since, with a ticket not seen
// before, and returns the ticket.
const seen = new Set();
async function resetTicket(since) {
  for (let i = 0; i < 100; i++) {
    const fresh = fs
      .readdirSync(mailDir)
      .filter((f) => f.endsWith('.eml'))
      .map((f) => [fs.statSync(path.join(mailDir, f)).mtimeMs, f])
      .filter(([t]) => t >= since)
      .sort((a, b) => b[0] - a[0]);
    if (fresh.length) {
      const mail = decodeQP(fs.readFileSync(path.join(mailDir, fresh[0][1]), 'utf8'));
      const m = mail.match(/\/u\/reset-password\?ticket=([A-Za-z0-9_-]+)/);
      if (m && !seen.has(m[1])) {
        seen.add(m[1]);
        return m[1];
      }
    }
    await sleep(100);
  }
  throw new Error('no reset email arrived');
}

// setPassword is the hosted reset page, as a browser would use it: the form
// carries a CSRF token that must match the page's cookie.
async function setPassword(ticket, password) {
  const page = await request('GET', `/u/reset-password?ticket=${ticket}`);
  assert.equal(page.status, 200, page.text);
  const csrf = page.text.match(/name="csrf" value="([^"]+)"/)[1];
  const cookie = [].concat(page.headers['set-cookie'] ?? []).map((c) => c.split(';')[0]).join('; ');
  return request('POST', '/u/reset-password', { form: { ticket, csrf, password, password_confirm: password }, headers: { cookie } });
}

const admin = await request('POST', '/oauth/token', { form: { grant_type: 'client_credentials', client_id: env.AUTH0_CLIENT_ID,
  client_secret: env.AUTH0_CLIENT_SECRET, audience: `https://${domain}/api/v2/` } });
assert.equal(admin.status, 200, admin.text);
const token = admin.body.access_token;

// An application that signs up and signs in through the connection
// (password-realm), and one that is only enabled and disabled.
const web = await request('POST', '/api/v2/clients', { token, json: { name: 'cli-conn-web', app_type: 'regular_web',
  token_endpoint_auth_method: 'client_secret_post',
  grant_types: ['http://auth0.com/oauth/grant-type/password-realm', 'password'] } });
assert.equal(web.status, 201, web.text);
const other = auth0('apps', 'create', '--name', 'cli-conn-other', '--type', 'regular', '--callbacks', 'https://app.e2e.test/cb', '--json');

// 1. connections create, then list and show by ID.
const created = auth0('connections', 'create', '--name', 'cli-db', '--strategy', 'auth0', '--json');
assert.equal(created.name, 'cli-db');
assert.equal(created.strategy, 'auth0');
assert.match(created.id, /^con_[A-Za-z0-9]{16}$/);
assert.equal(created.options.password_options.complexity.min_length, 15, 'the observed default');
assert.ok(auth0('connections', 'list', '--json').some((c) => c.id === created.id && c.name === 'cli-db'));
const shown = auth0('connections', 'show', created.id, '--json');
assert.equal(shown.id, created.id);
assert.equal(shown.name, 'cli-db');
assert.deepEqual(shown.realms, ['cli-db']);

// 2. connections update: options are replaced whole. A key not sent is gone,
//    and password_options keys not sent take their defaults.
const policy = {
  complexity: { min_length: 10 },
  history: { active: true, size: 2 },
  dictionary: { active: true, default: 'en_10k', custom: ['zebracrossing'] },
};
let updated = auth0('connections', 'update', created.id, '--data',
  JSON.stringify({ options: { password_options: policy, x_keep: 'one', x_gone: 'two' } }), '--json');
assert.equal(updated.options.x_gone, 'two');
assert.equal(updated.options.password_options.complexity.min_length, 10);
let again = auth0('connections', 'show', created.id, '--json');
assert.equal(again.options.x_keep, 'one');
assert.equal(again.options.x_gone, 'two');
assert.equal(again.options.password_options.history.size, 2);
updated = auth0('connections', 'update', created.id, '--data', JSON.stringify({ options: { x_keep: 'one' } }), '--json');
again = auth0('connections', 'show', created.id, '--json');
assert.equal(again.options.x_keep, 'one');
assert.equal(again.options.x_gone, undefined, 'a key not sent is gone');
assert.equal(again.options.password_options.complexity.min_length, 15, 'password_options not sent take their defaults');
assert.equal(again.options.password_options.history.active, false);
assert.equal(again.options.password_options.dictionary.active, false);

// 3. enabled-clients: enable two applications, then disable one.
const enabled = () => auth0('connections', 'enabled-clients', 'show', created.id, '--json').map((c) => c.client_id).sort();
assert.deepEqual(enabled(), []);
auth0('connections', 'enabled-clients', 'update', created.id, '--data',
  JSON.stringify([{ client_id: web.body.client_id, status: true }, { client_id: other.client_id, status: true }]));
assert.deepEqual(enabled(), [web.body.client_id, other.client_id].sort());
auth0('connections', 'enabled-clients', 'update', created.id, '--data', JSON.stringify([{ client_id: other.client_id, status: false }]));
assert.deepEqual(enabled(), [web.body.client_id]);
auth0('connections', 'enabled-clients', 'update', created.id, '--data', JSON.stringify([{ client_id: other.client_id, status: true }]));
assert.deepEqual(enabled(), [web.body.client_id, other.client_id].sort());
auth0('connections', 'enabled-clients', 'update', created.id, '--data', JSON.stringify([{ client_id: other.client_id, status: false }]));
assert.deepEqual(enabled(), [web.body.client_id]);

// 4. The policy again (min length 10, history 2, a custom dictionary word),
//    then sign-ups through /dbconnections/signup.
auth0('connections', 'update', created.id, '--data', JSON.stringify({ options: { password_options: policy } }), '--json');
const signup = (email, password) => request('POST', '/dbconnections/signup', { json: { client_id: web.body.client_id, connection: 'cli-db', email, password } });

const tooShort = await signup('cli-user@e2e.test', 'Short-1');
assert.equal(tooShort.status, 400, tooShort.text);
assert.equal(tooShort.body.error, 'invalid_password');
assert.match(tooShort.body.error_description, /at least 10 characters/, 'the length rule is named');
const common = await signup('cli-user@e2e.test', 'ZebraCrossing');
assert.equal(common.status, 400, common.text);
assert.equal(common.body.error, 'invalid_password');
assert.match(common.body.error_description, /too common/, 'the dictionary rule is named');

const first = 'Quartz-Lantern-42';
const ok = await signup('cli-user@e2e.test', first);
assert.equal(ok.status, 200, ok.text);
assert.equal(ok.body.email, 'cli-user@e2e.test');

// 5. History: the reset page is the way to set a password without being
//    signed in. A new password, then the earlier ones are refused.
const realm = (password) => request('POST', '/oauth/token', { form: { grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
  client_id: web.body.client_id, client_secret: web.body.client_secret, username: 'cli-user@e2e.test', password, realm: 'cli-db' } });
assert.equal((await realm(first)).status, 200, 'the new user signs in');
const requestReset = async () => {
  const since = Date.now() - 500;
  const r = await request('POST', '/dbconnections/change_password', { json: { client_id: web.body.client_id, connection: 'cli-db', email: 'cli-user@e2e.test' } });
  assert.equal(r.status, 200, r.text);
  return resetTicket(since);
};
const second = 'Amber-Meadow-77';
const changed = await setPassword(await requestReset(), second);
assert.equal(changed.status, 200, changed.text);
const stale = await realm(first);
assert.equal(stale.status, 400, 'the old password no longer signs in');
assert.equal(stale.body.error, 'invalid_grant');
assert.equal((await realm(second)).status, 200);
const ticket = await requestReset();
for (const reused of [first, second]) {
  const refused = await setPassword(ticket, reused);
  assert.equal(refused.status, 400, `${reused}: ${refused.text}`);
  assert.match(refused.text, /Password was used recently/, 'the history rule is named');
}
const third = 'Copper-Harbor-93';
assert.equal((await setPassword(ticket, third)).status, 200, 'the ticket survives refused passwords');
assert.equal((await realm(third)).status, 200);

// 6. Deleting the connection deletes its users: the user cannot sign in,
//    and the connection is gone. (There is no /api/v2/users to ask.)
auth0('connections', 'delete', created.id, '--force');
assert.ok(!auth0('connections', 'list', '--json').some((c) => c.id === created.id));
const gone = await request('GET', `/api/v2/connections/${created.id}`, { token });
assert.equal(gone.status, 404, gone.text);
assert.equal(gone.body.errorCode, 'inexistent_connection');
const after = await realm(third);
assert.ok(after.status >= 400 && after.status < 500, `a deleted connection's user signed in: ${after.status} ${after.text}`);
assert.equal((await signup('cli-user@e2e.test', 'Nickel-Valley-58')).status, 400, 'sign-up on the deleted connection is refused');

// 7. The same name again is a new, empty connection: the old user is not
//    there to collide with.
const reborn = auth0('connections', 'create', '--name', 'cli-db', '--strategy', 'auth0', '--json');
assert.notEqual(reborn.id, created.id);
auth0('connections', 'enabled-clients', 'update', reborn.id, '--data', JSON.stringify([{ client_id: web.body.client_id, status: true }]));
assert.equal((await realm(third)).status >= 400, true, 'the earlier user did not come back');
auth0('connections', 'delete', reborn.id, '--force');

console.log('m15-mgmt-cli: auth0-cli managed a database connection, its applications and its users on ' + domain);
