// Plan 42a My Account API acceptance helpers: setup through the Management
// API, raw request checks and the log audit. Values written to
// private-values.jsonl must never appear in the server log.
import assert from 'node:assert/strict';
import https from 'node:https';
import {appendFile, readFile} from 'node:fs/promises';

export const work = process.env.E2E_M42A_WORK;
export const origin = 'https://acct.e2e.test', app = 'https://app.acct.e2e.test', ME = origin + '/me/';
export const realm = 'Username-Password-Authentication', email = 'account42a@e2e.local';
export const scopes = ['read:me:factors', 'read:me:authentication_methods', 'create:me:authentication_methods', 'update:me:authentication_methods', 'delete:me:authentication_methods'];
export const secrets = () => JSON.parse(process.env.E2E_M42A_CREDENTIALS);

const watched = new Set();
export async function secret(value, kind = 'credential') {
  if (typeof value === 'string' && value.length >= 6 && !watched.has(value)) {
    watched.add(value);
    await appendFile(`${work}/private-values.jsonl`, JSON.stringify({kind, value}) + '\n', {mode: 0o600});
  }
  return value;
}

// fetch to the local server only, with the tenant's SNI and Host.
export function fixtureFetch(input, opts = {}) {
  const url = new URL(String(input));
  assert.equal(url.origin, origin, 'fixture refuses outbound destinations');
  return new Promise((resolve, reject) => {
    const req = https.request({hostname: '127.0.0.1', port: 9543, servername: url.hostname, method: opts.method ?? 'GET', path: url.pathname + url.search, headers: {...(opts.headers ?? {}), host: url.host}}, res => {
      let body = ''; res.setEncoding('utf8'); res.on('data', v => body += v);
      res.on('end', () => resolve(new Response([204, 205, 304].includes(res.statusCode) ? null : body, {status: res.statusCode, headers: res.headers})));
    });
    req.on('error', reject); req.setTimeout(45000, () => req.destroy(new Error('local fixture HTTP timeout')));
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function adminToken() {
  const s = secrets();
  const r = await fixtureFetch(`${origin}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({grant_type: 'client_credentials', client_id: 'm42a-admin', client_secret: s.admin, audience: origin + '/api/v2/'}).toString()});
  const b = await r.json();
  assert.equal(r.status, 200, JSON.stringify(b));
  return secret(b.access_token);
}

export async function mgmt(method, path, body) {
  const r = await fixtureFetch(`${origin}/api/v2/${path}`, {method, headers: {authorization: 'Bearer ' + await adminToken(), 'content-type': 'application/json'}, body: body && JSON.stringify(body)});
  const text = await r.text();
  assert.ok(r.status < 300, `${method} ${path} = ${r.status} ${text}`);
  return text ? JSON.parse(text) : undefined;
}

// setup: identifier-first login (a passkey prerequisite), TOTP, passkeys on
// the database connection without progressive enrollment, and the user.
async function setup() {
  await mgmt('PATCH', 'prompts', {universal_login_experience: 'new', identifier_first: true});
  await mgmt('PUT', 'guardian/factors/otp', {enabled: true});
  const [conn] = await mgmt('GET', 'connections?name=' + encodeURIComponent(realm));
  await mgmt('PATCH', 'connections/' + conn.id, {options: {...conn.options, authentication_methods: {password: {enabled: true}, passkey: {enabled: true}}, passkey_options: {challenge_ui: 'button', progressive_enrollment_enabled: false, local_enrollment_enabled: false}}});
  await secret(secrets().password, 'password');
  await mgmt('POST', 'users', {connection: realm, email, email_verified: true, password: secrets().password});
  console.log('Plan42a setup: prompts, TOTP, passkeys and user');
}

const problemShape = b => ['type', 'status', 'title', 'detail'].every(k => k in b);

// raw: errors without a browser: no token, a bad token, client credentials.
async function raw() {
  const none = await fixtureFetch(`${origin}/me/v1/factors`, {headers: {'x-correlation-id': 'plan42a-raw'}});
  const nb = await none.json();
  assert.equal(none.status, 401); assert.ok(problemShape(nb), JSON.stringify(nb));
  assert.equal(none.headers.get('x-correlation-id'), 'plan42a-raw');
  const bad = await fixtureFetch(`${origin}/me/v1/authentication-methods`, {headers: {authorization: 'Bearer not.a.token'}});
  assert.equal(bad.status, 401);
  const s = secrets();
  const cc = await fixtureFetch(`${origin}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({grant_type: 'client_credentials', client_id: 'm42a-admin', client_secret: s.admin, audience: ME}).toString()});
  assert.equal((await cc.json()).error, 'access_denied', 'client credentials for the My Account API');
  const pre = await fixtureFetch(`${origin}/me/v1/factors`, {method: 'OPTIONS', headers: {origin: 'https://evil.e2e.test', 'access-control-request-method': 'GET'}});
  assert.equal(pre.status, 403, 'foreign origin preflight');
  const ok = await fixtureFetch(`${origin}/me/v1/authentication-methods/x`, {method: 'OPTIONS', headers: {origin: app, 'access-control-request-method': 'DELETE', 'access-control-request-headers': 'authorization'}});
  assert.equal(ok.status, 204); assert.match(ok.headers.get('access-control-allow-methods'), /DELETE/);
  console.log('Plan42a raw requests passed');
}

// audit: no private value reaches the server log.
async function audit() {
  const log = await readFile(`${work}/server.log`, 'utf8');
  const values = (await readFile(`${work}/private-values.jsonl`, 'utf8')).trim().split('\n').map(l => JSON.parse(l));
  assert.ok(values.some(v => v.kind === 'totp_secret') && values.some(v => v.kind === 'auth_session') && values.some(v => v.kind === 'attestation'), 'the browser lane recorded its secrets');
  for (const {kind, value} of values) assert.ok(!log.includes(value), `${kind} found in the server log`);
  console.log(`Plan42a log audit: ${values.length} private values absent from the server log`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const step = {setup, raw, audit}[process.argv[2]];
  if (!step) throw Error('usage: m42a-my-account.mjs setup|raw|audit');
  await step();
}
