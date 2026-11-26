// Plan 42b My Organization API acceptance helpers: setup through the
// Management API, raw request checks and the log audit. Values written to
// private-values.jsonl must never appear in the server log.
import assert from 'node:assert/strict';
import https from 'node:https';
import {appendFile, readFile, writeFile} from 'node:fs/promises';

export const work = process.env.E2E_M42B_WORK;
export const origin = 'https://acct.e2e.test', app = 'https://app.acct.e2e.test', ORG = origin + '/my-org/';
export const scopes = ['read:my_org:configuration', 'read:my_org:details', 'update:my_org:details', 'read:my_org:members', 'delete:my_org:memberships', 'read:my_org:member_roles', 'create:my_org:member_roles', 'delete:my_org:member_roles', 'read:my_org:member_invitations', 'create:my_org:member_invitations', 'delete:my_org:member_invitations', 'read:my_org:user_stores'];
export const secrets = () => JSON.parse(process.env.E2E_M42B_CREDENTIALS);
export const orgs = async () => JSON.parse(await readFile(`${work}/orgs.json`, 'utf8'));

const watched = new Set();
export async function secret(value, kind = 'credential') {
  if (typeof value === 'string' && value.length >= 6 && !watched.has(value)) {
    watched.add(value);
    await appendFile(`${work}/private-values.jsonl`, JSON.stringify({kind, value}) + '\n', {mode: 0o600});
  }
  return value;
}

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
  const r = await fixtureFetch(`${origin}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({grant_type: 'client_credentials', client_id: 'm42b-admin', client_secret: secrets().admin, audience: origin + '/api/v2/'}).toString()});
  const b = await r.json();
  assert.equal(r.status, 200, JSON.stringify(b));
  return secret(b.access_token);
}

async function mgmt(method, path, body) {
  const r = await fixtureFetch(`${origin}/api/v2/${path}`, {method, headers: {authorization: 'Bearer ' + await adminToken(), 'content-type': 'application/json'}, body: body && JSON.stringify(body)});
  const text = await r.text();
  assert.ok(r.status < 300, `${method} ${path} = ${r.status} ${text}`);
  return text ? JSON.parse(text) : undefined;
}

// setup: organization IDs for the browser, and no invitation email (the
// lane has no mail provider).
async function setup() {
  const out = {};
  for (const o of await mgmt('GET', 'organizations')) out[o.name] = o.id;
  await writeFile(`${work}/orgs.json`, JSON.stringify(out), {mode: 0o600});
  await mgmt('PATCH', 'clients/m42b-spa', {initiate_login_uri: app + '/login'});
  await mgmt('POST', 'email-templates', {template: 'user_invitation', body: '<p>{{ url }}</p>', from: 'noreply@acct.e2e.test', subject: 'Invitation', syntax: 'liquid', enabled: false});
  await secret(secrets().password, 'password');
  console.log('Plan42b setup: organizations', Object.keys(out).join(', '));
}

async function raw() {
  const none = await fixtureFetch(`${origin}/my-org/v1/members`, {headers: {'x-correlation-id': 'plan42b-raw'}});
  const nb = await none.json();
  assert.equal(none.status, 401); assert.ok(['type', 'status', 'title'].every(k => k in nb), JSON.stringify(nb));
  assert.equal(none.headers.get('x-correlation-id'), 'plan42b-raw');
  const cc = await fixtureFetch(`${origin}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({grant_type: 'client_credentials', client_id: 'm42b-admin', client_secret: secrets().admin, audience: ORG}).toString()});
  assert.equal((await cc.json()).error, 'access_denied', 'client credentials for the My Organization API');
  const pre = await fixtureFetch(`${origin}/my-org/v1/members`, {method: 'OPTIONS', headers: {origin: app, 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization,content-type'}});
  assert.equal(pre.status, 204);
  console.log('Plan42b raw requests passed');
}

async function audit() {
  const log = await readFile(`${work}/server.log`, 'utf8');
  const values = (await readFile(`${work}/private-values.jsonl`, 'utf8')).trim().split('\n').map(l => JSON.parse(l));
  assert.ok(values.some(v => v.kind === 'invitation_url') && values.some(v => v.kind === 'access_token'), 'the browser lane recorded its secrets');
  for (const {kind, value} of values) assert.ok(!log.includes(value), `${kind} found in the server log`);
  console.log(`Plan42b log audit: ${values.length} private values absent from the server log`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const step = {setup, raw, audit}[process.argv[2]];
  if (!step) throw Error('usage: m42b-my-org.mjs setup|raw|audit');
  await step();
}
