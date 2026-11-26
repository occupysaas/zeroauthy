// Plan 41b acceptance helpers: setup through the Management API, raw RFC
// 7591 and CIMD requests, and the log audit. Values written to
// private-values.jsonl must never appear in the server log.
import assert from 'node:assert/strict';
import https from 'node:https';
import {appendFile, readFile} from 'node:fs/promises';

export const work = process.env.E2E_M41B_WORK;
export const origin = 'https://dcr.e2e.test', closed = 'https://closed.e2e.test', app = 'https://app.dcr.e2e.test', API = 'https://api.dcr.e2e.test';
export const docs = 'https://cimd.example.com';
export const secrets = () => JSON.parse(process.env.E2E_M41B_CREDENTIALS);

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
  assert.ok([origin, closed].includes(url.origin), 'fixture refuses outbound destinations');
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

const json = async r => { const t = await r.text(); return t ? JSON.parse(t) : null; };

async function adminToken() {
  const r = await fixtureFetch(`${origin}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({grant_type: 'client_credentials', client_id: 'm41b-admin', client_secret: secrets().admin, audience: origin + '/api/v2/'}).toString()});
  const b = await r.json();
  assert.equal(r.status, 200, JSON.stringify(b));
  return secret(b.access_token, 'access_token');
}

export async function mgmt(method, path, body) {
  const r = await fixtureFetch(`${origin}/api/v2/${path}`, {method, headers: {authorization: 'Bearer ' + await adminToken(), 'content-type': 'application/json'}, body: body && JSON.stringify(body)});
  return {status: r.status, body: await json(r)};
}

// register posts an RFC 7591 registration and records the secret.
export async function register(body, base = origin) {
  const r = await fixtureFetch(`${base}/oidc/register`, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body)});
  const b = await json(r);
  if (b?.client_secret) await secret(b.client_secret, 'client_secret');
  return {status: r.status, body: b, headers: r.headers};
}

// setup: a default user grant for third-party applications on the API, the
// permission every dynamically registered client relies on.
async function setup() {
  await secret(secrets().password, 'password');
  const g = await mgmt('POST', 'client-grants', {default_for: 'third_party_clients', audience: API, subject_type: 'user', scope: ['read:things']});
  assert.equal(g.status, 201, JSON.stringify(g.body));
  assert.equal(g.body.default_for, 'third_party_clients');
  assert.equal((await mgmt('POST', 'client-grants', {default_for: 'third_party_clients', audience: origin + '/api/v2/', scope: []})).status, 400, 'system APIs refuse default grants');
  console.log('Plan41b setup: default third-party grant', g.body.id);
}

async function raw() {
  // Off on a tenant without DCR.
  assert.equal((await register({redirect_uris: [app + '/']}, closed)).status, 404);
  // Discovery advertises the endpoint and CIMD.
  const disc = await json(await fixtureFetch(`${origin}/.well-known/openid-configuration`));
  assert.equal(disc.registration_endpoint, origin + '/oidc/register');
  assert.equal(disc.client_id_metadata_document_supported, true);
  // A confidential registration: tpc_ ID, secret once, filtered grants.
  const conf = await register({client_name: 'Plan41b raw', redirect_uris: [app + '/cb'], grant_types: ['client_credentials', 'password', 'authorization_code']});
  assert.equal(conf.status, 201, JSON.stringify(conf.body));
  assert.match(conf.body.client_id, /^tpc_[0-9A-Za-z]{22}$/);
  assert.ok(conf.body.client_secret?.length >= 32);
  assert.equal(conf.body.client_secret_expires_at, 0);
  assert.deepEqual(conf.body.grant_types, ['authorization_code']);
  assert.equal(conf.headers.get('cache-control'), 'no-store');
  // It cannot use client_credentials.
  const cc = await fixtureFetch(`${origin}/oauth/token`, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({grant_type: 'client_credentials', client_id: conf.body.client_id, client_secret: conf.body.client_secret, audience: API}).toString()});
  assert.equal(cc.status, 403, 'a DCR client has no client_credentials grant');
  const view = await mgmt('GET', `clients/${conf.body.client_id}`);
  assert.equal(view.body.is_first_party, false);
  assert.equal(view.body.third_party_security_mode, 'permissive');
  assert.equal(view.body.external_metadata_type, 'dcr');
  assert.equal(view.body.external_metadata_created_by, 'client');
  // RFC 7591 errors.
  const badURI = await register({redirect_uris: ['http://app.example/cb']});
  assert.equal(badURI.status, 400); assert.equal(badURI.body.error, 'invalid_redirect_uri');
  const badMeta = await register({redirect_uris: [app + '/cb'], token_endpoint_auth_method: 'client_secret_basic'});
  assert.equal(badMeta.status, 400); assert.equal(badMeta.body.error, 'invalid_client_metadata');

  // CIMD: the seed registered client.json; preview and register through
  // the Management API; a mismatched document is refused.
  const seeded = await mgmt('POST', 'clients/cimd/preview', {external_client_id: docs + '/client.json'});
  assert.equal(seeded.status, 200, JSON.stringify(seeded.body));
  assert.equal(seeded.body.validation.valid, true);
  assert.match(seeded.body.client_id, /^tpc_/, 'the seed registered client.json');
  assert.equal(seeded.body.external_metadata_created_by, 'admin');
  const bad = await mgmt('POST', 'clients/cimd/preview', {external_client_id: docs + '/mismatch.json'});
  assert.equal(bad.body.validation.valid, false);
  assert.equal((await mgmt('POST', 'clients/cimd/register', {external_client_id: docs + '/mismatch.json'})).status, 400);
  const again = await mgmt('POST', 'clients/cimd/register', {external_client_id: docs + '/client.json'});
  assert.equal(again.status, 200, JSON.stringify(again.body));
  assert.equal(again.body.client_id, seeded.body.client_id);
  const cimdView = await mgmt('GET', `clients/${again.body.client_id}`);
  assert.equal(cimdView.body.external_client_id, docs + '/client.json');
  assert.equal(cimdView.body.external_metadata_type, 'cimd');

  // The registration limit: 5 per second per tenant.
  const burst = await Promise.all(Array.from({length: 8}, () => register({redirect_uris: [app + '/cb'], token_endpoint_auth_method: 'none'})));
  assert.ok(burst.some(r => r.status === 429), 'the burst reached the rate limit: ' + burst.map(r => r.status));
  console.log('Plan41b raw requests passed');
}

async function audit() {
  const log = await readFile(`${work}/server.log`, 'utf8');
  const values = (await readFile(`${work}/private-values.jsonl`, 'utf8')).trim().split('\n').map(l => JSON.parse(l));
  for (const kind of ['access_token', 'client_secret', 'password']) assert.ok(values.some(v => v.kind === kind), `the lane recorded a ${kind}`);
  for (const {kind, value} of values) assert.ok(!log.includes(value), `${kind} found in the server log`);
  assert.ok(log.includes('dynamic client registered'), 'registrations are logged');
  assert.ok(log.includes('seed CIMD client registered'), 'the seed registered its CIMD client');
  console.log(`Plan41b log audit: ${values.length} private values absent from the server log`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const step = {setup, raw, audit}[process.argv[2]];
  if (!step) throw Error('usage: m41b-dcr.mjs setup|raw|audit');
  await step();
}
