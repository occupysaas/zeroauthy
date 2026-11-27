// Plan 41c acceptance helpers: setup through the Management API, raw
// /bc-authorize and poll requests, the delivered mail, log events and the
// log audit.
// Values written to private-values.jsonl must never appear in the server log.
import assert from 'node:assert/strict';
import https from 'node:https';
import {appendFile, readFile, readdir} from 'node:fs/promises';

export const work = process.env.E2E_M41C_WORK;
export const origin = 'https://ciba.e2e.test';
export const mailDir = () => `${work}/mail`;
export const secrets = () => JSON.parse(process.env.E2E_M41C_CREDENTIALS);
export const CIBA = 'urn:openid:params:grant-type:ciba';

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

const form = (path, fields) => fixtureFetch(origin + path, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams(fields).toString()});
const json = async r => { const t = await r.text(); return t ? JSON.parse(t) : null; };

async function mgmt(method, path, body) {
  const t = await json(await form('/oauth/token', {grant_type: 'client_credentials', client_id: 'm41c-admin', client_secret: secrets().admin, audience: origin + '/api/v2/'}));
  await secret(t.access_token, 'access_token');
  const r = await fixtureFetch(`${origin}/api/v2/${path}`, {method, headers: {authorization: 'Bearer ' + t.access_token, 'content-type': 'application/json'}, body: body && JSON.stringify(body)});
  return {status: r.status, body: await json(r)};
}

export async function userID(email) {
  const r = await mgmt('GET', 'users-by-email?email=' + encodeURIComponent(email));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body[0].user_id;
}

export const hint = sub => JSON.stringify({format: 'iss_sub', iss: origin + '/', sub});

// start asks /bc-authorize for an approval by sub.
export async function start(sub, binding = 'ORDER-42', extra = {}) {
  const r = await form('/bc-authorize', {client_id: 'agent', client_secret: secrets().agent, scope: 'openid email offline_access', login_hint: hint(sub), binding_message: binding, requested_expiry: '600', ...extra});
  const b = await json(r);
  if (b?.auth_req_id) await secret(b.auth_req_id, 'auth_req_id');
  return {status: r.status, body: b};
}

export async function poll(id) {
  const r = await form('/oauth/token', {grant_type: CIBA, client_id: 'agent', client_secret: secrets().agent, auth_req_id: id});
  const b = await json(r);
  for (const k of ['access_token', 'id_token', 'refresh_token']) if (b?.[k]) await secret(b[k], k);
  return {status: r.status, body: b};
}

// mails returns the delivered messages (the dir mail driver's .eml files).
export async function mails() {
  const names = (await readdir(mailDir())).filter(n => n.endsWith('.eml'));
  return Promise.all(names.map(n => readFile(`${mailDir()}/${n}`, 'utf8').then(m => m.replace(/=\r?\n/g, '').replace(/=3D/g, '='))));
}

// approvalLink waits for the email carrying binding and returns its link.
export async function approvalLink(binding) {
  for (let i = 0; i < 100; i++) {
    const joined = (await mails()).filter(m => m.includes(binding)).join('\n');
    const link = joined.match(/https:\/\/ciba\.e2e\.test\/bc-verify\?consent=[A-Za-z0-9]+/)?.[0];
    if (link) return secret(link, 'approval_link');
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error('no approval email for ' + binding);
}

async function setup() {
  await secret(secrets().password, 'password');
  const tpl = await mgmt('POST', 'email-templates', {template: 'async_approval', body: '<p>{{application.name}} says click on <a href="{{url}}">{{url}}</a>, binding message: {{binding_message}}</p>', subject: 'Action Required', syntax: 'liquid', enabled: true, from: ''});
  assert.equal(tpl.status, 200, JSON.stringify(tpl.body));
  console.log('Plan41c setup: async_approval template');
}

async function raw() {
  const disc = await json(await fixtureFetch(origin + '/.well-known/openid-configuration'));
  assert.equal(disc.backchannel_authentication_endpoint, origin + '/bc-authorize');
  assert.deepEqual(disc.backchannel_token_delivery_modes_supported, ['poll']);
  assert.equal(disc.backchannel_user_code_parameter_supported, false);
  // Refusals.
  assert.equal((await start('x', 'two words')).body.error, 'invalid_request');
  assert.equal((await start('x', 'ORDER', {requested_expiry: '120'})).body.error, 'invalid_request');
  assert.equal((await start('x', 'ORDER', {scope: 'email'})).body.error, 'invalid_scope');
  // No oracle: unknown and unverified users get the valid shape.
  const shape = r => JSON.stringify([r.status, Object.keys(r.body).sort(), r.body.expires_in, r.body.interval, r.body.auth_req_id?.length]);
  const valid = await start(await userID('alice@ciba.e2e.local'), 'SHAPE-1');
  const unknown = await start('auth0|nobody', 'SHAPE-2');
  const unverified = await start(await userID('bob@ciba.e2e.local'), 'SHAPE-3');
  assert.equal(shape(valid), shape(unknown));
  assert.equal(shape(valid), shape(unverified));
  assert.equal(valid.status, 200);
  await approvalLink('SHAPE-1');
  await new Promise(r => setTimeout(r, 1000));
  const msgs = (await mails()).join('\n');
  assert.ok(!msgs.includes('SHAPE-2') && !msgs.includes('SHAPE-3'), 'only the valid user is emailed');
  // Pending, then slow_down.
  assert.equal((await poll(valid.body.auth_req_id)).body.error, 'authorization_pending');
  const slow = await poll(valid.body.auth_req_id);
  assert.equal(slow.body.error, 'slow_down'); assert.equal(slow.body.interval, 10);
  console.log('Plan41c raw requests passed');
}

// events checks the tenant log events through the Management API.
async function events() {
  for (const type of ['ciba_start_succeeded', 'ciba_start_failed', 'ciba_exchange_succeeded', 'ciba_exchange_failed']) {
    let found = false;
    for (let i = 0; i < 50 && !found; i++) {
      const r = await mgmt('GET', 'logs?q=' + encodeURIComponent('type:' + type));
      assert.equal(r.status, 200, JSON.stringify(r.body));
      found = r.body.length > 0;
      if (!found) await new Promise(res => setTimeout(res, 200));
    }
    assert.ok(found, `a ${type} log event`);
  }
  console.log('Plan41c log events: start and exchange, succeeded and failed');
}

async function audit() {
  const log = await readFile(`${work}/server.log`, 'utf8');
  const values = (await readFile(`${work}/private-values.jsonl`, 'utf8')).trim().split('\n').map(l => JSON.parse(l));
  for (const kind of ['auth_req_id', 'approval_link', 'access_token', 'id_token', 'refresh_token', 'password']) assert.ok(values.some(v => v.kind === kind), `the lane recorded a ${kind}`);
  for (const {kind, value} of values) {
    assert.ok(!log.includes(value), `${kind} found in the server log`);
    if (kind === 'approval_link') assert.ok(!log.includes(new URL(value).searchParams.get('consent')), 'approval value found in the server log');
  }
  console.log(`Plan41c log audit: ${values.length} private values absent from the server log`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const step = {setup, raw, events, audit}[process.argv[2]];
  if (!step) throw Error('usage: m41c-ciba.mjs setup|raw|events|audit');
  await step();
}
