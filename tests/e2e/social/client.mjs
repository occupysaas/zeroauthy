import assert from 'node:assert/strict';
import { Agent, ProxyAgent } from 'undici';
// Node one and node two of the Plan 24 harness, through CONNECT proxies that
// map *.e2e.test:443 to each node.
export const fixtureDispatcher = new ProxyAgent('http://127.0.0.1:9198');
export const replicaDispatcher = new ProxyAgent('http://127.0.0.1:9199');
export const fixtureFetch = (url, options = {}) => fetch(url, { dispatcher: fixtureDispatcher, ...options });
export const primary = 'sdk.e2e.test';
export const ADMIN = { id: 'm24-admin', secret: 'm24-admin-secret-not-for-production' };
export const READER = { id: 'm24-reader', secret: 'm24-reader-secret-not-for-production' };
export const upstream = { id: 'm24-upstream-client', secret: 'm24-upstream-secret-not-for-production' };
export async function token(client = ADMIN, scope) {
 const r = await fixtureFetch(`https://${primary}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ grant_type: 'client_credentials', client_id: client.id, client_secret: client.secret, audience: `https://${primary}/api/v2/`, ...(scope ? { scope } : {}) }) });
 const out = await r.json(); assert.equal(r.status, 200, JSON.stringify(out)); return out.access_token;
}
export async function api(path, method = 'GET', body, bearer) {
 const r = await fixtureFetch(`https://${primary}/api/v2/${path}`, { method, headers: { authorization: `Bearer ${bearer ?? await token()}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
 const out = await r.json().catch(() => undefined); return { status: r.status, body: out, headers: r.headers };
}
export async function exchanges() {
 const r = await fetch('http://127.0.0.1:9173/exchanges', { dispatcher: new Agent() });
 return r.json();
}
export function noSecret(value) {
 const s = JSON.stringify(value);
 assert.ok(!s.includes(upstream.secret) && !s.includes('client_secret'), `secret exposed: ${s.slice(0, 200)}`);
}
export const oauthScript = `function fetchUserProfile(accessToken, context, callback) {
  request.get({ url: 'https://idp.e2e.test/oauth2/userinfo', headers: { Authorization: 'Bearer ' + accessToken }, json: true }, function (err, response, body) {
    if (err || response.statusCode !== 200) return callback(new Error('profile'));
    callback(null, { user_id: String(body.id), email: body.mail, name: body.display, email_verified: true });
  });
}`;
