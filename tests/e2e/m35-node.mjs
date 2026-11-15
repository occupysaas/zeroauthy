// Plan 35: shared fixtures (real local HTTP through the CONNECT proxy, RSA
// keys, a hand-built JWS signer, a fetch that records every credential it
// sends) and the node lanes: setup; sdk (pinned @auth0/auth0-auth-js 1.16.1
// with clientAssertionSigningKey, node-auth0 7.4.0 credentials and profiles
// managers, express-oauth2-jwt-bearer 1.11.0 verifying RS256, PS256 and HS256
// tokens); exchange (custom token exchange with a deployed Action); snapshot
// (the log export); and the representative-secret audit.
import assert from "node:assert/strict";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { constants, createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { createRequire } from "node:module";
import https from "node:https";
import tls from "node:tls";
import { ProxyAgent } from "undici";
import { ManagementClient } from "auth0";
import { AuthClient } from "@auth0/auth0-auth-js";
import express from "express";
import { auth as jwtBearer } from "express-oauth2-jwt-bearer";

export const work = process.env.E2E_M35_WORK;
export const domain = "sdk.e2e.test";
export const origin = `https://${domain}`;
export const issuer = `${origin}/`;
export const realm = "Username-Password-Authentication";
export const password = "Plan35-User-Password-2026",
  operatorPassword = "Plan35-Operator-Password-2026";
export const admin = { client: "m35-admin", secret: "Plan35-Management-Secret-2026" };
export const bridgeSecret = "Plan35-Bridge-Client-Secret-2026";
export const redirect = "https://callback.e2e.test/";
export const API = "https://api.m35.e2e.test";
export const HS_API = "https://hs256.m35.e2e.test";
export const PS_API = "https://ps256.m35.e2e.test";
export const SUBJECT_TYPE = "urn:plan35:legacy-token";
export const ACTOR_TYPE = "urn:plan35:service-token";
export const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
export const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

const dispatcher = new ProxyAgent("http://127.0.0.1:9198");
const statePath = () => `${work}/private-state.json`;
export async function state() {
  try {
    return JSON.parse(await readFile(statePath(), "utf8"));
  } catch {
    return {};
  }
}
export async function saveState(patch) {
  const next = { ...(await state()), ...patch };
  await writeFile(statePath(), JSON.stringify(next), { mode: 0o600 });
  return next;
}

// Representative secrets: every value is appended mode 0600 and must be absent
// from every captured sink.
const recorded = new Set();
export async function secret(value, kind) {
  assert.equal(typeof value, "string", `${kind} is not a string`);
  assert.ok(value.length >= 6, `${kind} too short to scan`);
  if (!recorded.has(value)) {
    recorded.add(value);
    await appendFile(`${work}/private-secrets.jsonl`, JSON.stringify({ kind, value }) + "\n", { mode: 0o600 });
  }
  return value;
}
// Every credential the clients send (an SDK builds some itself) becomes a
// representative secret before the request leaves.
const watched = {
  client_assertion: "client assertion",
  request: "request object",
  subject_token: "subject token",
  actor_token: "actor token",
  client_secret: "client secret",
};
async function recordSent(body) {
  if (body == null) return;
  let text = null;
  if (typeof body === "string") text = body;
  else if (body instanceof URLSearchParams) text = body.toString();
  else if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) text = Buffer.from(body).toString();
  if (!text) return;
  let fields;
  try {
    fields = JSON.parse(text);
  } catch {
    fields = Object.fromEntries(new URLSearchParams(text));
  }
  if (!fields || typeof fields !== "object") return;
  for (const [k, kind] of Object.entries(watched)) if (typeof fields[k] === "string" && fields[k].length >= 6) await secret(fields[k], kind);
}
export async function fixtureFetch(input, opts = {}) {
  const url = new URL(input instanceof Request ? input.url : String(input));
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  for (const [k, v] of new Headers(opts.headers ?? {})) headers.set(k, v);
  let { body, method } = opts;
  if (input instanceof Request) {
    method = method ?? input.method;
    if (body === undefined && !["GET", "HEAD"].includes(input.method)) body = await input.arrayBuffer();
  }
  await recordSent(body);
  return fetch(url, { ...opts, method, body, headers, dispatcher });
}

// Documented returned secrets (Management reads return client_secret and an
// HS256 API's signing_secret, C16) are replaced in our own captures; server
// sinks are scanned unmodified.
const documented = new Set(["client_secret", "signing_secret"]);
export function redactDocumented(value) {
  if (Array.isArray(value)) return value.map(redactDocumented);
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, documented.has(k) && typeof v === "string" ? "<documented-secret>" : redactDocumented(v)]));
  return value;
}
export function redactText(text) {
  try {
    return JSON.stringify(redactDocumented(JSON.parse(text)));
  } catch {
    return text;
  }
}
export async function capture(name, value) {
  await appendFile(`${work}/responses.jsonl`, JSON.stringify({ name, value: redactDocumented(value) }) + "\n");
  return value;
}
export async function until(fn, label, timeout = 30000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error(`timed out: ${label}`);
}

let bearer;
export async function token() {
  if (bearer) return bearer;
  const r = await fixtureFetch(`${origin}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "client_credentials", client_id: admin.client, client_secret: admin.secret, audience: `${origin}/api/v2/` }),
  });
  const b = await r.json();
  assert.equal(r.status, 200, JSON.stringify(b));
  bearer = await secret(b.access_token, "management token");
  return bearer;
}
export async function raw(path, method = "GET", body) {
  const r = await fixtureFetch(`${origin}/api/v2/${path}`, {
    method,
    headers: { authorization: `Bearer ${await token()}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const value = r.status === 204 ? null : await r.json().catch(() => null);
  await capture(`${method} ${path} ${r.status}`, value);
  return { status: r.status, body: value };
}
export async function api(path, method = "GET", body) {
  const r = await raw(path, method, body);
  assert.ok(r.status >= 200 && r.status < 300, `${method} ${path}: ${r.status} ${JSON.stringify(redactDocumented(r.body))}`);
  return r.body;
}
export const management = async () => new ManagementClient({ domain, token: await token(), maxRetries: 0, fetch: fixtureFetch });

// RSA keys: PKCS#8 for the signer, SPKI for registration.
export function rsaKey() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { pkcs8: privateKey.export({ type: "pkcs8", format: "pem" }), spki: publicKey.export({ type: "spki", format: "pem" }) };
}
// A compact JWS signed here, independent of the SDKs.
export function jws(header, payload, pkcs8) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const input = `${b64(header)}.${b64(payload)}`;
  const hash = header.alg === "RS384" ? "sha384" : "sha256";
  const key = header.alg === "PS256" ? { key: pkcs8, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 } : pkcs8;
  return `${input}.${sign(hash, Buffer.from(input), key).toString("base64url")}`;
}
export const now = () => Math.floor(Date.now() / 1000);
export async function assertion(clientId, pkcs8, { alg = "RS256", aud = issuer, kid, jti = randomUUID(), lifetime = 120 } = {}) {
  const t = now();
  return secret(jws({ alg, ...(kid ? { kid } : {}) }, { iss: clientId, sub: clientId, aud, jti, iat: t, exp: t + lifetime }, pkcs8), "client assertion");
}
export async function requestObject(clientId, params, pkcs8, { alg = "RS256", typ = "oauth-authz-req+jwt", aud = issuer, jti = randomUUID() } = {}) {
  const t = now();
  return secret(jws({ alg, typ }, { ...params, client_id: clientId, iss: clientId, aud, jti, iat: t, nbf: t, exp: t + 300 }, pkcs8), "request object");
}
export function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}
export const decode = (jwt) => ({ header: JSON.parse(Buffer.from(jwt.split(".")[0], "base64url")), claims: JSON.parse(Buffer.from(jwt.split(".")[1], "base64url")) });
export async function tokenForm(fields, headers = {}) {
  const r = await fixtureFetch(`${origin}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams(fields).toString() });
  const body = await r.json().catch(() => null);
  await capture(`oauth/token ${fields.grant_type} ${r.status}`, body);
  return { status: r.status, body };
}
export const authClient = (clientId, extra) => new AuthClient({ domain, clientId, customFetch: fixtureFetch, ...extra });

// The Action behind the token exchange profile. It logs the credentials it
// receives on purpose: the audit proves the Action log masks them.
export const exchangeAction = `exports.onExecuteCustomTokenExchange = async (event, api) => {
  const t = event.transaction;
  console.log('Plan35 exchange probe', t.subject_token, t.actor_token || 'no actor');
  const m = /^Plan35-valid\\.([a-z0-9-]+)\\.[A-Za-z0-9_-]+$/.exec(t.subject_token);
  if (!m) {
    api.access.rejectInvalidSubjectToken('Plan35 rejects this subject token');
    return;
  }
  api.authentication.setUserByConnection('${realm}', { user_id: m[1], email: m[1] + '@exchange.e2e.local', email_verified: true }, { creationBehavior: 'create_if_not_exists', updateBehavior: 'none' });
  if (t.actor_token) {
    const a = /^Plan35-actor\\.([a-z0-9-]+)\\.[A-Za-z0-9_-]+$/.exec(t.actor_token);
    if (a) api.authentication.setActor({ sub: a[1], act: { sub: 'plan35-gateway' } });
  }
};`;

export async function buildAndDeploy(name, trigger, code) {
  const a = await api("actions/actions", "POST", { name, supported_triggers: [{ id: trigger, version: "v1" }], runtime: "node22", code });
  await until(async () => {
    const v = await api(`actions/actions/${a.id}`);
    assert.notEqual(v.status, "failed", `Action ${name} build failed`);
    return v.status === "built";
  }, `Action ${name} built`, 60000);
  await api(`actions/actions/${a.id}/deploy`, "POST");
  return a;
}

async function setup() {
  const require = createRequire(import.meta.url);
  const modules = new URL("./node_modules/", import.meta.url).pathname;
  for (const [pkg, version] of [["auth0", "7.4.0"], ["@auth0/auth0-auth-js", "1.16.1"], ["express-oauth2-jwt-bearer", "1.11.0"], ["auth0-deploy-cli", "9.1.0"]])
    assert.equal(require(`${modules}${pkg}/package.json`).version, version, `${pkg} pin`);
  for (const [v, k] of [
    [password, "password"],
    [operatorPassword, "password"],
    [admin.secret, "client secret"],
    [bridgeSecret, "client secret"],
    ["Plan35-Backend-Secret-Before-Keys-2026", "client secret"],
    ["Plan35-Web-Secret-Before-Keys-2026", "client secret"],
  ])
    await secret(v, k);
  const keys = {};
  for (const name of ["backendA", "backendB", "backendC", "webAuth", "webJar", "consoleKey", "deploy1", "deploy2"]) {
    keys[name] = rsaKey();
    await secret(keys[name].pkcs8, "private key");
  }
  const m = await management();
  await m.resourceServers.create({ name: "Plan35 API", identifier: API, scopes: [{ value: "read:things", description: "Read things" }], allow_offline_access: true, skip_consent_for_verifiable_first_party_clients: true, signing_alg: "RS256" });
  const hs = await m.resourceServers.create({ name: "Plan35 HS256", identifier: HS_API, scopes: [{ value: "read:things", description: "Read things" }], skip_consent_for_verifiable_first_party_clients: true, signing_alg: "HS256" });
  assert.equal(hs.signing_alg, "HS256");
  assert.ok(typeof hs.signing_secret === "string" && hs.signing_secret.length >= 32, "HS256 API has a generated secret");
  await secret(hs.signing_secret, "signing secret");
  const ps = await m.resourceServers.create({ name: "Plan35 PS256", identifier: PS_API, scopes: [{ value: "read:things", description: "Read things" }], skip_consent_for_verifiable_first_party_clients: true, signing_alg: "PS256" });
  assert.equal(ps.signing_alg, "PS256");
  for (const audience of [API, HS_API, PS_API]) await m.clientGrants.create({ client_id: "m35-backend", audience, scope: ["read:things"] });

  // private_key_jwt for the backend (key A, RS256, generated kid).
  const a = await m.clients.credentials.create("m35-backend", { credential_type: "public_key", name: "backend-a", pem: keys.backendA.spki, alg: "RS256" });
  assert.equal(a.pem, undefined, "the PEM is never returned");
  assert.match(a.id, /^cred_[0-9A-Za-z]{22}$/);
  await m.clients.update("m35-backend", { client_authentication_methods: { private_key_jwt: { credentials: [{ id: a.id }] } }, token_endpoint_auth_method: null });
  // The web application: private_key_jwt (PS256) and required signed requests.
  const webAuth = await m.clients.credentials.create("m35-web", { credential_type: "public_key", name: "web-auth", pem: keys.webAuth.spki, alg: "PS256", kid: "plan35-web-auth-key" });
  const webJar = await m.clients.credentials.create("m35-web", { credential_type: "public_key", name: "web-jar", pem: keys.webJar.spki, alg: "RS256" });
  await m.clients.update("m35-web", {
    client_authentication_methods: { private_key_jwt: { credentials: [{ id: webAuth.id }] } },
    signed_request_object: { required: true, credentials: [{ id: webJar.id }] },
    token_endpoint_auth_method: null,
  });
  const web = await m.clients.get("m35-web");
  assert.equal(web.signed_request_object?.required, true);
  assert.equal(web.token_endpoint_auth_method ?? null, null);
  await m.clients.update("m35-bridge", { token_exchange: { allow_any_profile_of_type: ["custom_authentication"] } });
  await m.users.create({ connection: realm, email: "jar35@e2e.local", password, email_verified: true });
  const action = await buildAndDeploy("Plan35 legacy exchange", "custom-token-exchange", exchangeAction);
  const profile = await m.tokenExchangeProfiles.create({ name: "Plan35 legacy tokens", subject_token_type: SUBJECT_TYPE, action_id: action.id, type: "custom_authentication" });
  await capture("profile create", profile);
  await api("log-streams", "POST", { name: "Plan35 privacy", type: "http", sink: { httpEndpoint: "https://127.0.0.1:9186/logs", httpContentType: "application/json", httpContentFormat: "JSONLINES" } });
  await saveState({ keys, credentials: { backendA: a.id, webAuth: webAuth.id, webJar: webJar.id }, action: { id: action.id, name: action.name }, profile: profile.id });
  console.log("Plan35 setup complete");
}

// The pinned strict verifier, express-oauth2-jwt-bearer, behind a local
// express app. Its HTTPS agent dials the server directly with the tenant's
// host name, so discovery and the JWKS are the live ones.
class LocalAgent extends https.Agent {
  createConnection(options, callback) {
    return tls.connect({ ...options, host: "127.0.0.1", port: 9543, servername: domain }, callback);
  }
}
export async function verifier(hsSecret) {
  const agent = new LocalAgent();
  const app = express();
  const ok = (req, res) => res.json({ sub: req.auth.payload.sub, alg: req.auth.header.alg, act: req.auth.payload.act ?? null });
  app.get("/rs", jwtBearer({ issuerBaseURL: issuer, audience: API, agent }), ok);
  app.get("/id", jwtBearer({ issuerBaseURL: issuer, audience: "m35-bridge", agent }), ok);
  app.get("/ps", jwtBearer({ issuer, jwksUri: `${origin}/.well-known/jwks.json`, audience: PS_API, tokenSigningAlg: "PS256", agent }), ok);
  app.get("/ps-discovery", jwtBearer({ issuerBaseURL: issuer, audience: PS_API, agent }), ok);
  app.get("/hs", jwtBearer({ issuer, audience: HS_API, secret: hsSecret, tokenSigningAlg: "HS256" }), ok);
  app.get("/hs-wrong", jwtBearer({ issuer, audience: HS_API, secret: "Plan35-not-the-signing-secret-0000000000", tokenSigningAlg: "HS256" }), ok);
  app.use((err, _req, res, _next) => res.status(err.status ?? 500).json({ error: err.code ?? "error", message: err.message }));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    async check(path, jwt) {
      const r = await fetch(`${base}${path}`, { headers: { authorization: `Bearer ${jwt}` } });
      const body = await r.json();
      await capture(`verifier ${path} ${r.status}`, body);
      return { status: r.status, body };
    },
    close: () => new Promise((r) => server.close(r)),
  };
}

async function sdk() {
  const st = await state();
  const m = await management();
  const backend = (key, alg) => authClient("m35-backend", { clientAssertionSigningKey: key, clientAssertionSigningAlg: alg });
  // auth-js sends no kid: the server tries every key of the right algorithm.
  const a = await backend(st.keys.backendA.pkcs8, "RS256").getTokenByClientCredentials({ audience: API });
  let d = decode(a.accessToken);
  assert.equal(d.header.alg, "RS256");
  assert.equal(d.claims.aud, API);
  assert.equal(d.claims.azp, "m35-backend");
  assert.equal(d.claims.gty, "client-credentials");

  // A jti is single-use, also after a success.
  const once = await assertion("m35-backend", st.keys.backendA.pkcs8);
  const base = { grant_type: "client_credentials", client_id: "m35-backend", audience: API, client_assertion_type: ASSERTION_TYPE };
  let r = await tokenForm({ ...base, client_assertion: once });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  r = await tokenForm({ ...base, client_assertion: once });
  assert.equal(r.status, 401, "replayed assertion refused");
  assert.equal(r.body.error, "invalid_client");
  // The exact endpoint URL is also an accepted audience (LR35-3).
  r = await tokenForm({ ...base, client_assertion: await assertion("m35-backend", st.keys.backendA.pkcs8, { aud: `${origin}/oauth/token` }) });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  // An assertion plus a secret is two methods: invalid_request.
  r = await tokenForm({ ...base, client_secret: "Plan35-Backend-Secret-Before-Keys-2026", client_assertion: await assertion("m35-backend", st.keys.backendA.pkcs8) });
  assert.equal(r.status, 400);
  assert.equal(r.body.error, "invalid_request");
  // The secret alone no longer authenticates the client.
  r = await tokenForm({ grant_type: "client_credentials", client_id: "m35-backend", client_secret: "Plan35-Backend-Secret-Before-Keys-2026", audience: API });
  assert.equal(r.status, 401, JSON.stringify(r.body));
  // A lifetime over five minutes is refused.
  r = await tokenForm({ ...base, client_assertion: await assertion("m35-backend", st.keys.backendA.pkcs8, { lifetime: 600 }) });
  assert.equal(r.status, 401);

  // Two-key rotation without kid: add B (PS256), use both, remove A.
  const b = await m.clients.credentials.create("m35-backend", { credential_type: "public_key", name: "backend-b", pem: st.keys.backendB.spki, alg: "PS256" });
  await capture("credential create B", b);
  assert.equal(b.pem, undefined);
  assert.equal(b.alg, "PS256");
  await m.clients.update("m35-backend", { client_authentication_methods: { private_key_jwt: { credentials: [{ id: st.credentials.backendA }, { id: b.id }] } } });
  for (const [key, alg] of [[st.keys.backendA.pkcs8, "RS256"], [st.keys.backendB.pkcs8, "PS256"]]) {
    const t = await backend(key, alg).getTokenByClientCredentials({ audience: API });
    assert.equal(decode(t.accessToken).claims.azp, "m35-backend");
  }
  const third = await raw("clients/m35-backend/credentials", "POST", { credential_type: "public_key", name: "backend-c", pem: st.keys.backendC.spki });
  assert.equal(third.status, 400, "a third credential is refused (C2)");
  const list = await m.clients.credentials.list("m35-backend");
  await capture("credential list", list);
  assert.deepEqual(list.map((c) => c.name).sort(), ["backend-a", "backend-b"]);
  assert.ok(list.every((c) => c.pem === undefined), "list never returns a PEM");
  const expires = new Date(Date.now() + 30 * 86400000).toISOString().replace(/\.\d+Z$/, ".000Z");
  const patched = await m.clients.credentials.update("m35-backend", b.id, { expires_at: expires });
  assert.equal(new Date(patched.expires_at).toISOString(), expires);
  assert.equal((await m.clients.credentials.get("m35-backend", b.id)).name, "backend-b");
  await m.clients.credentials.delete("m35-backend", st.credentials.backendA);
  await assert.rejects(backend(st.keys.backendA.pkcs8, "RS256").getTokenByClientCredentials({ audience: API }), "removed key A no longer authenticates");
  const client = await m.clients.get("m35-backend");
  assert.deepEqual(client.client_authentication_methods.private_key_jwt.credentials.map((c) => c.id), [b.id], "deleting A detached it (C3)");
  const withB = backend(st.keys.backendB.pkcs8, "PS256");

  // RS256, PS256 and HS256 access tokens against the strict verifier.
  const rs = await withB.getTokenByClientCredentials({ audience: API });
  const ps = await withB.getTokenByClientCredentials({ audience: PS_API });
  const hs = await withB.getTokenByClientCredentials({ audience: HS_API });
  assert.equal(decode(rs.accessToken).header.alg, "RS256");
  assert.equal(decode(ps.accessToken).header.alg, "PS256");
  assert.equal(decode(hs.accessToken).header.alg, "HS256");
  const jwks = await (await fixtureFetch(`${origin}/.well-known/jwks.json`)).json();
  await capture("jwks", jwks);
  assert.ok(jwks.keys.length > 0 && jwks.keys.every((k) => k.alg === undefined && k.use === "sig" && k.kty === "RSA"), "JWKS keys carry no alg (C19)");
  assert.ok(jwks.keys.some((k) => k.kid === decode(ps.accessToken).header.kid), "PS256 token kid is published");
  const hsSecret = (await api(`resource-servers/${encodeURIComponent(HS_API)}`)).signing_secret;
  assert.equal(typeof hsSecret, "string", "the HS256 secret is returned on read (C16)");
  await secret(hsSecret, "signing secret");
  const v = await verifier(hsSecret);
  try {
    let out = await v.check("/rs", rs.accessToken);
    assert.equal(out.status, 200, JSON.stringify(out.body));
    assert.equal(out.body.alg, "RS256");
    out = await v.check("/ps", ps.accessToken);
    assert.equal(out.status, 200, `PS256 against the live JWKS: ${JSON.stringify(out.body)}`);
    assert.equal(out.body.alg, "PS256");
    out = await v.check("/hs", hs.accessToken);
    assert.equal(out.status, 200, JSON.stringify(out.body));
    assert.equal(out.body.alg, "HS256");
    for (const [path, jwt] of [["/hs-wrong", hs.accessToken], ["/ps", hs.accessToken], ["/hs", ps.accessToken], ["/ps", ps.accessToken.slice(0, -4) + (ps.accessToken.endsWith("AAAA") ? "BBBB" : "AAAA")]]) {
      out = await v.check(path, jwt);
      assert.equal(out.status, 401, `${path} must refuse: ${JSON.stringify(out.body)}`);
    }
    // Observation, not an assertion: with discovery only, the verifier also
    // limits algorithms to id_token_signing_alg_values_supported (RS256).
    out = await v.check("/ps-discovery", ps.accessToken);
    await saveState({ psDiscoveryObservation: out });
  } finally {
    await v.close();
  }

  // node-auth0 token exchange profiles manager.
  const page = await m.tokenExchangeProfiles.list({ take: 50 });
  const profiles = page.data;
  await capture("profiles list", profiles);
  assert.ok(profiles.some((p) => p.id === st.profile && p.action_id === st.action.id));
  const second = await m.tokenExchangeProfiles.create({ name: "Plan35 second", subject_token_type: "https://plan35.e2e.test/second-token", action_id: st.action.id, type: "custom_authentication" });
  await m.tokenExchangeProfiles.update(second.id, { name: "Plan35 second renamed" });
  assert.equal((await m.tokenExchangeProfiles.get(second.id)).name, "Plan35 second renamed");
  for (const [type, status] of [["urn:ietf:params:plan35", 400], ["https://auth0.com/plan35", 400], [SUBJECT_TYPE, 409]]) {
    const res = await raw("token-exchange-profiles", "POST", { name: "Plan35 refused", subject_token_type: type, action_id: st.action.id, type: "custom_authentication" });
    assert.equal(res.status, status, `${type}: ${JSON.stringify(res.body)}`);
  }
  await m.tokenExchangeProfiles.delete(second.id);
  assert.equal((await raw(`token-exchange-profiles/${second.id}`)).status, 404);
  console.log("Plan35 sdk: auth-js private_key_jwt (replay, rotation without kid), node-auth0 credentials/profiles, express-oauth2-jwt-bearer RS256/PS256/HS256 passed");
}

async function exchange() {
  const st = await state();
  const m = await management();
  const bridge = authClient("m35-bridge", { clientSecret: bridgeSecret });
  const subject = (uid) => secret(`Plan35-valid.${uid}.${randomBytes(18).toString("base64url")}`, "subject token");
  const scope = "openid offline_access read:things";
  // Create, then reuse, the user selected with setUserByConnection.
  const first = await bridge.exchangeToken({ subjectTokenType: SUBJECT_TYPE, subjectToken: await subject("legacy-35"), audience: API, scope });
  await capture("exchange 1", first);
  assert.ok(first.accessToken && first.idToken && first.refreshToken, "exchange issues access, ID and refresh tokens");
  const c1 = decode(first.accessToken).claims;
  assert.equal(c1.aud.includes?.(API) || c1.aud === API, true);
  assert.equal(c1.gty, undefined, "no gty on an exchange token");
  const users = async () => (await api(`users-by-email?email=${encodeURIComponent("legacy-35@exchange.e2e.local")}`));
  let found = await users();
  assert.equal(found.length, 1, "the exchange created the user");
  assert.equal(found[0].user_id, c1.sub);
  const second = await bridge.exchangeToken({ subjectTokenType: SUBJECT_TYPE, subjectToken: await subject("legacy-35"), audience: API, scope });
  assert.equal(decode(second.accessToken).claims.sub, c1.sub, "the second exchange reuses the user");
  found = await users();
  assert.equal(found.length, 1, "no second user");
  const refreshed = await bridge.getTokenByRefreshToken({ refreshToken: second.refreshToken });
  assert.equal(decode(refreshed.accessToken).claims.sub, c1.sub);
  // An actor chain gives act and no refresh token.
  const actor = await secret(`Plan35-actor.svc-35.${randomBytes(18).toString("base64url")}`, "actor token");
  const acted = await bridge.exchangeToken({ subjectTokenType: SUBJECT_TYPE, subjectToken: await subject("legacy-35"), actorToken: actor, actorTokenType: ACTOR_TYPE, audience: API, scope });
  await capture("exchange with actor", acted);
  assert.deepEqual(decode(acted.accessToken).claims.act, { sub: "svc-35", act: { sub: "plan35-gateway" } });
  assert.equal(acted.refreshToken, undefined, "no refresh token when setActor was used");
  // The exchange's RS256 ID token against the strict verifier.
  const v = await verifier("unused-hs256-secret-plan35");
  try {
    const out = await v.check("/id", first.idToken);
    assert.equal(out.status, 200, JSON.stringify(out.body));
    assert.equal(out.body.sub, c1.sub);
    assert.equal((await v.check("/rs", acted.accessToken)).body.act?.sub, "svc-35");
  } finally {
    await v.close();
  }
  // Refusals.
  const form = async (fields, headers) => tokenForm({ grant_type: EXCHANGE, client_id: "m35-bridge", client_secret: bridgeSecret, audience: API, scope: "openid", ...fields }, headers);
  let r = await form({ subject_token_type: "urn:plan35:unknown", subject_token: await subject("legacy-35") });
  assert.equal(r.status, 400);
  assert.equal(r.body.error, "invalid_request");
  r = await form({ subject_token_type: SUBJECT_TYPE, subject_token: await secret(`Plan35-bogus-${randomBytes(12).toString("base64url")}`, "subject token") });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.equal(r.body.error, "invalid_request");
  r = await tokenForm({ grant_type: EXCHANGE, client_id: "m35-web", client_assertion_type: ASSERTION_TYPE, client_assertion: await assertion("m35-web", st.keys.webAuth.pkcs8, { alg: "PS256" }), subject_token_type: SUBJECT_TYPE, subject_token: await subject("legacy-35") });
  assert.equal(r.status, 403, `a client without token_exchange: ${JSON.stringify(r.body)}`);
  assert.equal(r.body.error, "unauthorized_client");

  // Throttle lockout on its own end-user address (auth0-forwarded-for from
  // this confidential client): two rejected
  // subject tokens spend the budget, the third request is 429 even with a
  // valid token, and the Action does not run.
  await m.attackProtection.suspiciousIpThrottling.update({ enabled: true, shields: ["block"], stage: { "pre-custom-token-exchange": { max_attempts: 2, rate: 600000 } } });
  const xff = { "auth0-forwarded-for": "203.0.113.35" };
  for (let i = 0; i < 2; i++) {
    r = await form({ subject_token_type: SUBJECT_TYPE, subject_token: await secret(`Plan35-bogus-${randomBytes(12).toString("base64url")}`, "subject token") }, xff);
    assert.equal(r.status, 400, `rejected attempt ${i + 1}: ${JSON.stringify(r.body)}`);
  }
  r = await form({ subject_token_type: SUBJECT_TYPE, subject_token: await subject("legacy-35") }, xff);
  assert.equal(r.status, 429, JSON.stringify(r.body));
  assert.equal(r.body.error, "too_many_attempts");
  const other = await bridge.exchangeToken({ subjectTokenType: SUBJECT_TYPE, subjectToken: await subject("legacy-35"), audience: API, scope: "openid" });
  assert.ok(other.accessToken, "another address is not blocked");
  // Logs: secte with the actor, fecte, and the throttle record.
  const types = await until(async () => {
    const rows = await api("logs?per_page=100&page=0&sort=date:-1");
    const t = new Set(rows.map((x) => x.type));
    return t.has("secte") && t.has("fecte") && t.has("limit_mu") ? rows : null;
  }, "secte, fecte and limit_mu logs");
  assert.ok(types.some((x) => x.type === "secte" && JSON.stringify(x).includes("svc-35")), "secte records the actor");
  console.log("Plan35 exchange: auth-js exchangeToken create/reuse, actor chain without refresh token, refusals, 429 lockout, logs passed");
}

async function snapshot() {
  const out = [];
  for (let page = 0; ; page++) {
    const rows = await api(`logs?per_page=100&page=${page}&sort=date:1`);
    out.push(...rows);
    if (rows.length < 100) break;
  }
  await writeFile(`${work}/logs-export.jsonl`, out.map((x) => JSON.stringify(x)).join("\n") + "\n", { mode: 0o600 });
  await until(async () => {
    const rows = (await readFile(`${work}/receiver.jsonl`, "utf8")).trim().split("\n").filter(Boolean).map(JSON.parse);
    return rows.some((r) => r.path === "/logs" && r.body.includes("secte"));
  }, "the log stream delivered the exchange logs", 60000);
}

function variants(value) {
  const out = [value, encodeURIComponent(value), Buffer.from(value).toString("base64"), Buffer.from(value).toString("base64url")];
  if (/^[A-Za-z0-9_-]+$/.test(value) && value.length >= 16) {
    const raw = Buffer.from(value, "base64url");
    out.push(raw.toString("base64"), raw.toString("hex"));
  }
  // A JWT's signature part alone is as identifying as the whole value.
  if (/^[\w-]+\.[\w-]+\.[\w-]{20,}$/.test(value)) out.push(value.split(".")[2]);
  return out;
}
export function scan(text, secrets, label) {
  for (const { value, kind } of secrets) assert.ok(!variants(value).some((v) => text.includes(v)), `${label}: leaked ${kind}`);
}

async function audit() {
  const secrets = (await readFile(`${work}/private-secrets.jsonl`, "utf8")).trim().split("\n").map(JSON.parse);
  const lanes = ` ${process.env.E2E_M35_LANES ?? "browser sdk exchange deploy cli audit"} `;
  const required = ["management token", "password", "client secret", "signing secret"];
  if (lanes.includes(" sdk ") || lanes.includes(" exchange ")) required.push("client assertion");
  if (lanes.includes(" exchange ")) required.push("subject token", "actor token");
  if (lanes.includes(" browser ") && process.env.E2E_M35_BACKEND === "sqlite") required.push("request object");
  for (const kind of required) assert.ok(secrets.some((s) => s.kind === kind), `actual ${kind} positive control`);
  const names = ["responses.jsonl", "browser-console.jsonl", "browser-responses.jsonl", "cli.jsonl", "receiver.jsonl", "logs-export.jsonl", "server.log", "proxy.log", "receiver.log", "migrate.log", "bootstrap.stderr", "stored-sinks.jsonl"];
  let bytes = 0;
  for (const name of names) {
    const text = await readFile(`${work}/${name}`, "utf8");
    scan(text, secrets, name);
    bytes += text.length;
  }
  if (lanes.includes(" exchange ")) {
    const logs = await readFile(`${work}/logs-export.jsonl`, "utf8");
    for (const type of ['"secte"', '"fecte"']) assert.ok(logs.includes(type), `log export holds ${type}`);
    assert.ok((await readFile(`${work}/receiver.jsonl`, "utf8")).includes("secte"), "log stream delivered secte");
    if (process.env.E2E_M35_BACKEND === "sqlite") {
      const stored = await readFile(`${work}/stored-sinks.jsonl`, "utf8");
      assert.ok(stored.includes("Plan35 exchange probe"), "the Action log (which printed the subject and actor tokens) was scanned");
      assert.ok(stored.includes('"table": "tenant_logs"'), "tenant_logs dump populated");
    }
  }
  const kinds = [...new Set(secrets.map((s) => s.kind))].sort();
  await writeFile(`${work}/privacy-audit.json`, JSON.stringify({ passed: true, names, bytes, representativeSecrets: secrets.length, kinds, exemptions: "Our own captures replace the documented returned fields client_secret and signing_secret; server sinks are scanned unmodified." }));
  console.log(`Plan35 privacy: ${names.length} sinks (${bytes} bytes), ${secrets.length} representative secrets of ${kinds.length} kinds absent`);
}

if (process.argv[1] === import.meta.filename)
  await ({ setup, sdk, exchange, snapshot, audit }[process.argv[2]] ?? (() => { throw Error("unknown mode"); }))();
