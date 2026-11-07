// Plan 33b: shared fixtures (real local HTTP through the CONNECT proxy, the
// custom-domain proxy keys, an independent software authenticator) and the
// node lanes: setup, sdk (journeys 8 and 10 with pinned node-auth0 7.4.0 and
// @auth0/auth0-auth-js 1.16.1), deploy (pinned Deploy CLI 9.1.0 round trip),
// snapshot and the representative-secret audit (journey 11).
import assert from "node:assert/strict";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createRequire } from "node:module";
import { ProxyAgent } from "undici";
import { ManagementClient } from "auth0";
import { AuthClient } from "@auth0/auth0-auth-js";

export const work = process.env.E2E_M33B_WORK;
export const origin = "https://sdk.e2e.test";
export const realm = "Username-Password-Authentication";
export const password = "Plan33b-User-Password-2026",
  operatorPassword = "Plan33b-Operator-Password-2026";
export const admin = { client: "m33b-admin", secret: "Plan33b-Management-Secret-2026" };
export const nativeSecret = "Plan33b-Native-Client-Secret-2026";
export const receiverBearer = "Plan33b-Receiver-Bearer-2026";
// Two Plan 23 style self-managed custom domains. The first uses the shared
// parent as its RP ID from the start; the second keeps its own host (§15 j5).
export const domains = { primary: "login.domains.e2e.test", alt: "alt.domains.e2e.test" };
export const sharedRP = "domains.e2e.test";
export const appOrigin = "https://app.domains.e2e.test";
export const mobile = {
  ios: { team_id: "ABCDE12345", app_bundle_identifier: "com.example.passkeys" },
  android: {
    app_package_name: "com.example.passkeys",
    sha256_cert_fingerprints: ["AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"],
  },
};

const dispatchers = {
  main: new ProxyAgent("http://127.0.0.1:9198"),
  legacy: new ProxyAgent("http://127.0.0.1:9199"),
};
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
// Proxy keys: a custom domain is admitted only with its own cname-api-key
// from a trusted peer (Plan 23). The fixture adds it as an edge proxy would.
export async function proxyHeaders(host) {
  const key = (await state()).proxyKeys?.[host];
  // custom_client_ip_header defaults to x-forwarded-for (one address).
  return key ? { "cname-api-key": key, "x-forwarded-for": "127.0.0.1" } : {};
}
export async function fixtureFetch(input, opts = {}) {
  const url = new URL(input instanceof Request ? input.url : String(input));
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  for (const [k, v] of new Headers(opts.headers ?? {})) headers.set(k, v);
  for (const [k, v] of Object.entries(await proxyHeaders(url.hostname))) headers.set(k, v);
  const dispatcher = url.hostname === "legacy.e2e.test" ? dispatchers.legacy : dispatchers.main;
  if (input instanceof Request) {
    const body = ["GET", "HEAD"].includes(input.method) ? undefined : await input.arrayBuffer();
    return fetch(url, { method: input.method, body, ...opts, headers, dispatcher });
  }
  return fetch(url, { ...opts, headers, dispatcher });
}

// Representative secrets: every value is appended mode 0600 and must be absent
// from every captured sink (journey 11).
export async function secret(value, kind) {
  assert.equal(typeof value, "string", `${kind} is not a string`);
  assert.ok(value.length >= 6, `${kind} too short to scan`);
  await appendFile(`${work}/private-secrets.jsonl`, JSON.stringify({ kind, value }) + "\n", { mode: 0o600 });
  return value;
}
// A WebAuthn credential as the browser serialized it: each binary member and
// the challenge inside client data is a representative secret.
export async function credentialSecrets(credential, source) {
  const r = credential?.response ?? {};
  for (const [field, kind] of [
    ["clientDataJSON", "clientDataJSON"],
    ["attestationObject", "attestationObject"],
    ["authenticatorData", "authenticatorData"],
    ["signature", "signature"],
    ["userHandle", "userHandle"],
  ])
    if (typeof r[field] === "string" && r[field].length >= 6) await secret(r[field], kind);
  if (typeof r.clientDataJSON === "string") {
    const data = JSON.parse(Buffer.from(r.clientDataJSON, "base64url").toString());
    await secret(data.challenge, "challenge");
  }
  await appendFile(`${work}/credential-sources.jsonl`, JSON.stringify({ source, id: credential.id }) + "\n", { mode: 0o600 });
}
export async function optionsSecrets(publicKey) {
  if (publicKey?.challenge) await secret(publicKey.challenge, "challenge");
  if (publicKey?.user?.id) await secret(publicKey.user.id, "userHandle");
}
function variants(value) {
  const out = [value, encodeURIComponent(value), Buffer.from(value).toString("base64"), Buffer.from(value).toString("base64url")];
  if (/^[A-Za-z0-9_-]+$/.test(value) && value.length >= 16) {
    const raw = Buffer.from(value, "base64url");
    out.push(raw.toString("base64"), raw.toString("base64").replace(/=+$/, ""), raw.toString("hex"));
  }
  return out;
}
export function scan(text, secrets, label) {
  for (const { value, kind } of secrets) {
    const numeric = /^\d+$/.test(value);
    const leaked = (v) => (numeric && v === value ? new RegExp(`(?<!\\d)${v}(?!\\d)`).test(text) : text.includes(v));
    assert.ok(!variants(value).some(leaked), `${label}: leaked ${kind}`);
  }
}
// Documented Management fields that are public: credential IDs and public keys
// appear where the API documents them; they are not representative secrets.
export async function capture(name, value) {
  await appendFile(`${work}/responses.jsonl`, JSON.stringify({ name, value }) + "\n");
  return value;
}
export async function until(fn, label, timeout = 30000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 150));
  }
  throw Error(`timed out: ${label}`);
}

const bearers = {};
export async function token(host = "sdk.e2e.test") {
  if (bearers[host]) return bearers[host];
  const r = await fixtureFetch(`https://${host}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "client_credentials", client_id: admin.client, client_secret: admin.secret, audience: `https://${host}/api/v2/` }),
  });
  const b = await r.json();
  assert.equal(r.status, 200, JSON.stringify(b));
  bearers[host] = await secret(b.access_token, "management token");
  return bearers[host];
}
// raw Management call: returns {status, body}; never asserts.
export async function mgmt(path, method = "GET", body, host = "sdk.e2e.test") {
  const r = await fixtureFetch(`https://${host}/api/v2/${path}`, {
    method,
    headers: { authorization: `Bearer ${await token(host)}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await r.text();
  let value = null;
  try {
    value = text ? JSON.parse(text) : null;
  } catch {
    value = text;
  }
  await capture(`${host} ${method} ${path}`, { status: r.status, value });
  return { status: r.status, body: value };
}
export async function api(path, method = "GET", body, host = "sdk.e2e.test") {
  const r = await mgmt(path, method, body, host);
  assert.ok(r.status < 300, `${method} ${path}: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body;
}
export const management = async (host = "sdk.e2e.test") =>
  new ManagementClient({ domain: host, token: await token(host), maxRetries: 0, fetch: fixtureFetch });
export const connectionId = async (host = "sdk.e2e.test") =>
  (await api(`connections?name=${encodeURIComponent(realm)}`, "GET", undefined, host))[0].id;
// Idempotent Management configuration of the journey 1 prerequisites, for lanes
// that run without the console journey (memory backend, partial lanes).
export async function ensurePasskeys(host = "sdk.e2e.test", ui = "button") {
  await api("prompts", "PATCH", { universal_login_experience: "new", identifier_first: true }, host);
  const id = await connectionId(host);
  const c = await api(`connections/${id}`, "GET", undefined, host);
  const options = c.options ?? {};
  await api(`connections/${id}`, "PATCH", {
    options: {
      ...options,
      authentication_methods: { ...(options.authentication_methods ?? {}), password: { enabled: true }, passkey: { enabled: true } },
      passkey_options: { challenge_ui: ui, progressive_enrollment_enabled: true, local_enrollment_enabled: true },
    },
  }, host);
}
export async function logsOf(type, filter = () => true) {
  const rows = [];
  for (let page = 0; ; page++) {
    const batch = await api(`logs?per_page=100&page=${page}&sort=date:1`);
    rows.push(...batch);
    if (batch.length < 100) break;
  }
  return rows.filter((r) => r.type === type && filter(r));
}
export const waitLog = (type, filter, label) => until(async () => (await logsOf(type, filter))[0], label ?? `log ${type}`, 30000);

// Independent RFC 6238 (SHA-1, six digits, 30 s), no server module import.
export function totp(seed, step = Math.floor(Date.now() / 30000)) {
  let bits = "";
  for (const ch of seed.replace(/=+$/, "")) bits += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hash = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = hash.at(-1) & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}
export const newTOTPSeed = () => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(randomBytes(32), (b) => alphabet[b % 32]).join("");
};

// Minimal deterministic CBOR (RFC 8949 core) for COSE keys and none
// attestation; written for this fixture, no server code imported.
export function cbor(value) {
  const head = (major, n) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  if (typeof value === "string") {
    const b = Buffer.from(value);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])]);
}
// A software ES256 authenticator. Its credential is registered through the
// Management API (journey 10) and lets a test sign client data a browser
// would refuse to produce (a forged origin, journey 5).
export function softKey(rpId, { backup = false } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
  return { privateKey, cose, credId: randomBytes(32), userHandle: randomBytes(32), rpId, count: 0, backup };
}
export function softBody(k, extra = {}) {
  return {
    type: "passkey",
    name: "Software key",
    key_id: k.credId.toString("base64url"),
    public_key: k.cose.toString("base64url"),
    relying_party_identifier: k.rpId,
    user_handle: k.userHandle.toString("base64url"),
    credential_device_type: k.backup ? "multi_device" : "single_device",
    credential_backed_up: k.backup,
    ...extra,
  };
}
export function softAssert(k, { challenge, origin: o, type = "webauthn.get", count = ++k.count }) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge, origin: o, crossOrigin: false }));
  const flags = 0x01 | 0x04 | (k.backup ? 0x18 : 0);
  const count4 = Buffer.alloc(4);
  count4.writeUInt32BE(count);
  const authData = Buffer.concat([createHash("sha256").update(k.rpId).digest(), Buffer.from([flags]), count4]);
  const signature = sign("sha256", Buffer.concat([authData, createHash("sha256").update(clientDataJSON).digest()]), k.privateKey);
  const id = k.credId.toString("base64url");
  return {
    id, rawId: id, type: "public-key", authenticatorAttachment: "platform",
    response: {
      clientDataJSON: clientDataJSON.toString("base64url"),
      authenticatorData: authData.toString("base64url"),
      signature: signature.toString("base64url"),
      userHandle: k.userHandle.toString("base64url"),
    },
    clientExtensionResults: {},
  };
}

async function setup() {
  assert.equal(JSON.parse(await readFile(new URL("../../package.json", import.meta.resolve("auth0")))).version, "7.4.0");
  for (const [v, k] of [[password, "password"], [operatorPassword, "operator password"], [admin.secret, "client secret"], [nativeSecret, "client secret"], [receiverBearer, "receiver secret"]]) await secret(v, k);
  const m = await management();
  await api("prompts", "PATCH", { universal_login_experience: "new", identifier_first: false });
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.factors.set("recovery-code", { enabled: true });
  await m.guardian.policies.set([]);
  await api("event-streams", "POST", {
    name: "Plan33b privacy",
    subscriptions: [{ event_type: "user.created" }, { event_type: "user.updated" }, { event_type: "user.deleted" }],
    destination: { type: "webhook", configuration: { webhook_endpoint: "https://127.0.0.1:9186/events", webhook_authorization: { method: "bearer", token: receiverBearer } } },
  });
  await api("log-streams", "POST", {
    name: "Plan33b privacy",
    type: "http",
    sink: { httpEndpoint: "https://127.0.0.1:9186/logs", httpContentType: "application/json", httpContentFormat: "JSONLINES" },
  });
  // Custom domains through the production Management API and DNS proof.
  const proxyKeys = {}, ids = {};
  for (const [name, rp] of [[domains.primary, sharedRP], [domains.alt, undefined]]) {
    const d = await api("custom-domains", "POST", { domain: name, type: "self_managed_certs", ...(rp ? { relying_party_identifier: rp } : {}) });
    const txt = d.verification.methods.find((x) => x.name === "txt");
    const proof = await fetch("http://127.0.0.1:8064/proof", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: txt.domain, value: txt.record }) });
    assert.equal(proof.status, 204);
    const r = await fixtureFetch(`${origin}/api/v2/custom-domains/${d.custom_domain_id}/verify`, { method: "POST", headers: { authorization: `Bearer ${await token()}`, "content-type": "application/json" }, body: "{}" });
    const v = await r.json();
    assert.equal(r.status, 200, JSON.stringify(v));
    assert.equal(v.status, "ready");
    proxyKeys[name] = await secret(v.cname_api_key, "cname_api_key");
    ids[name] = d.custom_domain_id;
    await capture(`verify ${name}`, { ...v, cname_api_key: "<one-time-display>" });
  }
  await saveState({ proxyKeys, domainIDs: ids });
  for (const name of Object.values(domains)) {
    const r = await fixtureFetch(`https://${name}/.well-known/openid-configuration`);
    const text = await r.text();
    assert.equal(r.status, 200, `${name} is not served: ${text}`);
    assert.equal(JSON.parse(text).issuer, `https://${name}/`);
  }
  // Native client mobile settings (journey 9 .well-known files).
  const native = await api("clients/m33b-native");
  await api("clients/m33b-native", "PATCH", { mobile, grant_types: native.grant_types });
  // The second tenant offers passkeys, so its login page issues real
  // challenges for the cross-tenant replay (journey 5).
  await ensurePasskeys("other.e2e.test");
  await api("users", "POST", { connection: realm, email: "other-user@e2e.local", password, email_verified: true }, "other.e2e.test");
  console.log("Plan33b setup: custom domains verified, sinks, Guardian and second tenant ready");
}

async function sdk() {
  await ensurePasskeys();
  const m = await management();
  // Journey 10: Management API passkeys with pinned node-auth0 7.4.0, raw HTTP
  // where its 7.4.0 types lack passkey.
  const u = await m.users.create({ connection: realm, email: "sdk-passkeys@e2e.local", password, email_verified: true });
  const id = u.user_id;
  const key = softKey(sharedRP, { backup: true });
  const created = await api(`users/${encodeURIComponent(id)}/authentication-methods`, "POST", softBody(key, { name: "SDK passkey" }));
  assert.equal(created.type, "passkey");
  assert.equal(created.credential_device_type, "multi_device");
  await m.users.authenticationMethods.create(id, { type: "totp", totp_secret: newTOTPSeed() });
  let list = (await m.users.authenticationMethods.list(id)).data;
  await capture("SDK list", list);
  const passkey = list.find((x) => x.type === "passkey");
  assert.ok(passkey, "passkey listed");
  assert.equal(passkey.relying_party_identifier, sharedRP);
  assert.equal(passkey.key_id, key.credId.toString("base64url"));
  await m.users.authenticationMethods.update(id, passkey.id, { name: "Renamed SDK passkey" });
  assert.equal((await m.users.authenticationMethods.get(id, passkey.id)).name, "Renamed SDK passkey");
  // DELETE /users/{id}/authentication-methods keeps passkeys.
  await m.users.authenticationMethods.deleteAll(id);
  list = (await m.users.authenticationMethods.list(id)).data;
  assert.deepEqual(list.map((x) => x.type), ["passkey"]);
  await m.users.authenticationMethods.delete(id, passkey.id);
  assert.equal((await m.users.authenticationMethods.list(id)).data.length, 0);
  // Linking moves the secondary database identity's passkeys to the primary.
  const primary = await m.users.create({ connection: realm, email: "link-primary@e2e.local", password, email_verified: true });
  const secondary = await m.users.create({ connection: realm, email: "link-secondary@e2e.local", password, email_verified: true });
  const linkKey = softKey(sharedRP);
  await api(`users/${encodeURIComponent(secondary.user_id)}/authentication-methods`, "POST", softBody(linkKey, { name: "Linked passkey" }));
  await m.users.identities.link(primary.user_id, { provider: "auth0", user_id: secondary.user_id.split("|")[1] });
  const moved = (await m.users.authenticationMethods.list(primary.user_id)).data.filter((x) => x.type === "passkey");
  assert.equal(moved.length, 1, "linked passkey moved to the primary user");
  assert.equal(moved[0].key_id, linkKey.credId.toString("base64url"));
  // A 21st passkey is refused (20 per user, atomically).
  const full = await m.users.create({ connection: realm, email: "full-passkeys@e2e.local", password, email_verified: true });
  const handle = randomBytes(32);
  for (let i = 0; i < 20; i++) {
    const k = softKey(sharedRP);
    k.userHandle = handle;
    await api(`users/${encodeURIComponent(full.user_id)}/authentication-methods`, "POST", softBody(k, { name: `Key ${i + 1}` }));
  }
  const extra = softKey(sharedRP);
  extra.userHandle = handle;
  const refused = await mgmt(`users/${encodeURIComponent(full.user_id)}/authentication-methods`, "POST", softBody(extra));
  assert.equal(refused.status, 400, JSON.stringify(refused.body));
  assert.match(JSON.stringify(refused.body), /passkey enrollment limit reached/);

  // Journey 8: MFA API with pinned auth-js and raw HTTP. WebAuthn
  // authenticators are listed and deleted; associate/challenge are refused.
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.factors.set("webauthn-roaming", { enabled: true });
  await m.guardian.policies.set(["all-applications"]);
  const mfaUser = await m.users.create({ connection: realm, email: "mfa-api@e2e.local", password, email_verified: true });
  const seed = newTOTPSeed();
  await api(`users/${encodeURIComponent(mfaUser.user_id)}/authentication-methods`, "POST", { type: "totp", totp_secret: seed });
  const roaming = softKey(sharedRP);
  await api(`users/${encodeURIComponent(mfaUser.user_id)}/authentication-methods`, "POST", { type: "webauthn-roaming", name: "API key", key_id: roaming.credId.toString("base64url"), public_key: roaming.cose.toString("base64url"), relying_party_identifier: sharedRP });
  const r = await fixtureFetch(`${origin}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant_type: "password", client_id: "m33b-native", client_secret: nativeSecret, username: mfaUser.email, password, audience: `${origin}/mfa/`, scope: "openid read:authenticators remove:authenticators" }) });
  const pending = await r.json();
  assert.equal(r.status, 403, JSON.stringify(pending));
  assert.equal(pending.error, "mfa_required");
  const mfaToken = await secret(pending.mfa_token, "mfa_token");
  const auth = new AuthClient({ domain: "sdk.e2e.test", clientId: "m33b-native", clientSecret: nativeSecret, customFetch: fixtureFetch });
  const authenticators = await auth.mfa.listAuthenticators({ mfaToken });
  await capture("auth-js MFA list", authenticators);
  const webauthn = authenticators.find((a) => (a.authenticatorType ?? a.authenticator_type) === "webauthn-roaming");
  assert.ok(webauthn, `WebAuthn authenticator listed: ${JSON.stringify(authenticators)}`);
  // /mfa/challenge carries mfa_token in the body; /mfa/associate as a bearer.
  const call = async (path, body) => {
    const headers = { "content-type": "application/json", ...(path === "/mfa/associate" ? { authorization: `Bearer ${mfaToken}` } : {}) };
    const res = await fixtureFetch(`${origin}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  const challenge = await call("/mfa/challenge", { client_id: "m33b-native", client_secret: nativeSecret, mfa_token: mfaToken, challenge_type: "otp", authenticator_id: webauthn.id });
  assert.equal(challenge.status, 400, JSON.stringify(challenge.body));
  for (const type of ["webauthn-roaming", "webauthn-platform", "passkey"]) {
    const associate = await call("/mfa/associate", { client_id: "m33b-native", client_secret: nativeSecret, authenticator_types: [type] });
    assert.ok(associate.status >= 400 && associate.status < 500, `${type} associate: ${associate.status}`);
  }
  // Deletion needs an MFA API access token: finish the OTP step first.
  const otp = await fixtureFetch(`${origin}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant_type: "http://auth0.com/oauth/grant-type/mfa-otp", client_id: "m33b-native", client_secret: nativeSecret, mfa_token: mfaToken, otp: totp(seed) }) });
  const mfaAccess = await otp.json();
  assert.equal(otp.status, 200, JSON.stringify(mfaAccess));
  await secret(mfaAccess.access_token, "MFA API access token");
  await auth.mfa.deleteAuthenticator({ mfaToken: mfaAccess.access_token, authenticatorId: webauthn.id });
  const after = await auth.mfa.listAuthenticators({ mfaToken: mfaAccess.access_token });
  assert.ok(!after.some((a) => a.id === webauthn.id), "WebAuthn authenticator deleted through the MFA API");
  await m.guardian.policies.set([]);
  await m.guardian.factors.set("webauthn-roaming", { enabled: false });
  console.log("Plan33b node-auth0 passkeys (list/rename/delete/create/deleteAll/link/limit) and auth-js MFA API passed");
}

async function deploy() {
  // Journey 10: the pinned Deploy CLI handlers, unmodified, with the pinned
  // SDK's paged client against this server (clients mobile + grant,
  // database passkey options, custom domain RP ID, WebAuthn factors).
  const require = createRequire(import.meta.url);
  const modules = new URL("./node_modules/", import.meta.url).pathname;
  assert.equal(require(`${modules}auth0-deploy-cli/package.json`).version, "9.1.0");
  const { ManagementClient: CJSClient } = require(`${modules}auth0`);
  const tools = `${modules}auth0-deploy-cli/lib/tools/auth0`;
  const client = require(`${tools}/client`).default(new CJSClient({ domain: "sdk.e2e.test", token: await token(), maxRetries: 0, fetch: fixtureFetch }));
  const make = (name) => new (require(`${tools}/handlers/${name}`).default)({ client, config: () => false });
  const pick = (rows, k, v) => rows.find((row) => row[k] === v);
  const grant = "urn:okta:params:oauth:grant-type:webauthn";
  await make("clients").processChanges({ clients: [{ name: "Deploy Passkey Native", app_type: "native", token_endpoint_auth_method: "none", is_first_party: true, callbacks: ["com.example.passkeys://callback"], grant_types: ["authorization_code", "refresh_token", grant], mobile }] });
  let app = pick(await make("clients").getType(), "name", "Deploy Passkey Native");
  assert.deepEqual(app.mobile, mobile);
  assert.ok(app.grant_types.includes(grant));
  const changed = { ...mobile, ios: { ...mobile.ios, team_id: "FGHIJ67890" } };
  await make("clients").processChanges({ clients: [{ ...structuredClone(app), mobile: changed }] });
  app = pick(await make("clients").getType(), "name", "Deploy Passkey Native");
  assert.deepEqual(app.mobile, changed);
  const options = { authentication_methods: { password: { enabled: true }, passkey: { enabled: true } }, passkey_options: { challenge_ui: "button", progressive_enrollment_enabled: false, local_enrollment_enabled: true } };
  await make("databases").processChanges({ databases: [{ name: "Deploy-Passkey-Users", strategy: "auth0", options, enabled_clients: ["Deploy Passkey Native"] }] });
  let db = pick(await make("databases").getType(), "name", "Deploy-Passkey-Users");
  assert.deepEqual(db.options.passkey_options, options.passkey_options);
  assert.deepEqual(db.options.authentication_methods, options.authentication_methods);
  const changedOptions = { ...options.passkey_options, challenge_ui: "autofill", progressive_enrollment_enabled: true };
  await make("databases").processChanges({ databases: [{ ...structuredClone(db), options: { ...db.options, passkey_options: changedOptions } }] });
  db = pick(await make("databases").getType(), "name", "Deploy-Passkey-Users");
  assert.deepEqual(db.options.passkey_options, changedOptions);
  await make("customDomains").processChanges({ customDomains: [{ domain: "deploy.domains.e2e.test", type: "self_managed_certs", relying_party_identifier: sharedRP }] });
  let domain = pick(await make("customDomains").getType(), "domain", "deploy.domains.e2e.test");
  assert.equal(domain?.relying_party_identifier, sharedRP);
  await make("customDomains").processChanges({ customDomains: [{ domain: domain.domain, type: domain.type, relying_party_identifier: "deploy.domains.e2e.test" }] });
  domain = pick(await make("customDomains").getType(), "domain", "deploy.domains.e2e.test");
  assert.equal(domain.relying_party_identifier, "deploy.domains.e2e.test");
  for (const [roaming, platform] of [[true, true], [false, true], [false, false]]) {
    await make("guardianFactors").processChanges({ guardianFactors: [{ name: "webauthn-roaming", enabled: roaming }, { name: "webauthn-platform", enabled: platform }] });
    const factors = await make("guardianFactors").getType();
    assert.equal(pick(factors, "name", "webauthn-roaming").enabled, roaming);
    assert.equal(pick(factors, "name", "webauthn-platform").enabled, platform);
  }
  console.log(`Plan33b Deploy CLI 9.1.0 round trip (clients, databases, customDomains, guardianFactors) passed on ${process.env.E2E_M33B_BACKEND}`);
}

async function snapshot() {
  await logsOf("s");
  await until(async () => {
    const rows = (await readFile(`${work}/receiver.jsonl`, "utf8")).trim().split("\n").filter(Boolean).map(JSON.parse);
    return rows.some((r) => r.path === "/logs") && rows.some((r) => r.path === "/events");
  }, "real log stream and event stream deliveries", 60000);
}

async function audit() {
  const secrets = (await readFile(`${work}/private-secrets.jsonl`, "utf8")).trim().split("\n").map(JSON.parse);
  const lanes = ` ${process.env.E2E_M33B_LANES ?? "browser native sdk cli audit"} `;
  const required = ["management token", "password"];
  if (lanes.includes(" native ")) required.push("auth_session", "challenge", "clientDataJSON", "attestationObject", "signature", "userHandle", "authenticatorData");
  if (lanes.includes(" browser ") && process.env.E2E_M33B_BACKEND === "sqlite") required.push("challenge_id");
  for (const kind of required) assert.ok(secrets.some((s) => s.kind === kind), `actual ${kind} positive control`);
  const names = ["responses.jsonl", "browser-console.jsonl", "browser-responses.jsonl", "browser-navigation.jsonl", "cli.jsonl", "receiver.jsonl", "server.log", "legacy-server.log", "proxy.log", "receiver.log", "migrate.log", "bootstrap.stderr", "stored-sinks.jsonl"];
  let bytes = 0;
  for (const name of names) {
    const text = await readFile(`${work}/${name}`, "utf8");
    scan(text, secrets, name);
    bytes += text.length;
  }
  const kinds = [...new Set(secrets.map((s) => s.kind))].sort();
  await writeFile(`${work}/privacy-audit.json`, JSON.stringify({ passed: true, names, bytes, representativeSecrets: secrets.length, kinds }));
  console.log(`Plan33b privacy: ${names.length} sinks (${bytes} bytes), ${secrets.length} representative secrets of ${kinds.length} kinds absent`);
}

if (process.argv[1] === import.meta.filename)
  await ({ setup, sdk, deploy, snapshot, audit }[process.argv[2]] ?? (() => { throw Error("unknown mode"); }))();
