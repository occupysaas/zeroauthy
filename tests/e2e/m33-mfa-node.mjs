// Plan 33: real local HTTP and pinned node-auth0; shared privacy instrumentation.
import assert from "node:assert/strict";
import {
  appendFile,
  readFile,
  writeFile,
  readdir,
  stat,
} from "node:fs/promises";
import { createHmac } from "node:crypto";
import { ProxyAgent } from "undici";
import { ManagementClient } from "auth0";
export const work = process.env.E2E_M33_WORK,
  origin = "https://sdk.e2e.test";
export const password = "Plan33-User-Password-2026",
  operatorPassword = "Plan33-Operator-Password-2026";
export const credentials = {
  client: "m33-admin",
  secret: "Plan33-Management-Secret-2026",
};
export const clientSecret = "Plan33-Password-Client-Secret-2026";
const dispatcher = new ProxyAgent("http://127.0.0.1:9198");
export const fixtureFetch = (url, opts = {}) =>
  fetch(url, { ...opts, dispatcher });
export const state = async () =>
  JSON.parse(await readFile(`${work}/private-state.json`, "utf8"));
export const saveState = (value) =>
  writeFile(`${work}/private-state.json`, JSON.stringify(value), {
    mode: 0o600,
  });
export async function secret(value, kind) {
  assert.equal(typeof value, "string");
  assert.ok(value.length >= 6);
  await appendFile(
    `${work}/private-secrets.jsonl`,
    JSON.stringify({ kind, value }) + "\n",
    { mode: 0o600 },
  );
  return value;
}
// Each exemption is a documented one-time field, never a whole response/sink.
function displayFields(location, value) {
  if (location === "/mfa/associate")
    return ["secret", "barcode_uri", "recovery_codes", "oob_code"];
  if (location === "SDK associate")
    return ["secret", "barcodeUri", "recoveryCodes"];
  if (location === "SDK ticket") return ["ticket_id", "ticket_url"];
  if (location === "SDK recovery") return ["recovery_code"];
  if (location === "SDK email challenge") return ["oobCode"];
  if (location === "raw token")
    return value?.error === "mfa_required"
      ? ["mfa_token"]
      : value?.access_token
        ? ["recovery_code"]
        : [];
  if (
    /^console POST \/api\/v2\/users\/[^/]+\/recovery-code-regeneration$/.test(
      location,
    ) ||
    location === "console POST recovery-code-regeneration delayed"
  )
    return ["recovery_code"];
  if (/^CLI POST users\/[^/]+\/recovery-code-regeneration$/.test(location))
    return ["recovery_code"];
  return [];
}
export async function oneTime(
  value,
  allowed = [],
  location = "ordinary response",
) {
  const permitted = displayFields(location, value);
  for (const field of allowed)
    assert.ok(
      permitted.includes(field),
      `${location}: one-time exception not permitted for ${field}`,
    );
  const copy = structuredClone(value);
  for (const key of allowed) {
    assert.ok(
      [
        "secret",
        "barcode_uri",
        "recovery_codes",
        "recovery_code",
        "mfa_token",
        "oob_code",
        "ticket_id",
        "ticket_url",
        "barcodeUri",
        "recoveryCodes",
        "oobCode",
      ].includes(key),
    );
    if (copy?.[key] !== undefined) {
      for (const v of [].concat(copy[key])) await secret(v, key);
      copy[key] = "<one-time-display>";
    }
  }
  return copy;
}
export async function capture(name, value, allowed = []) {
  const copy = await oneTime(value, allowed, name);
  await appendFile(
    `${work}/responses.jsonl`,
    JSON.stringify({ name, value: copy }) + "\n",
  );
  return value;
}
export function scan(text, secrets, label) {
  for (const { value, kind } of secrets) {
    const variants = [
      value,
      encodeURIComponent(value),
      Buffer.from(value).toString("base64"),
      Buffer.from(value).toString("base64url"),
      Buffer.from(value).toString("hex"),
    ];
    // A numeric code is disclosed only as a whole digit token; otherwise a
    // random code collides with digits in timestamps or padded IDs (as in
    // the Plan 34 scan).
    const numeric = /^\d+$/.test(value);
    const leaked = (v) =>
      numeric && v === value
        ? new RegExp(`(?<!\\d)${v}(?!\\d)`).test(text)
        : text.includes(v);
    assert.ok(!variants.some(leaked), `${label}: leaked ${kind}`);
  }
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
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: credentials.client,
      client_secret: credentials.secret,
      audience: `${origin}/api/v2/`,
    }),
  });
  assert.equal(r.status, 200);
  bearer = (await r.json()).access_token;
  await secret(bearer, "management token");
  return bearer;
}
export async function api(path, method = "GET", body, allowed = []) {
  const r = await fixtureFetch(`${origin}/api/v2/${path}`, {
    method,
    headers: {
      authorization: `Bearer ${await token()}`,
      "content-type": "application/json",
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const value = await r.json().catch(() => null);
  assert.ok(r.ok, `${method} ${path}: ${r.status} ${JSON.stringify(value)}`);
  return capture(path, value, allowed);
}
export const management = async () =>
  new ManagementClient({
    domain: "sdk.e2e.test",
    token: await token(),
    maxRetries: 0,
    fetch: fixtureFetch,
  });
// Independent RFC 6238, SHA-1 / six digits / 30 seconds; no server module import.
export function totp(seed, step = Math.floor(Date.now() / 30000)) {
  let bits = "";
  for (const ch of seed.replace(/=+$/, "")) {
    const n = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch);
    assert.ok(n >= 0);
    bits += n.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8)
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hash = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = hash.at(-1) & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(
    6,
    "0",
  );
}
export async function code(seed, step) {
  return secret(totp(seed, step), "OTP");
}
const readMail = new Set();
export const mailCheckpoint = async () =>
  new Set(await readdir(`${work}/private-mail`));
export async function mailbox(email, before = new Set()) {
  return until(async () => {
    const names = (await readdir(`${work}/private-mail`)).sort().reverse();
    for (const name of names) {
      if (readMail.has(name) || before.has(name)) continue;
      const body = await readFile(`${work}/private-mail/${name}`, "utf8");
      if (body.includes(email)) {
        const found = body.match(/\b\d{6}\b/);
        if (found) {
          readMail.add(name);
          return secret(found[0], "email code");
        }
      }
    }
  }, "tenant SMTP code");
}
async function setup() {
  const m = await management();
  assert.equal(
    JSON.parse(
      await readFile(
        new URL("../../package.json", import.meta.resolve("auth0")),
      ),
    ).version,
    "7.4.0",
  );
  await secret(password, "password");
  await secret(operatorPassword, "operator password");
  await secret(credentials.secret, "client secret");
  await secret(clientSecret, "client secret");
  await secret("Plan33-Receiver-Bearer-2026", "receiver secret");
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.factors.set("recovery-code", { enabled: true });
  await m.guardian.policies.set(["all-applications"]);
  await api("emails/provider", "POST", {
    name: "smtp",
    enabled: true,
    default_from_address: "mfa@e2e.local",
    credentials: { smtp_host: "127.0.0.1", smtp_port: 9185 },
  });
  await api("email-templates", "POST", {
    template: "mfa_oob_code",
    body: "<p>{{ code }}</p>",
    subject: "Plan33 {{ code }}",
    enabled: true,
  });
  await api("event-streams", "POST", {
    name: "Plan33 privacy",
    subscriptions: [{ event_type: "user.updated" }],
    destination: {
      type: "webhook",
      configuration: {
        webhook_endpoint: "https://127.0.0.1:9186/events",
        webhook_authorization: {
          method: "bearer",
          token: "Plan33-Receiver-Bearer-2026",
        },
      },
    },
  });
  await api("log-streams", "POST", {
    name: "Plan33 privacy",
    type: "http",
    sink: {
      httpEndpoint: "https://127.0.0.1:9186/logs",
      httpContentType: "application/json",
      httpContentFormat: "JSONLINES",
    },
  });
  await saveState({});
  console.log(
    "Plan33 setup: real SMTP/log/event sinks and Guardian policy ready",
  );
}
async function sdk() {
  const m = await management();
  // Since Plan 33b a roaming security key is a real factor that the hosted
  // picker offers, so it is enabled only for this round trip and the browser
  // and grants lanes keep their Plan 33 factor set.
  await m.guardian.factors.set("webauthn-roaming", { enabled: true });
  const factors = await m.guardian.factors.list();
  await capture("SDK guardian factors", factors);
  assert.equal(
    factors.find((f) => f.name === "webauthn-roaming").enabled,
    true,
  );
  await m.guardian.factors.set("webauthn-roaming", { enabled: false });
  assert.deepEqual(await m.guardian.policies.list(), ["all-applications"]);
  const u = await m.users.create({
    connection: "Username-Password-Authentication",
    email: "sdk-mfa@e2e.local",
    password,
    email_verified: true,
  });
  const id = u.user_id;
  const method = await m.users.authenticationMethods.create(id, {
    type: "email",
    email: u.email,
  });
  await capture("SDK method", method);
  const list = await m.users.authenticationMethods.list(id);
  assert.ok(list.data.some((x) => x.id === method.id));
  assert.equal(
    (await m.users.authenticationMethods.get(id, method.id)).id,
    method.id,
  );
  await m.users.authenticationMethods.update(id, method.id, {
    name: "SDK email",
  });
  const enrollments = await m.users.enrollments.get(id);
  await capture("SDK enrollments", enrollments);
  assert.ok(enrollments.length);
  await capture(
    "SDK enrollment",
    await m.guardian.enrollments.get(method.id.split("|").at(-1)),
  );
  await capture("SDK recovery", await m.users.regenerateRecoveryCode(id), [
    "recovery_code",
  ]);
  await capture(
    "SDK ticket",
    await m.guardian.enrollments.createTicket({
      user_id: id,
      send_mail: false,
    }),
    ["ticket_id", "ticket_url"],
  );
  await m.guardian.enrollments.delete(method.id.split("|").at(-1));
  assert.equal(
    (await m.users.authenticationMethods.list(id)).data.length,
    1,
    "recovery remains",
  );
  await m.users.authenticationMethods.deleteAll(id);
  assert.equal((await m.users.authenticationMethods.list(id)).data.length, 0);
  console.log("Plan33 node-auth0 Guardian/methods/enrollments/recovery passed");
}
async function snapshot() {
  // Checkpoint IDs must be positive; ordinary sorted pages include the first
  // event as well as recent events, without an invalid zero sentinel.
  for (let page = 0; ; page++) {
    const rows = await api(`logs?per_page=100&page=${page}&sort=date:1`);
    if (rows.length < 100) break;
  }
  await until(async () => {
    const rows = (await readFile(`${work}/receiver.jsonl`, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse);
    const f = await state();
    const enrollment = rows
      .filter((r) => r.path === "/events")
      .map((r) => JSON.parse(r.body))
      .some((event) => {
        const user = event.data?.object;
        return (
          event.type === "user.updated" &&
          (f.uid
            ? user?.user_id === f.uid
            : user?.email === "grants-raw-otp@e2e.local") &&
          JSON.stringify(user?.multifactor) === '["guardian"]'
        );
      });
    return rows.some((r) => r.path === "/logs") && enrollment;
  }, "real log sink and user.updated event sink");
}
async function audit() {
  const secrets = (await readFile(`${work}/private-secrets.jsonl`, "utf8"))
    .trim()
    .split("\n")
    .map(JSON.parse);
  for (const kind of [
    "TOTP seed",
    "OTP",
    "email code",
    "mfa_token",
    "recovery_code",
    "ticket_id",
  ]) {
    assert.ok(
      secrets.some((s) => s.kind === kind),
      `actual ${kind} positive control`,
    );
  }
  const names = [
    "responses.jsonl",
    "browser-console.jsonl",
    "browser-responses.jsonl",
    "cli.jsonl",
    "receiver.jsonl",
    "server.log",
    "proxy.log",
    "receiver.log",
    "migrate.log",
    "bootstrap.stderr",
    "stored-sinks.jsonl",
  ];
  let bytes = 0;
  for (const name of names) {
    const text = await readFile(`${work}/${name}`, "utf8");
    scan(text, secrets, name);
    bytes += text.length;
  }
  await writeFile(
    `${work}/privacy-audit.json`,
    JSON.stringify({
      passed: true,
      names,
      bytes,
      representativeSecrets: secrets.length,
      allowedFields:
        "Explicit one-time fields only; private input/mail/token material retained mode0600.",
    }),
  );
  console.log(
    `Plan33 privacy: ${names.length} complete captured sinks, ${secrets.length} actual secrets absent`,
  );
}
if (process.argv[1] === import.meta.filename)
  await (
    { setup, sdk, snapshot, audit }[process.argv[2]] ??
    (() => {
      throw Error("unknown mode");
    })
  )();
