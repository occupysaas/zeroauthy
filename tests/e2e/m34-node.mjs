// Plan 34: real local HTTP and pinned node-auth0; shared privacy instrumentation.
import assert from "node:assert/strict";
import { appendFile, readFile, writeFile, readdir } from "node:fs/promises";
import { ProxyAgent } from "undici";
import { ManagementClient } from "auth0";
export const work = process.env.E2E_M34_WORK,
  origin = "https://sdk.e2e.test";
export const password = "Plan34-User-Password-2026",
  operatorPassword = "Plan34-Operator-Password-2026";
export const credentials = {
  client: "m34-admin",
  secret: "Plan34-Management-Secret-2026",
};
export const clientSecret = "Plan34-Password-Client-Secret-2026";
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
function displayFields(location) {
  if (location === "phone associate") return ["oob_code", "recovery_codes"];
  if (location === "phone challenge") return ["oob_code"];
  if (location === "token") return ["mfa_token", "recovery_code"];
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
export const twilioSecret = "Plan34-Twilio-Auth-Secret-2026",
  snsSecret = "Plan34-SNS-Secret-2026";
export const otpGrant = "http://auth0.com/oauth/grant-type/passwordless/otp";
export async function phoneRecords() {
  return (await fetch("http://127.0.0.1:9184/_requests")).json();
}
export async function phoneCheckpoint() {
  return (await phoneRecords()).length;
}
export async function phoneCode(number, before = 0, kind) {
  await secret(number, "phone number");
  return until(
    async () => {
      const rows = (await phoneRecords()).slice(before).reverse();
      for (const r of rows) {
        if (kind && r.kind !== kind) continue;
        const text = JSON.stringify(r.form ?? r.body);
        if (!text.includes(number) && !text.includes(number.slice(1))) continue;
        let code = (r.form?.Body ?? r.form?.Message ?? r.body ?? "").match(
          /\b\d{6}\b/,
        )?.[0];
        if (r.form?.Twiml)
          code = r.form.Twiml.match(/(?:\d[. ]+){5}\d/)?.[0].replace(/\D/g, "");
        if (code) {
          if (r.authorization)
            await secret(r.authorization, "provider authorization");
          return secret(code, "phone OTP");
        }
      }
    },
    `phone delivery ${kind ?? ""}`,
  );
}
export async function emailBody(email, before = new Set()) {
  return until(async () => {
    for (const name of (await readdir(`${work}/private-mail`))
      .sort()
      .reverse()) {
      if (before.has(name)) continue;
      const body = await readFile(`${work}/private-mail/${name}`, "utf8");
      if (body.includes(email)) return body;
    }
  }, "mail delivery");
}
export async function start(body, status = 200) {
  const r = await fixtureFetch(`${origin}/passwordless/start`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_id: "m34-password", ...body }),
  });
  const b = await r.json();
  assert.equal(r.status, status, `start ${r.status} ${JSON.stringify(b)}`);
  // Only the documented submitted-phone echo may contain the input number.
  // Preserve every other field so an unexpected secret in any response fails.
  const ordinary = structuredClone(b);
  if (ordinary.phone_number !== undefined) {
    assert.equal(ordinary.phone_number, body.phone_number);
    await secret(body.phone_number, "phone number");
    ordinary.phone_number = "<submitted-phone-echo>";
  }
  await capture("passwordless/start", ordinary);
  return b;
}
export async function provider(name = "twilio") {
  for (const p of (await api("branding/phone/providers")).providers)
    await api("branding/phone/providers/" + p.id, "DELETE");
  const b =
    name === "twilio"
      ? {
          name,
          credentials: { auth_token: twilioSecret },
          configuration: {
            sid: "AC34Branding",
            default_from: "+15550001111",
            delivery_methods: ["text", "voice"],
          },
        }
      : name === "sns"
        ? {
            name,
            credentials: {
              access_key_id: "AKIAPLAN34EXAMPLE",
              secret_access_key: snsSecret,
            },
            configuration: {
              region: "us-east-1",
              sender_id: "ZA34",
              sms_type: "Transactional",
              delivery_methods: ["text"],
            },
          }
        : {
            name: "custom",
            credentials: {},
            configuration: { delivery_methods: ["text", "voice"] },
          };
  return api("branding/phone/providers", "POST", b);
}
export async function deploy(trigger, code) {
  const a = await api("actions/actions", "POST", {
    name: `Plan34 ${trigger}`,
    supported_triggers: [{ id: trigger, version: "v1" }],
    runtime: "node22",
    code,
  });
  await until(async () => {
    const v = await api("actions/actions/" + a.id);
    assert.notEqual(v.status, "failed");
    return v.status === "built";
  }, "Action built");
  await api("actions/actions/" + a.id + "/deploy", "POST");
  await api(`actions/triggers/${trigger}/bindings`, "PATCH", {
    bindings: [
      { ref: { type: "action_id", value: a.id }, display_name: a.name },
    ],
  });
  return a;
}
async function setup() {
  assert.equal(
    JSON.parse(
      await readFile(
        new URL("../../package.json", import.meta.resolve("auth0")),
      ),
    ).version,
    "7.4.0",
  );
  for (const [v, k] of [
    [password, "password"],
    [operatorPassword, "operator password"],
    [credentials.secret, "client secret"],
    [clientSecret, "client secret"],
    [twilioSecret, "provider credential"],
    [snsSecret, "provider credential"],
    ["Plan34-Guardian-Auth-Secret-2026", "provider credential"],
    ["Plan34-Gateway-Secret-2026", "provider credential"],
    ["Plan34-Receiver-Bearer-2026", "receiver secret"],
  ])
    await secret(v, k);
  await api("tenants/settings", "PATCH", {
    phone_consolidated_experience: true,
    flags: { disable_management_api_sms_obfuscation: false },
  });
  await api("emails/provider", "POST", {
    name: "smtp",
    enabled: true,
    default_from_address: "passwordless@e2e.local",
    credentials: { smtp_host: "127.0.0.1", smtp_port: 9185 },
  });
  await api("email-templates", "POST", {
    template: "auth_email_by_code",
    body: "<p>Code {{ code }}</p>",
    subject: "Plan34 code",
    enabled: true,
  });
  const enabled_clients = ["m34-spa", "m34-password"];
  const email = await api("connections", "POST", {
    name: "email",
    strategy: "email",
    enabled_clients,
    options: { totp: { length: 6, time_step: 300 } },
  });
  const sms = await api("connections", "POST", {
    name: "sms",
    strategy: "sms",
    enabled_clients,
    options: {
      provider: "twilio",
      from: "+15550001111",
      totp: { length: 6, time_step: 300 },
    },
  });
  await provider();
  await api("guardian/factors/sms", "PUT", { enabled: true });
  await api("guardian/factors/phone/message-types", "PUT", {
    message_types: ["sms", "voice"],
  });
  await api("guardian/factors/phone/selected-provider", "PUT", {
    provider: "twilio",
  });
  await api("guardian/factors/phone/settings", "PUT", {
    otp_length: 6,
    otp_expiration_time: 300,
  });
  await api("guardian/policies", "PUT", []);
  await api("event-streams", "POST", {
    name: "Plan34 privacy",
    subscriptions: [
      { event_type: "user.created" },
      { event_type: "user.updated" },
    ],
    destination: {
      type: "webhook",
      configuration: {
        webhook_endpoint: "https://127.0.0.1:9186/events",
        webhook_authorization: {
          method: "bearer",
          token: "Plan34-Receiver-Bearer-2026",
        },
      },
    },
  });
  await api("event-streams", "POST", {
    name: "Plan34 stored delivery privacy",
    subscriptions: [
      { event_type: "user.created" },
      { event_type: "user.updated" },
    ],
    destination: {
      type: "webhook",
      configuration: {
        webhook_endpoint: "https://127.0.0.1:9186/events-failure",
        webhook_authorization: {
          method: "bearer",
          token: "Plan34-Receiver-Bearer-2026",
        },
      },
    },
  });
  await api("log-streams", "POST", {
    name: "Plan34 privacy",
    type: "http",
    sink: {
      httpEndpoint: "https://127.0.0.1:9186/logs",
      httpContentType: "application/json",
      httpContentFormat: "JSONLINES",
    },
  });
  await saveState({ emailConnection: email.id, smsConnection: sms.id });
  console.log("Plan34 setup complete");
}
async function sdk() {
  const m = await management();
  // These are the pinned SDK resources, not a wrapper around raw HTTP.
  const connections = await m.connections.list();
  assert.ok(connections.data.some((c) => c.strategy === "sms"));
  const p = await m.branding.phone.providers.list();
  await capture("SDK providers", p);
  assert.equal(p.providers.length, 1);
  let id = p.providers[0].id;
  await capture("SDK provider", await m.branding.phone.providers.get(id));
  await m.branding.phone.providers.delete(id);
  const made = await m.branding.phone.providers.create({
    name: "twilio",
    credentials: { auth_token: twilioSecret },
    configuration: {
      sid: "AC34SDK",
      default_from: "+15550001111",
      delivery_methods: ["text", "voice"],
    },
  });
  await capture("SDK provider create", made);
  id = made.id;
  await m.branding.phone.providers.update(id, { disabled: false });
  const templates = await m.branding.phone.templates.list();
  await capture("SDK templates", templates);
  assert.ok(templates.templates.length);
  const t = await m.branding.phone.templates.create({
    type: "otp_verify",
    content: { body: { text: "Plan34 {{code}}", voice: "Plan34 {{code}}" } },
  });
  await capture("SDK template create", t);
  await m.branding.phone.templates.update(t.id, {
    content: { body: { text: "Code {{code}}" } },
  });
  await capture("SDK template get", await m.branding.phone.templates.get(t.id));
  await m.branding.phone.templates.delete(t.id);
  await capture(
    "SDK phone methods",
    await m.guardian.factors.phone.getMessageTypes(),
  );
  await m.guardian.factors.phone.setMessageTypes({
    message_types: ["sms", "voice"],
  });
  await m.guardian.factors.phone.setProvider({ provider: "twilio" });
  await capture(
    "SDK guardian provider",
    await m.guardian.factors.phone.getSelectedProvider(),
  );
  await m.guardian.factors.phone.set({
    otp_length: 6,
    otp_expiration_time: 300,
  });
  await capture("SDK guardian settings", await m.guardian.factors.phone.get());
  await m.attackProtection.phoneProviderProtection.patch({
    type: "exponential",
  });
  await capture(
    "SDK phone protection",
    await m.attackProtection.phoneProviderProtection.get(),
  );
  await m.attackProtection.phoneProviderProtection.patch({ type: "default" });
  await m.guardian.factors.phone.setTwilioProvider({
    sid: "AC34Guardian",
    auth_token: "Plan34-Guardian-Auth-Secret-2026",
    from: "+15550001111",
  });
  await capture(
    "SDK Guardian Twilio",
    await m.guardian.factors.phone.getTwilioProvider(),
  );
  await m.guardian.factors.phone.setTemplates({
    enrollment_message: "Code {{code}}",
    verification_message: "Code {{code}}",
  });
  await capture(
    "SDK Guardian templates",
    await m.guardian.factors.phone.getTemplates(),
  );
  const current = await state();
  await capture(
    "SDK email connection",
    await m.connections.get(current.emailConnection),
  );
  await m.connections.update(current.emailConnection, {
    options: { disable_signup: false },
  });
  console.log(
    "Plan34 node-auth0 7.4.0 connections/phone/Guardian/protection passed",
  );
}
async function snapshot() {
  const executions = new Set();
  for (let page = 0; ; page++) {
    const rows = await api(`logs?per_page=100&page=${page}&sort=date:1`);
    for (const row of rows)
      for (const id of row.details?.actions?.executions ?? [])
        executions.add(id);
    if (rows.length < 100) break;
  }
  await until(async () => {
    const rows = (await readFile(`${work}/receiver.jsonl`, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse);
    return (
      rows.some((r) => r.path === "/logs") &&
      rows.some((r) => r.path === "/events") &&
      rows.some((r) => r.path === "/events-failure")
    );
  }, "real log and event sinks");
  assert.ok(executions.size, "actual phone Action execution positive control");
  for (const id of executions) {
    const execution = await api("actions/executions/" + id);
    assert.ok(
      execution.trigger_id === "custom-phone-provider" &&
        execution.results.length > 0,
      "actual phone Action execution captured",
    );
  }
}
export function privacyScan(text, secrets, label) {
  for (const { value, kind } of secrets) {
    const variants = [
      value,
      encodeURIComponent(value),
      Buffer.from(value).toString("base64"),
      Buffer.from(value).toString("hex"),
      Buffer.from(value).toString("base64url"),
    ];
    if (kind === "phone number") variants.push(value.slice(1));
    const isCode = kind.includes("OTP") || kind.includes("code");
    if (isCode) variants.push(value.split("").join(". "));
    // A numeric code is disclosed only as a whole digit token; otherwise a
    // random code like 000147 collides with zero-padded IDs such as log row 147.
    const numeric = isCode && /^\d+$/.test(value);
    const leaked = (v) =>
      numeric && v === value
        ? new RegExp(`(?<!\\d)${v}(?!\\d)`).test(text)
        : text.includes(v);
    assert.ok(!variants.some(leaked), `${label}: leaked ${kind}`);
  }
  if (
    !["responses.jsonl", "cli.jsonl", "browser-responses.jsonl"].includes(label)
  )
    assert.ok(!/\+\d{10,15}\b/.test(text), `${label}: unmasked E.164`);
}
async function audit() {
  const secrets = (await readFile(`${work}/private-secrets.jsonl`, "utf8"))
    .trim()
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse);
  for (const k of [
    "phone number",
    "phone OTP",
    "email code",
    "link token",
    "provider credential",
  ])
    assert.ok(
      secrets.some((s) => s.kind === k),
      `positive control actual ${k}`,
    );
  // Private SMTP/phone delivery/request fixtures contain required cleartext input.
  // All server sinks and authorized ordinary API/console responses are scanned.
  const names = [
    "responses.jsonl",
    "browser-console.jsonl",
    "browser-responses.jsonl",
    "cli.jsonl",
    "receiver.jsonl",
    "server.log",
    "proxy.log",
    "receiver.log",
    "phone-fakes.log",
    "migrate.log",
    "bootstrap.stderr",
    "stored-sinks.jsonl",
  ];
  let bytes = 0;
  for (const name of names) {
    const body = await readFile(`${work}/${name}`, "utf8");
    privacyScan(body, secrets, name);
    bytes += body.length;
  }
  const consoleBodies = await readFile(
    `${work}/browser-responses.jsonl`,
    "utf8",
  );
  assert.ok(
    consoleBodies.includes("Plan34 phone privacy probe"),
    "actual Action console logs scanned on this backend",
  );
  const stored = await readFile(`${work}/stored-sinks.jsonl`, "utf8");
  if (process.env.E2E_M34_BACKEND !== "memory") {
    for (const table of [
      "tenant_logs",
      "action_executions",
      "tenant_events",
      "event_deliveries",
    ])
      assert.ok(stored.includes(table), `SQL ${table} dump populated`);
  }
  await writeFile(
    `${work}/privacy-audit.json`,
    JSON.stringify({
      passed: true,
      names,
      bytes,
      representativeSecrets: secrets.length,
      exemptions:
        "Only passwordless/start submitted-address echo and exact one-time credential fields; SMTP and provider transport are private fixtures.",
    }),
  );
  console.log(
    `Plan34 privacy ${names.length} captured sinks, ${secrets.length} actual representative secrets absent`,
  );
}
if (process.argv[1] === import.meta.filename)
  await { setup, sdk, snapshot, audit }[process.argv[2]]();
