// Plan 33b browser acceptance (spec §15 journeys 1-7, 11-12): the production
// app, Chromium CDP virtual authenticators, real hosted pages and console.
// Task 1 recorded that conditional (autofill) mediation resolves under a
// virtual authenticator, so journey 1 covers autofill and the button path.
import { test, expect } from "@playwright/test";
import { appendFile, readFile } from "node:fs/promises";
import { authorization, complete } from "./social/browser.mjs";
import {
  work, password, operatorPassword, realm, domains, sharedRP, api, mgmt, management, state, saveState, secret,
  credentialSecrets, optionsSecrets, until, logsOf, waitLog, connectionId, newTOTPSeed, totp, softKey, softBody,
  softAssert, proxyHeaders, fixtureFetch, ensurePasskeys,
} from "./m33b-node.mjs";

test.skip(!process.env.E2E_M33B_WORK, "Run make e2e-passkeys");
test.describe.configure({ mode: "serial" });
test.use({ trace: "off" });

// Virtual authenticators (§15).
const synced = { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, defaultBackupEligibility: true, defaultBackupState: true };
const hybrid = { ...synced, transport: "cable" };
const usbUV = { protocol: "ctap2", transport: "usb", hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };
const usbNoUV = { protocol: "ctap2", transport: "usb", hasResidentKey: false, hasUserVerification: false, isUserVerified: false, automaticPresenceSimulation: true };
const fido1 = { protocol: "u2f", transport: "usb", hasResidentKey: false, hasUserVerification: false, automaticPresenceSimulation: true };

const pending = [];
const settle = async () => { while (pending.length) await pending.shift(); };

// A browser profile: one context and page with the custom-domain edge proxy
// headers, sink capture, and representative-secret capture of every ceremony.
const profile = (browser, ...authenticators) => profileVia(browser, "http://127.0.0.1:9198", ...authenticators);
async function profileVia(browser, proxy, ...authenticators) {
  const context = await browser.newContext({ proxy: { server: proxy }, ignoreHTTPSErrors: true });
  await context.route(/^https:\/\/callback\.e2e\.test\//, (r) => r.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>Plan33b callback</title>" }));
  await context.route(/^https:\/\/[a-z0-9-]+\.domains\.e2e\.test\//, async (r) => {
    const headers = await proxyHeaders(new URL(r.request().url()).hostname);
    await r.continue({ headers: { ...r.request().headers(), ...headers } });
  });
  const page = await context.newPage();
  page.setDefaultNavigationTimeout(20000);
  page.setDefaultTimeout(15000);
  page.on("console", (msg) => pending.push(appendFile(`${work}/browser-console.jsonl`, JSON.stringify({ type: msg.type(), text: msg.text() }) + "\n")));
  page.on("request", (req) => {
    if (req.method() !== "POST") return;
    const form = new URLSearchParams(req.postData() ?? "");
    const credential = form.get("credential"), id = form.get("challenge_id");
    if (id) pending.push(secret(id, "challenge_id"));
    if (credential) pending.push(credentialSecrets(JSON.parse(credential), `hosted ${new URL(req.url()).pathname}`));
  });
  page.on("domcontentloaded", () => {
    pending.push((async () => {
      const text = await page.evaluate(() => document.getElementById("za-webauthn")?.textContent).catch(() => null);
      if (!text) return;
      const config = JSON.parse(text);
      if (config.challenge_id) await secret(config.challenge_id, "challenge_id");
      await optionsSecrets(config.publicKey);
    })().catch(() => {}));
  });
  page.on("response", (r) => {
    const u = new URL(r.url());
    if (r.request().resourceType() === "document")
      pending.push(appendFile(`${work}/browser-navigation.jsonl`, JSON.stringify({ method: r.request().method(), url: `${u.origin}${u.pathname}`, status: r.status(), location: r.headers().location ? new URL(r.headers().location, u).pathname : undefined }) + "\n"));
    if (u.pathname.startsWith("/api/")) pending.push((async () => {
      await appendFile(`${work}/browser-responses.jsonl`, JSON.stringify({ url: r.url(), status: r.status(), body: await r.text().catch(() => "") }) + "\n");
    })());
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const s = { context, page, cdp, proxy, authenticators: [] };
  for (const options of authenticators) await addAuthenticator(s, options);
  return s;
}
async function addAuthenticator(s, options) {
  const { authenticatorId } = await s.cdp.send("WebAuthn.addVirtualAuthenticator", { options });
  s.authenticators.push(authenticatorId);
  return authenticatorId;
}
const credentials = async (s, i = 0) => (await s.cdp.send("WebAuthn.getCredentials", { authenticatorId: s.authenticators[i] })).credentials;

async function start(s, { host = "sdk.e2e.test", hint, extra = {} } = {}) {
  const flow = authorization({ domain: host, client: "m33b-spa", connection: realm });
  const u = new URL(flow.url);
  if (hint) u.searchParams.set("screen_hint", hint);
  for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
  await s.page.goto(u.href);
  return flow;
}
async function identify(s, email) {
  await s.page.fill("#username", email);
  await s.page.locator('form[action="/u/login"] button[type=submit]').click();
}
async function passwordStep(s) {
  await s.page.fill("#password", password);
  await s.page.locator("button[type=submit]").first().click();
}
async function finish(s, flow) {
  const result = await complete(s.page, flow, { proxy: s.proxy, headers: await proxyHeaders(flow.domain) });
  await secret(result.token.access_token, "access token");
  return result;
}
async function logout(s, host = "sdk.e2e.test") {
  await s.page.goto(`https://${host}/v2/logout?client_id=m33b-spa&returnTo=https%3A%2F%2Fcallback.e2e.test%2F`);
}
const userByEmail = async (email, host) => (await api(`users-by-email?email=${encodeURIComponent(email)}`, "GET", undefined, host))[0];
const methods = async (uid) => api(`users/${encodeURIComponent(uid)}/authentication-methods`);
async function newUser(email, extra = {}) {
  return api("users", "POST", { connection: realm, email, password, email_verified: true, ...extra });
}
async function addTOTP(uid) {
  const seed = await secret(newTOTPSeed(), "TOTP seed");
  await api(`users/${encodeURIComponent(uid)}/authentication-methods`, "POST", { type: "totp", totp_secret: seed });
  return seed;
}
let lastStep = 0;
async function otp(s, seed) {
  // A fresh 30 s step for every proof: OTP replay protection is real.
  await until(() => Math.floor(Date.now() / 30000) > lastStep, "fresh TOTP step", 35000);
  lastStep = Math.floor(Date.now() / 30000);
  await s.page.fill("#code", await secret(totp(seed, lastStep), "OTP"));
  await s.page.locator("button[type=submit]").first().click();
}
async function action(m, trigger, code) {
  await api(`actions/triggers/${trigger}/bindings`, "PATCH", { bindings: [] });
  const a = await m.actions.create({ name: `Plan33b ${trigger} ${Date.now()}`, supported_triggers: [{ id: trigger, version: trigger === "post-login" ? "v3" : "v1" }], runtime: "node22", code });
  await until(async () => {
    const v = await m.actions.get(a.id);
    expect(v.status).not.toBe("failed");
    return v.status === "built";
  }, "Action build", 60000);
  await m.actions.deploy(a.id);
  await api(`actions/triggers/${trigger}/bindings`, "PATCH", { bindings: [{ ref: { type: "action_id", value: a.id }, display_name: a.name }] });
}
async function passkeyOptions(patch) {
  const id = await connectionId();
  const options = (await api(`connections/${id}`)).options;
  await api(`connections/${id}`, "PATCH", { options: { ...options, passkey_options: { ...options.passkey_options, ...patch } } });
}
const unbind = (trigger) => api(`actions/triggers/${trigger}/bindings`, "PATCH", { bindings: [] });

async function operator(browser) {
  const context = await browser.newContext({ proxy: { server: "http://127.0.0.1:9198" }, ignoreHTTPSErrors: true });
  const op = await context.newPage();
  op.setDefaultNavigationTimeout(20000);
  op.setDefaultTimeout(15000);
  // Every console API response is captured in full for the audit (journey 11).
  await op.route("**/api/**", async (route) => {
    const response = await route.fetch({ maxRedirects: 0 });
    const body = await response.text();
    await appendFile(`${work}/browser-responses.jsonl`, JSON.stringify({ console: true, method: route.request().method(), url: route.request().url(), status: response.status(), body }) + "\n");
    await route.fulfill({ response, body });
  });
  op.on("console", (msg) => pending.push(appendFile(`${work}/browser-console.jsonl`, JSON.stringify({ type: msg.type(), text: msg.text() }) + "\n")));
  const st = await state();
  if (!st.operatorReady) {
    const setup = (await readFile(`${work}/operator-setup.txt`, "utf8")).trim().split("\n").at(-1);
    await op.goto(setup);
    await op.fill("#password", operatorPassword);
    await op.fill("#password_confirm", operatorPassword);
    await op.click("button[type=submit]");
    await saveState({ operatorReady: true });
  }
  await op.goto("https://system.e2e.test/admin/");
  await op.fill("#username", "operator33b@e2e.local");
  await op.fill("#password", operatorPassword);
  await op.click("button[type=submit]");
  await op.waitForURL(/\/admin\/t\//);
  return { context, op };
}


// Exported journey 1 passkey: later profiles hold "the same synced passkey".
async function withJ1(browser, signCount) {
  const s = await profile(browser, synced);
  const credential = { ...(await state()).j1Credential };
  if (signCount !== undefined) credential.signCount = signCount;
  await s.cdp.send("WebAuthn.addCredential", { authenticatorId: s.authenticators[0], credential });
  return s;
}
async function saveJ1(s) {
  const [credential] = await credentials(s);
  await saveState({ j1Credential: credential });
}
// Wait for the next hosted step and report which one appeared.
async function next(s, ...patterns) {
  await s.page.waitForURL((u) => patterns.some((p) => p.test(u.href)), { timeout: 20000 });
  return patterns.findIndex((p) => p.test(s.page.url()));
}
const callback = /^https:\/\/callback\.e2e\.test\//;
// After a WebAuthn MFA nickname or recovery code is submitted, walk the
// in-place success and recovery-code pages until the callback. Returns the
// recovery code shown on the way, if any (a representative secret).
async function confirmEnrollment(s) {
  let recovery;
  for (let i = 0; i < 6; i++) {
    await s.page.waitForLoadState("domcontentloaded");
    if (callback.test(s.page.url())) return recovery;
    if (await s.page.locator("p.alert[role=alert]").count()) throw Error(`enrollment refused: ${await s.page.locator("p.alert[role=alert]").innerText()}`);
    if (await s.page.locator("#recovery-code").count()) {
      recovery = await secret(await s.page.locator("#recovery-code").innerText(), "recovery_code");
      await s.page.locator("[name=ack]").check();
    }
    await Promise.all([s.page.waitForResponse((r) => r.request().method() === "POST" && r.request().resourceType() === "document", { timeout: 20000 }), s.page.locator("button[type=submit]").first().click()]);
  }
  throw Error(`enrollment did not finish at ${s.page.url()}`);
}
const alert = (s) => s.page.locator("p.alert[role=alert]");

test("journey 1: console prerequisites, passkey signup, autofill and button login, logs and Management API", async ({ browser }) => {
  test.setTimeout(240000);
  const { context: opContext, op } = await operator(browser);
  const conn = await connectionId();
  // An unmet prerequisite blocks enabling.
  await op.goto(`https://system.e2e.test/admin/t/sdk/connections/${conn}?tab=password`);
  await expect(op.locator('[data-prerequisite="identifier_first"]')).toContainText("Needs attention");
  await expect(op.locator("#passkey-enabled")).toBeDisabled();
  // Meet it in the prompts settings, then enable passkeys with "both".
  await op.goto("https://system.e2e.test/admin/t/sdk/branding?tab=prompts");
  const editor = op.locator("#branding-prompts");
  await expect(editor).toBeVisible();
  await expect(editor).toBeEnabled();
  await editor.fill(JSON.stringify({ universal_login_experience: "new", identifier_first: true }));
  await editor.locator("xpath=ancestor::form").getByRole("button", { name: /^Save( changes)?$/ }).click();
  await until(async () => (await api("prompts")).identifier_first === true, "identifier first saved by the console");
  await op.goto(`https://system.e2e.test/admin/t/sdk/connections/${conn}?tab=password`);
  for (const item of ["universal_login", "identifier_first", "username_or_flexible", "custom_db_import", "password_enabled"])
    await expect(op.locator(`[data-prerequisite="${item}"]`)).toContainText("Ready");
  await op.locator("#passkey-enabled").check();
  await op.locator("#passkey-ui").selectOption("both");
  await op.locator("#passkey-settings").getByRole("button", { name: /^Save( changes)?$/ }).click();
  await until(async () => (await api(`connections/${conn}`)).options?.authentication_methods?.passkey?.enabled === true, "passkeys enabled by the console");
  expect((await api(`connections/${conn}`)).options.passkey_options.challenge_ui).toBe("both");

  // A new user signs up with a passkey (no password).
  const email = "journey1-passkey@e2e.local";
  const s = await profile(browser, synced);
  let flow = await start(s, { hint: "signup" });
  await s.page.fill("#email", email);
  await s.page.locator('form[action="/u/signup/identifier"] button[type=submit]').click();
  await expect(s.page.locator("#za-passkey-button")).toBeVisible();
  await s.page.locator("#za-passkey-button").click();
  let result = await finish(s, flow);
  expect(result.claims.amr).toBeUndefined();
  const user = await userByEmail(email);
  const uid = user.user_id;
  await saveState({ j1: { uid, email } });
  expect((await credentials(s)).length).toBe(1);
  const ss = await waitLog("ss", (r) => r.user_id === uid);
  expect(ss.details.authentication_methods).toEqual(["passkey"]);
  const listed = (await methods(uid)).filter((x) => x.type === "passkey");
  expect(listed.length).toBe(1);
  expect(listed[0].credential_device_type).toBe("multi_device");
  expect(listed[0].credential_backed_up).toBe(true);
  expect(listed[0].relying_party_identifier).toBe("sdk.e2e.test");

  // Autofill ("both"): conditional mediation resolves on page load.
  await logout(s);
  flow = await start(s);
  result = await finish(s, flow);
  expect(result.claims.amr).toBeUndefined();
  expect(result.claims.sub).toBe(uid);
  const login = await waitLog("s", (r) => r.user_id === uid && Array.isArray(r.details?.prompts));
  expect(login.details.prompts).toEqual([{ name: "login-id", performed_amr: ["phr"] }]);
  // Button ("button"): no conditional request; the click starts the ceremony.
  const options = (await api(`connections/${conn}`)).options;
  await api(`connections/${conn}`, "PATCH", { options: { ...options, passkey_options: { ...options.passkey_options, challenge_ui: "button" } } });
  await logout(s);
  flow = await start(s);
  await expect(s.page.locator("#za-passkey-button")).toBeVisible();
  expect(await s.page.locator("#username").getAttribute("autocomplete")).toBe("username");
  await s.page.waitForTimeout(1500);
  expect(new URL(s.page.url()).pathname).toBe("/u/login");
  await s.page.locator("#za-passkey-button").click();
  result = await finish(s, flow);
  expect(result.claims.amr).toBeUndefined();
  expect(result.claims.sub).toBe(uid);
  await saveJ1(s);

  // The console shows the passkey through its safe projection.
  await op.goto(`https://system.e2e.test/admin/t/sdk/users/${encodeURIComponent(uid)}`);
  await op.getByRole("tab", { name: "MFA", exact: true }).click();
  await expect(op.getByRole("heading", { name: "Passkeys" })).toBeVisible();
  await expect(op.getByText("Synced").first()).toBeVisible({ timeout: 30000 });
  await settle();
  await s.context.close();
  await opContext.close();
});

test("journey 2: an MFA policy challenges a passkey login; an Action skips MFA for passkey logins", async ({ browser }) => {
  test.setTimeout(240000);
  const m = await management();
  const { uid } = (await state()).j1;
  const seed = await addTOTP(uid);
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.policies.set(["all-applications"]);
  const s = await withJ1(browser);
  let flow = await start(s);
  await s.page.locator("#za-passkey-button").click();
  await expect(s.page.locator("#code")).toBeVisible();
  await otp(s, seed);
  expect((await finish(s, flow)).claims.amr).toEqual(["mfa"]);
  await action(m, "post-login", `exports.onExecutePostLogin=async(event,api)=>{console.log("Plan33b methods "+JSON.stringify(event.authentication));if(event.authentication.methods.some(x=>x.name==="passkey"))api.multifactor.enable("none");};`);
  await logout(s);
  flow = await start(s);
  await s.page.locator("#za-passkey-button").click();
  expect((await finish(s, flow)).claims.amr).toBeUndefined();
  // A password login is still challenged under the same Action.
  await logout(s);
  const email = "journey2-password@e2e.local";
  const pw = await newUser(email);
  const pwSeed = await addTOTP(pw.user_id);
  const p = await profile(browser, synced);
  flow = await start(p);
  await identify(p, email);
  await passwordStep(p);
  await expect(p.page.locator("#code")).toBeVisible();
  await otp(p, pwSeed);
  // Progressive enrollment follows MFA for this password user (journey 3).
  expect(await next(p, callback, /\/u\/passkey-enrollment/)).toBe(1);
  await p.page.locator("#za-passkey-skip button[type=submit]").click();
  expect((await finish(p, flow)).claims.amr).toEqual(["mfa"]);
  await saveJ1(s);
  await unbind("post-login");
  await m.guardian.policies.set([]);
  await settle();
  await s.context.close();
  await p.context.close();
});

test("journey 3: progressive enrollment after MFA, don't show again, a second user enrolls, hybrid local enrollment", async ({ browser }) => {
  test.setTimeout(300000);
  const m = await management();
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.policies.set(["all-applications"]);
  const first = await newUser("journey3-snooze@e2e.local");
  const seed = await addTOTP(first.user_id);
  const a = await profile(browser, synced);
  let flow = await start(a);
  await identify(a, first.email);
  await passwordStep(a);
  await otp(a, seed);
  expect(await next(a, callback, /\/u\/passkey-enrollment$|\/u\/passkey-enrollment\?/)).toBe(1);
  await expect(a.page.locator("#za-passkey-button")).toBeVisible();
  await a.page.locator("#za-passkey-skip [name=snooze]").check();
  await a.page.locator("#za-passkey-skip button[type=submit]").click();
  expect((await finish(a, flow)).claims.amr).toEqual(["mfa"]);
  await logout(a);
  flow = await start(a);
  await identify(a, first.email);
  await passwordStep(a);
  await otp(a, seed);
  expect(await next(a, callback, /\/u\/passkey-enrollment/)).toBe(0);
  await finish(a, flow);
  expect((await methods(first.user_id)).some((x) => x.type === "passkey")).toBe(false);

  const second = await newUser("journey3-enroll@e2e.local");
  const seed2 = await addTOTP(second.user_id);
  const b = await profile(browser, synced);
  flow = await start(b);
  await identify(b, second.email);
  await passwordStep(b);
  await otp(b, seed2);
  expect(await next(b, callback, /\/u\/passkey-enrollment/)).toBe(1);
  await b.page.locator("#za-passkey-button").click();
  await finish(b, flow);
  const enrolled = (await methods(second.user_id)).filter((x) => x.type === "passkey");
  expect(enrolled.length).toBe(1);
  expect(enrolled[0].relying_party_identifier).toBe("sdk.e2e.test");
  await m.guardian.policies.set([]);

  // Hybrid: a phone passkey (cable) is enrolled progressively, then a login
  // with it on a device with a platform authenticator offers local enrollment.
  const third = await newUser("journey3-hybrid@e2e.local");
  const c = await profile(browser, hybrid);
  flow = await start(c);
  await identify(c, third.email);
  await passwordStep(c);
  expect(await next(c, callback, /\/u\/passkey-enrollment/)).toBe(1);
  await c.page.locator("#za-passkey-button").click();
  await finish(c, flow);
  expect((await credentials(c, 0)).length).toBe(1);
  await logout(c);
  await addAuthenticator(c, synced);
  flow = await start(c);
  await c.page.locator("#za-passkey-button").click();
  expect(await next(c, callback, /\/u\/passkey-enrollment-local/)).toBe(1);
  await c.page.locator("#za-passkey-button").click();
  await finish(c, flow);
  expect((await credentials(c, 1)).length).toBe(1);
  expect((await methods(third.user_id)).filter((x) => x.type === "passkey").length).toBe(2);
  await settle();
  for (const p of [a, b, c]) await p.context.close();
});

test("journey 4: an unmet prerequisite hides passkey UI; the API keeps the options unchanged", async ({ browser }) => {
  test.setTimeout(120000);
  const conn = await connectionId();
  const before = (await api(`connections/${conn}`)).options;
  await api("prompts", "PATCH", { identifier_first: false });
  const s = await profile(browser, synced);
  await start(s);
  await expect(s.page.locator("#username")).toBeVisible();
  await expect(s.page.locator("#za-passkey-button")).toHaveCount(0);
  await expect(s.page.locator("#za-webauthn")).toHaveCount(0);
  const after = (await api(`connections/${conn}`)).options;
  expect(after.authentication_methods).toEqual(before.authentication_methods);
  expect(after.passkey_options).toEqual(before.passkey_options);
  expect(after.authentication_methods.passkey.enabled).toBe(true);
  await api("prompts", "PATCH", { identifier_first: true });
  await start(s);
  await expect(s.page.locator("#za-passkey-button")).toBeVisible();
  await settle();
  await s.context.close();
});

test("journey 5: RP IDs across custom domains, shared parent, cross-host/tenant replay, forged origin, base domain", async ({ browser }) => {
  test.setTimeout(300000);
  const st = await state();
  const user = await newUser("journey5-domains@e2e.local");
  const s = await profile(browser, synced);
  // Enroll on the first custom domain, whose RP ID is the shared parent.
  let flow = await start(s, { host: domains.primary });
  await identify(s, user.email);
  await passwordStep(s);
  expect(await next(s, callback, /\/u\/passkey-enrollment/)).toBe(1);
  await s.page.locator("#za-passkey-button").click();
  const r1 = await finish(s, flow);
  expect(r1.claims.iss).toBe(`https://${domains.primary}/`);
  expect((await methods(user.user_id)).find((x) => x.type === "passkey").relying_party_identifier).toBe(sharedRP);
  // The second custom domain keeps its own host as RP ID: not offered.
  // The browser holds no credential for alt's RP ID, so it reports
  // NotAllowedError; the server answers with the sign-in page again.
  expect((await credentials(s)).map((c) => c.rpId)).toEqual([sharedRP]);
  flow = await start(s, { host: domains.alt });
  const answered = s.page.waitForResponse((r) => new URL(r.url()).pathname === "/u/login/passkey");
  await s.page.locator("#za-passkey-button").click();
  const posted = await answered;
  expect(new URLSearchParams(posted.request().postData()).get("webauthn_error")).toBe("NotAllowedError");
  await expect(s.page.locator("#username")).toBeVisible();
  expect(new URL(s.page.url()).host).toBe(domains.alt);
  // Sharing the parent makes it work there.
  await api(`custom-domains/${st.domainIDs[domains.alt]}`, "PATCH", { relying_party_identifier: sharedRP });
  flow = await start(s, { host: domains.alt });
  await s.page.locator("#za-passkey-button").click();
  expect((await finish(s, flow)).claims.sub).toBe(user.user_id);
  // Capture one real assertion without delivering it.
  await logout(s, domains.alt);
  await start(s, { host: domains.alt });
  let captured;
  await s.page.route("**/u/login/passkey", async (r) => { captured = new URLSearchParams(r.request().postData()).get("credential"); await r.abort(); });
  await s.page.locator("#za-passkey-button").click();
  await until(() => captured, "captured assertion");
  await s.page.unroute("**/u/login/passkey");
  async function submit(page, credential) {
    await page.evaluate((credential) => {
      const form = document.getElementById("za-passkey-form");
      form.action = "/u/login/passkey";
      form.elements.credential.value = credential;
      form.submit();
    }, credential);
    await page.waitForLoadState("domcontentloaded");
  }
  const failures = (await logsOf("gd_webauthn_challenge_failed")).length;
  // Replayed on another host of the same RP, and on another tenant.
  for (const host of [domains.primary, "other.e2e.test"]) {
    const t = await profile(browser);
    await start(t, { host });
    await expect(t.page.locator("#za-passkey-form")).toHaveCount(1);
    await submit(t.page, captured);
    await expect(alert(t)).toBeVisible();
    expect(new URL(t.page.url()).pathname).toMatch(/^\/u\/login/);
    await t.context.close();
  }
  await until(async () => (await logsOf("gd_webauthn_challenge_failed")).length >= failures + 1, "replay refusals logged");
  // A forged origin, signed by a software key registered through the API.
  const soft = await newUser("journey5-soft@e2e.local");
  const key = softKey(sharedRP);
  await api(`users/${encodeURIComponent(soft.user_id)}/authentication-methods`, "POST", softBody(key));
  const f = await profile(browser);
  const challengeOf = async () => JSON.parse(await f.page.locator("#za-webauthn").textContent()).publicKey.challenge;
  await start(f, { host: domains.alt });
  await submit(f.page, JSON.stringify(softAssert(key, { challenge: await challengeOf(), origin: "https://evil.domains.e2e.test" })));
  await expect(alert(f)).toBeVisible();
  // Positive control: the same key and the true origin sign in.
  flow = await start(f, { host: domains.alt });
  await submit(f.page, JSON.stringify(softAssert(key, { challenge: await challengeOf(), origin: `https://${domains.alt}` })));
  expect((await finish(f, flow)).claims.sub).toBe(soft.user_id);
  // An RP ID at the shared namespace (e2e.test) covers the system host and
  // the second tenant: refused (R1, restrict_shared_rp_ids). No base_domain
  // is configured here: custom domains may not sit under it (Plan 23).
  const base = await mgmt(`custom-domains/${st.domainIDs[domains.alt]}`, "PATCH", { relying_party_identifier: "e2e.test" });
  expect(base.status).toBe(400);
  await settle();
  await s.context.close();
  await f.context.close();
});

test("journey 6: a cloned credential with a lower sign count is refused; no prompt at the passkey limit", async ({ browser }) => {
  test.setTimeout(240000);
  const { uid } = (await state()).j1;
  const clone = await withJ1(browser, 0);
  const flow = await start(clone);
  await clone.page.locator("#za-passkey-button").click();
  await expect(alert(clone)).toBeVisible();
  void flow;
  const log = await waitLog("gd_webauthn_challenge_failed", (r) => r.details?.failure_details?.errorCode === "sign_count");
  expect(log.details.first_factor).toBe(true);
  void uid;
  // At 20 passkeys no enrollment is offered and a 21st is refused.
  const user = await newUser("journey6-limit@e2e.local");
  const c = await profile(browser, hybrid);
  let f = await start(c);
  await identify(c, user.email);
  await passwordStep(c);
  expect(await next(c, callback, /\/u\/passkey-enrollment/)).toBe(1);
  await c.page.locator("#za-passkey-button").click();
  await finish(c, f);
  for (let i = 0; i < 19; i++)
    await api(`users/${encodeURIComponent(user.user_id)}/authentication-methods`, "POST", softBody(softKey("sdk.e2e.test"), { name: `Key ${i + 2}`, user_handle: undefined }));
  expect((await methods(user.user_id)).filter((x) => x.type === "passkey").length).toBe(20);
  await logout(c);
  await addAuthenticator(c, synced);
  f = await start(c);
  await c.page.locator("#za-passkey-button").click();
  expect(await next(c, callback, /\/u\/passkey-enrollment-local/)).toBe(0);
  await finish(c, f);
  const extra = await mgmt(`users/${encodeURIComponent(user.user_id)}/authentication-methods`, "POST", softBody(softKey("sdk.e2e.test"), { user_handle: undefined }));
  expect(extra.status).toBe(400);
  expect(JSON.stringify(extra.body)).toContain("passkey enrollment limit reached");
  await settle();
  await clone.context.close();
  await c.context.close();
});

test("journey 7: WebAuthn MFA security keys, UV, FIDO-1, biometrics, recovery, tickets and Actions", async ({ browser }) => {
  test.setTimeout(600000);
  const m = await management();
  const { context: opContext, op } = await operator(browser);
  const setUV = async (value) => {
    await op.goto("https://system.e2e.test/admin/t/sdk/mfa");
    await expect(op.locator("#webauthn-uv")).toBeEnabled();
    await op.locator("#webauthn-uv").selectOption(value);
    await expect(op.locator("#webauthn-uv")).toHaveValue(value);
    await op.waitForTimeout(500);
  };
  // Journey 7 is about MFA: no passkey enrollment prompts in between.
  await passkeyOptions({ progressive_enrollment_enabled: false });
  await m.guardian.factors.set("otp", { enabled: false });
  await m.guardian.factors.set("webauthn-roaming", { enabled: true });
  await m.guardian.factors.set("recovery-code", { enabled: true });
  await m.guardian.policies.set(["all-applications"]);
  await setUV("discouraged");
  // Enroll a UV-less USB key ("Never"), name it, keep the recovery code.
  const user = await newUser("journey7-key@e2e.local");
  const k = await profile(browser, usbNoUV);
  let flow = await start(k);
  await identify(k, user.email);
  await passwordStep(k);
  expect(await next(k, /\/u\/mfa-webauthn-roaming-enrollment/)).toBe(0);
  await k.page.locator("#za-passkey-button").click();
  expect(await next(k, /\/u\/mfa-webauthn-change-key-nickname/)).toBe(0);
  await k.page.fill("#name", "Journey7 key");
  await Promise.all([k.page.waitForNavigation(), k.page.locator("button[type=submit]").first().click()]);
  const recovery = await confirmEnrollment(k);
  expect((await finish(k, flow)).claims.amr).toEqual(["mfa"]);
  expect(recovery).toBeTruthy();
  const keyMethod = (await methods(user.user_id)).find((x) => x.type === "webauthn-roaming");
  expect(keyMethod.name).toBe("Journey7 key");
  expect(keyMethod.relying_party_identifier).toBe("sdk.e2e.test");
  // Log in with it and tick remember browser.
  await logout(k);
  flow = await start(k);
  await identify(k, user.email);
  await passwordStep(k);
  expect(await next(k, /\/u\/mfa-webauthn-roaming-challenge/)).toBe(0);
  await k.page.locator("[name=remember]").check();
  await k.page.locator("#za-passkey-button").click();
  expect((await finish(k, flow)).claims.amr).toEqual(["mfa"]);
  await logout(k);
  flow = await start(k);
  await identify(k, user.email);
  await passwordStep(k);
  await finish(k, flow);
  // UV Required: the UV-less key fails, and a FIDO-1 key cannot enroll.
  await setUV("required");
  await api(`users/${encodeURIComponent(user.user_id)}/multifactor/actions/invalidate-remember-browser`, "POST", {});
  await logout(k);
  flow = await start(k);
  await identify(k, user.email);
  await passwordStep(k);
  expect(await next(k, /\/u\/mfa-webauthn-roaming-challenge/)).toBe(0);
  await k.page.locator("#za-passkey-button").click();
  await expect(alert(k)).toBeVisible();
  const u2fUser = await newUser("journey7-u2f@e2e.local");
  const u = await profile(browser, fido1);
  flow = await start(u);
  await identify(u, u2fUser.email);
  await passwordStep(u);
  expect(await next(u, /\/u\/mfa-webauthn-roaming-enrollment/)).toBe(0);
  await u.page.locator("#za-passkey-button").click();
  await expect(alert(u)).toBeVisible();
  expect((await methods(u2fUser.user_id)).some((x) => x.type === "webauthn-roaming" && x.confirmed !== false)).toBe(false);
  await setUV("discouraged");
  // The recovery code still works.
  await logout(k);
  flow = await start(k);
  await identify(k, user.email);
  await passwordStep(k);
  expect(await next(k, /\/u\/mfa-webauthn-roaming-challenge/)).toBe(0);
  await k.page.locator("a[href*='action=another']").click();
  await k.page.locator('button[name=factor][value="recovery-code"]').click();
  await k.page.fill("#code", recovery);
  await Promise.all([k.page.waitForNavigation(), k.page.locator("button[type=submit]").first().click()]);
  // A used recovery code is replaced: the new one is shown in place.
  await confirmEnrollment(k);
  expect((await finish(k, flow)).claims.amr).toEqual(["mfa"]);

  // Biometrics: enroll after OTP through the progressive prompt; "Remind me
  // later" suppresses it; a platform challenge follows enrollment.
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.factors.set("webauthn-platform", { enabled: true });
  const later = await newUser("journey7-remind@e2e.local");
  const laterSeed = await addTOTP(later.user_id);
  const r = await profile(browser, synced);
  flow = await start(r);
  await identify(r, later.email);
  await passwordStep(r);
  await expect(r.page.locator("#code")).toBeVisible();
  await otp(r, laterSeed);
  expect(await next(r, /\/u\/mfa-webauthn-platform-enrollment/, callback)).toBe(0);
  await r.page.locator('button[name=platform_choice][value="remind"]').click();
  await finish(r, flow);
  await logout(r);
  flow = await start(r);
  await identify(r, later.email);
  await passwordStep(r);
  await otp(r, laterSeed);
  expect(await next(r, /\/u\/mfa-webauthn-platform-enrollment/, callback)).toBe(1);
  await finish(r, flow);
  const bio = await newUser("journey7-biometrics@e2e.local");
  const bioSeed = await addTOTP(bio.user_id);
  const b = await profile(browser, synced);
  flow = await start(b);
  await identify(b, bio.email);
  await passwordStep(b);
  await otp(b, bioSeed);
  expect(await next(b, /\/u\/mfa-webauthn-platform-enrollment/)).toBe(0);
  await b.page.locator("#za-passkey-button").click();
  expect(await next(b, /\/u\/mfa-webauthn-change-key-nickname/)).toBe(0);
  await expect(b.page.locator("#name")).toBeVisible();
  await b.page.fill("#name", "Journey7 device");
  await Promise.all([b.page.waitForNavigation(), b.page.locator("button[type=submit]").first().click()]);
  await confirmEnrollment(b);
  await finish(b, flow);
  expect((await methods(bio.user_id)).some((x) => x.type === "webauthn-platform")).toBe(true);
  await logout(b);
  flow = await start(b);
  await identify(b, bio.email);
  await passwordStep(b);
  if ((await next(b, /\/u\/mfa-webauthn-platform-challenge/, /\/u\/mfa-otp-challenge/, /\/u\/mfa\b/)) !== 0) {
    await b.page.locator("a[href*='action=another']").click().catch(() => {});
    await b.page.locator('button[name=factor][value="webauthn-platform"]').click();
    await next(b, /\/u\/mfa-webauthn-platform-challenge/);
  }
  await b.page.locator("#za-passkey-button").click();
  expect((await finish(b, flow)).claims.amr).toEqual(["mfa"]);
  await m.guardian.factors.set("webauthn-platform", { enabled: false });
  await m.guardian.factors.set("otp", { enabled: false });

  // Enrollment ticket with factor webauthn-roaming.
  await m.guardian.policies.set([]);
  const ticketUser = await newUser("journey7-ticket@e2e.local");
  const ticket = await api("guardian/enrollments/ticket", "POST", { user_id: ticketUser.user_id, send_mail: false, factor: "webauthn-roaming" });
  await secret(ticket.ticket_id, "ticket_id");
  const t = await profile(browser, usbUV);
  await t.page.goto(ticket.ticket_url);
  expect(await next(t, /\/u\/mfa-webauthn-roaming-enrollment/)).toBe(0);
  await t.page.locator("#za-passkey-button").click();
  expect(await next(t, /\/u\/mfa-webauthn-change-key-nickname/)).toBe(0);
  await t.page.fill("#name", "Ticket key");
  await Promise.all([t.page.waitForNavigation(), t.page.locator("button[type=submit]").first().click()]);
  await confirmEnrollment(t).catch(() => {});
  await until(async () => (await methods(ticketUser.user_id)).some((x) => x.type === "webauthn-roaming" && x.name === "Ticket key"), "ticket enrollment stored");

  // challengeWith({type: "webauthn-roaming"}) in post-login and in
  // password-reset-post-challenge.
  await api("tenants/settings", "PATCH", { customize_mfa_in_postlogin_action: true });
  await action(m, "post-login", `exports.onExecutePostLogin=async(event,api)=>{api.authentication.challengeWith({type:"webauthn-roaming"});};`);
  await api(`users/${encodeURIComponent(user.user_id)}/multifactor/actions/invalidate-remember-browser`, "POST", {});
  await logout(k);
  flow = await start(k);
  await identify(k, user.email);
  await passwordStep(k);
  expect(await next(k, /\/u\/mfa-webauthn-roaming-challenge/)).toBe(0);
  await k.page.locator("#za-passkey-button").click();
  expect((await finish(k, flow)).claims.amr).toEqual(["mfa"]);
  await unbind("post-login");
  await action(m, "password-reset-post-challenge", `exports.onExecutePostChallenge=async(event,api)=>{api.authentication.challengeWith({type:"webauthn-roaming"});};`);
  const reset = await api("tickets/password-change", "POST", { user_id: user.user_id });
  await secret(new URL(reset.ticket).searchParams.get("ticket") ?? reset.ticket, "reset ticket");
  await k.page.goto(reset.ticket);
  expect(await next(k, /\/u\/mfa-webauthn-roaming-challenge/)).toBe(0);
  await k.page.locator("#za-passkey-button").click();
  await expect(k.page.locator("#password")).toBeVisible();
  await unbind("password-reset-post-challenge");
  await api("tenants/settings", "PATCH", { customize_mfa_in_postlogin_action: false });
  await m.guardian.factors.set("webauthn-roaming", { enabled: false });
  await passkeyOptions({ progressive_enrollment_enabled: true });
  await settle();
  for (const p of [k, u, r, b, t]) await p.context.close();
  await opContext.close();
});

test("journey 12: an older plugin without webauthn.v1 keeps working; passkeys unavailable, options stored-only", async ({ browser }) => {
  test.setTimeout(180000);
  const host = "legacy.e2e.test";
  await ensurePasskeys(host);
  const conn = await connectionId(host);
  const options = (await api(`connections/${conn}`, "GET", undefined, host)).options;
  expect(options.authentication_methods.passkey.enabled).toBe(true);
  expect(options.passkey_options.challenge_ui).toBe("button");
  const user = await api("users", "POST", { connection: realm, email: "legacy-user@e2e.local", password, email_verified: true }, host);
  const s = await profileVia(browser, "http://127.0.0.1:9199", synced);
  let flow = await start(s, { host });
  await expect(s.page.locator("#username")).toBeVisible();
  await expect(s.page.locator("#za-passkey-button")).toHaveCount(0);
  await expect(s.page.locator("#za-webauthn")).toHaveCount(0);
  await identify(s, user.email);
  await passwordStep(s);
  expect((await finish(s, flow)).claims.sub).toBe(user.user_id);
  // Native endpoints answer 404 and Management passkey create 501.
  for (const path of ["/passkey/register", "/passkey/challenge"]) {
    const r = await fixtureFetch(`https://${host}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: "m33b-native", client_secret: "Plan33b-Native-Client-Secret-2026", realm, user_profile: { email: "legacy-native@e2e.local" } }) });
    expect(r.status, path).toBe(404);
  }
  const create = await mgmt(`users/${encodeURIComponent(user.user_id)}/authentication-methods`, "POST", softBody(softKey(host)), host);
  expect(create.status).toBe(501);
  expect(JSON.stringify(create.body)).toContain("webauthn_unavailable");
  // WebAuthn factors are not offered: with OTP and security keys enabled the
  // MFA step offers OTP only.
  await api("guardian/factors/otp", "PUT", { enabled: true }, host);
  await api("guardian/factors/webauthn-roaming", "PUT", { enabled: true }, host);
  await api("guardian/policies", "PUT", ["all-applications"], host);
  const t = await profileVia(browser, "http://127.0.0.1:9199", synced);
  flow = await start(t, { host });
  await identify(t, user.email);
  await passwordStep(t);
  await expect(t.page.locator("#mfa-secret, button[name=factor]").first()).toBeVisible();
  expect(t.page.url()).not.toMatch(/mfa-webauthn|mfa-detect/);
  await expect(t.page.locator('button[name=factor][value^="webauthn"]')).toHaveCount(0);
  await settle();
  await s.context.close();
  await t.context.close();
});
