// Plan 35 browser lane: a JAR-required application signs in through the
// hosted login with a signed request object (GET /authorize) and with a
// signed PAR push, and the code and refresh token are redeemed by the pinned
// auth-js with private_key_jwt. The console adds and removes a key and lists
// the token exchange profile.
import { test, expect } from "@playwright/test";
import { appendFile, readFile } from "node:fs/promises";
import {
  work, origin, redirect, password, operatorPassword, API, ASSERTION_TYPE,
  state, saveState, capture, fixtureFetch, redactText, requestObject, assertion, pkce, decode, authClient, api,
} from "./m35-node.mjs";

test.skip(!process.env.E2E_M35_WORK, "Run make e2e-client-auth");
test.use({ proxy: { server: "http://127.0.0.1:9198" }, trace: "off" });

const pending = [];
async function contextFor(browser) {
  const ctx = await browser.newContext({ proxy: { server: "http://127.0.0.1:9198" }, ignoreHTTPSErrors: true });
  await ctx.route(/^https:\/\/callback\.e2e\.test\//, (r) => r.fulfill({ status: 200, body: "Plan35 local callback" }));
  const page = await ctx.newPage();
  page.setDefaultTimeout(15000);
  page.setDefaultNavigationTimeout(20000);
  page.on("console", (m) => pending.push(appendFile(`${work}/browser-console.jsonl`, JSON.stringify({ type: m.type(), text: m.text() }) + "\n")));
  return { ctx, page };
}
const callback = (page) => page.waitForURL((u) => u.href.startsWith(redirect));
async function login(page) {
  await page.fill("#username", "jar35@e2e.local");
  await page.fill("#password", password);
  await page.locator('form[action="/u/login"] button[type=submit]').click();
}
// An authorize request that must be refused before any login: the error
// comes back to the registered redirect URI, or, when the redirect URI only
// lives inside an object that failed verification, an error page shows it.
const pageText = { invalid_request: /request/i, invalid_request_object: /request object is invalid/ };
async function refused(page, url, error) {
  await page.goto(url);
  const u = new URL(page.url());
  if (u.href.startsWith(redirect)) {
    expect(u.searchParams.get("code")).toBeNull();
    expect(u.searchParams.get("error")).toBe(error);
  } else {
    await expect(page.locator("#username")).toHaveCount(0);
    await expect(page.getByRole("alert")).toBeVisible();
    expect(await page.content()).toMatch(pageText[error]);
  }
}

test("JAR required: signed authorize, replay and bad key refused, signed PAR push, auth-js code and refresh with private_key_jwt", async ({ browser }) => {
  test.setTimeout(120000);
  const st = await state();
  const web = authClient("m35-web", { clientAssertionSigningKey: st.keys.webAuth.pkcs8, clientAssertionSigningAlg: "PS256" });
  const { ctx, page } = await contextFor(browser);
  try {
    const plain = new URLSearchParams({ client_id: "m35-web", response_type: "code", redirect_uri: redirect, scope: "openid", state: "plan35-plain" });
    await refused(page, `${origin}/authorize?${plain}`, "invalid_request");
    // auth-js pushes an unsigned PAR (authenticated with private_key_jwt):
    // the application requires signed requests, so the push is refused.
    await expect(web.buildAuthorizationUrl({ pushedAuthorizationRequests: true, authorizationParams: { redirect_uri: redirect, scope: "openid" } })).rejects.toThrow();

    // A signed request object on GET /authorize. No state or nonce: auth-js
    // redeems the code without expecting them.
    const p1 = pkce();
    const params = { response_type: "code", redirect_uri: redirect, scope: "openid offline_access read:things", audience: API, code_challenge: p1.challenge, code_challenge_method: "S256", prompt: "login" };
    const signed = await requestObject("m35-web", params, st.keys.webJar.pkcs8);
    await page.goto(`${origin}/authorize?${new URLSearchParams({ client_id: "m35-web", request: signed })}`);
    await login(page);
    await callback(page);
    const tokens = await web.getTokenByCode(new URL(page.url()), { codeVerifier: p1.verifier });
    await capture("JAR code redeemed", tokens);
    expect(decode(tokens.accessToken).claims.aud).toContain(API);
    expect(tokens.refreshToken).toBeTruthy();
    const refreshed = await web.getTokenByRefreshToken({ refreshToken: tokens.refreshToken });
    expect(decode(refreshed.accessToken).claims.sub).toBe(decode(tokens.accessToken).claims.sub);

    // The same object again: its jti is spent.
    await refused(page, `${origin}/authorize?${new URLSearchParams({ client_id: "m35-web", request: signed })}`, "invalid_request_object");
    // Signed with the private_key_jwt key, which is not a signed-request key.
    const wrongKey = await requestObject("m35-web", { ...params, code_challenge: pkce().challenge }, st.keys.webAuth.pkcs8, { alg: "PS256" });
    await refused(page, `${origin}/authorize?${new URLSearchParams({ client_id: "m35-web", request: wrongKey })}`, "invalid_request_object");

    // A signed PAR push, authenticated with a hand-built PS256 assertion.
    const p2 = pkce();
    const pushed = await requestObject("m35-web", { ...params, code_challenge: p2.challenge }, st.keys.webJar.pkcs8, { typ: "JWT" });
    const r = await fixtureFetch(`${origin}/oauth/par`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: "m35-web", client_assertion_type: ASSERTION_TYPE, client_assertion: await assertion("m35-web", st.keys.webAuth.pkcs8, { alg: "PS256", kid: "plan35-web-auth-key" }), request: pushed }).toString(),
    });
    const par = await r.json();
    await capture("PAR signed push", par);
    expect(r.status, JSON.stringify(par)).toBe(201);
    expect(par.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    await page.goto(`${origin}/authorize?${new URLSearchParams({ client_id: "m35-web", request_uri: par.request_uri })}`);
    await login(page);
    await callback(page);
    const viaPar = await web.getTokenByCode(new URL(page.url()), { codeVerifier: p2.verifier });
    expect(decode(viaPar.accessToken).claims.azp).toBe("m35-web");
  } finally {
    await ctx.close();
    await Promise.all(pending);
  }
});

async function operator(browser) {
  const context = await browser.newContext({ proxy: { server: "http://127.0.0.1:9198" }, ignoreHTTPSErrors: true });
  const op = await context.newPage();
  op.setDefaultNavigationTimeout(20000);
  op.setDefaultTimeout(15000);
  // Every console API response is captured for the audit (documented
  // returned secrets replaced, as in our other captures).
  await op.route("**/api/**", async (route) => {
    const response = await route.fetch({ maxRedirects: 0 });
    const body = await response.text();
    pending.push(appendFile(`${work}/browser-responses.jsonl`, JSON.stringify({ method: route.request().method(), url: route.request().url(), status: response.status(), body: redactText(body) }) + "\n"));
    await route.fulfill({ response, body });
  });
  op.on("console", (msg) => pending.push(appendFile(`${work}/browser-console.jsonl`, JSON.stringify({ type: msg.type(), text: msg.text() }) + "\n")));
  const st = await state();
  if (!st.operatorReady) {
    const setup = (await readFile(`${work}/operator-setup.txt`, "utf8")).trim().split("\n").at(-1);
    await op.goto(setup);
    await op.fill("#password", operatorPassword);
    await op.fill("#password_confirm", operatorPassword);
    await Promise.all([op.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/u/reset-password"), op.press("#password_confirm", "Enter")]);
    await saveState({ operatorReady: true });
  }
  await op.goto("https://system.e2e.test/admin/");
  await op.fill("#username", "operator35@e2e.local");
  await op.fill("#password", operatorPassword);
  await op.press("#password", "Enter");
  await op.waitForURL(/\/admin\/t\//);
  return { context, op };
}

test("console: add and remove a key, list keys and token exchange profiles", async ({ browser }) => {
  test.setTimeout(90000);
  const st = await state();
  const { context, op } = await operator(browser);
  try {
    await op.goto("https://system.e2e.test/admin/t/sdk/applications/m35-web");
    await op.getByRole("tab", { name: "Credentials" }).click();
    await expect(op.getByTestId("credential")).toHaveCount(2);
    await expect(op.getByTestId("credential").filter({ hasText: "plan35-web-auth-key" })).toContainText("PS256");
    await expect(op.getByTestId("cred-full")).toBeVisible();

    await op.goto("https://system.e2e.test/admin/t/sdk/applications/m35-bridge");
    await op.getByRole("tab", { name: "Credentials" }).click();
    await expect(op.getByTestId("cred-empty")).toBeVisible();
    await op.selectOption("#cred-alg", "RS384");
    await op.fill("#cred-name", "console-key");
    await op.fill("#cred-pem", st.keys.consoleKey.spki);
    await op.getByRole("button", { name: "Add key" }).click();
    await expect(op.getByTestId("credential")).toHaveCount(1);
    await expect(op.getByTestId("credential")).toContainText("RS384");
    const stored = await api("clients/m35-bridge/credentials");
    expect(stored.map((c) => [c.name, c.alg])).toEqual([["console-key", "RS384"]]);
    await op.getByRole("button", { name: "Remove console-key" }).click();
    await op.getByRole("dialog").getByRole("button", { name: "Remove" }).click();
    await expect(op.getByTestId("cred-empty")).toBeVisible();
    expect(await api("clients/m35-bridge/credentials")).toEqual([]);

    await op.goto("https://system.e2e.test/admin/t/sdk/actions/token-exchange-profiles");
    await expect(op.getByText("Plan35 legacy tokens")).toBeVisible();
    await expect(op.getByText("urn:plan35:legacy-token")).toBeVisible();
  } finally {
    await context.close();
    await Promise.all(pending);
  }
});
