import { test, expect } from "@playwright/test";
import { appendFile, readFile } from "node:fs/promises";
import { authorization, complete } from "./social/browser.mjs";
import {
  work,
  password,
  operatorPassword,
  management,
  api,
  saveState,
  code,
  secret,
  capture,
  until,
} from "./m33-mfa-node.mjs";
test.skip(!process.env.E2E_M33_WORK, "Run make e2e-mfa");
test.use({ proxy: { server: "http://127.0.0.1:9198" }, trace: "off" });
test("SQLite journey first: signup QR, recovery acknowledgement, challenge, remember, invalidate, AMR, SSO and Actions", async ({
  browser,
}) => {
  test.setTimeout(300000);
  const m = await management();
  const context = await browser.newContext({
    proxy: { server: "http://127.0.0.1:9198" },
    ignoreHTTPSErrors: true,
  });
  await context.route(/^https:\/\/callback\.e2e\.test\//, (r) =>
    r.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>Plan33 callback</title>",
    }),
  );
  const p = await context.newPage(),
    pending = [];
  p.setDefaultNavigationTimeout(20000);
  p.setDefaultTimeout(15000);
  p.on("console", (msg) =>
    pending.push(
      appendFile(
        `${work}/browser-console.jsonl`,
        JSON.stringify({ type: msg.type(), text: msg.text() }) + "\n",
      ),
    ),
  );
  p.on("response", (r) => {
    if (new URL(r.url()).pathname.startsWith("/api/"))
      pending.push(
        (async () => {
          await appendFile(
            `${work}/browser-responses.jsonl`,
            JSON.stringify({
              url: r.url(),
              status: r.status(),
              body: await r.text(),
            }) + "\n",
          );
        })(),
      );
  });
  const email = "journey-mfa@e2e.local";
  async function submit() {
    await p.locator("button[type=submit]").first().click();
  }
  async function login(client = "m33-spa", extra = {}) {
    const f = authorization({
      client,
      connection: "Username-Password-Authentication",
    });
    const u = new URL(f.url);
    for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
    await p.goto(u.href);
    if (await p.locator("#username").isVisible()) {
      await p.fill("#username", email);
      await p.fill("#password", password);
      await submit();
    }
    return f;
  }
  async function logout() {
    await p.goto(
      "https://sdk.e2e.test/v2/logout?client_id=m33-spa&returnTo=https%3A%2F%2Fcallback.e2e.test%2F",
    );
  }
  let seed, recovery, firstRememberStep;
  try {
    const flow = authorization({
      client: "m33-spa",
      connection: "Username-Password-Authentication",
    });
    const start = new URL(flow.url);
    start.searchParams.set("screen_hint", "signup");
    await p.goto(start.href);
    await p.fill("#email", email);
    await p.fill("#password", password);
    await submit();
    await expect(p.locator("#mfa-secret")).toBeVisible();
    seed = await secret(
      await p.locator("#mfa-secret").innerText(),
      "TOTP seed",
    );
    await expect(p.locator("svg")).toBeVisible();
    await expect(p.locator("body")).not.toContainText("Security key");
    await p.fill("#code", await code(seed));
    await submit();
    recovery = await secret(
      await p.locator("#recovery-code").innerText(),
      "recovery_code",
    );
    expect(recovery).toMatch(/^[A-Z0-9]{24}$/);
    await expect(p.locator("[name=ack]")).toBeVisible();
    await p.locator("[name=ack]").check();
    await submit();
    expect((await complete(p, flow)).claims.amr).toEqual(["mfa"]);
    const users = await api(
        `users-by-email?email=${encodeURIComponent(email)}`,
      ),
      uid = users[0].user_id;
    await saveState({ uid, email, seed, recovery });
    await logout();
    let f = await login();
    await expect(p.locator("#code")).toBeVisible();
    await p.locator("[name=remember]").check();
    firstRememberStep = Math.floor(Date.now() / 30000) + 1;
    await p.fill("#code", await code(seed, firstRememberStep));
    await submit();
    expect((await complete(p, f)).claims.amr).toEqual(["mfa"]);
    for (const cookie of await context.cookies())
      if (cookie.name.startsWith("za_mfa_"))
        await secret(cookie.value, "MFA browser cookie");
    await logout();
    f = await login();
    // A remembered browser permits this fresh session without a new proof.
    await complete(p, f);
    await expect(p.locator("#code")).toHaveCount(0);
    await api(
      `users/${encodeURIComponent(uid)}/multifactor/actions/invalidate-remember-browser`,
      "POST",
      {},
    );
    await logout();
    f = await login();
    await expect(p.locator("#code")).toBeVisible();
    // Recovery is single-use, replacement must be acknowledged before OAuth resumes.
    await p
      .getByRole("link")
      .filter({ hasText: /another/i })
      .click();
    await p.locator('button[value="recovery-code"]').click();
    await p.fill("#code", recovery);
    await submit();
    const replacement = await secret(
      await p.locator("#recovery-code").innerText(),
      "recovery_code",
    );
    expect(replacement).not.toBe(recovery);
    await p.locator("[name=ack]").check();
    await submit();
    expect((await complete(p, f)).claims.amr).toEqual(["mfa"]);
    // Establish non-MFA SSO, then change policy before the second application.
    await m.guardian.policies.set([]);
    await logout();
    f = await login();
    expect((await complete(p, f)).claims.amr).toBeUndefined();
    await m.guardian.policies.set(["all-applications"]);
    const silent = authorization({
      client: "m33-second",
      connection: "Username-Password-Authentication",
    });
    await p.goto(silent.url + "&prompt=none");
    await p.waitForURL(/^https:\/\/callback/);
    expect(new URL(p.url()).searchParams.get("error")).toBe(
      "interaction_required",
    );
    await login("m33-second");
    await expect(p.locator("#code")).toBeVisible();
    // Actions are deployed and bound through real Management APIs.
    async function action(body) {
      await api("actions/triggers/post-login/bindings", "PATCH", {
        bindings: [],
      });
      const a = await m.actions.create({
        name: `Plan33 ${Date.now()}`,
        supported_triggers: [{ id: "post-login", version: "v3" }],
        runtime: "node22",
        code: `exports.onExecutePostLogin=async(event,api)=>{if(!event.user.enrolledFactors.some(f=>f.type==='otp'))throw Error('missing enrolledFactors');${body}};`,
      });
      await until(async () => {
        const v = await m.actions.get(a.id);
        expect(v.status).not.toBe("failed");
        return v.status === "built";
      }, "Action build");
      await m.actions.deploy(a.id);
      await api("actions/triggers/post-login/bindings", "PATCH", {
        bindings: [
          { ref: { type: "action_id", value: a.id }, display_name: a.name },
        ],
      });
    }
    await m.guardian.policies.set([]);
    await action('api.multifactor.enable("any");');
    await logout();
    await login();
    await expect(p.locator("#code")).toBeVisible();
    await m.guardian.policies.set(["all-applications"]);
    await action('api.multifactor.enable("none");');
    await logout();
    f = await login();
    expect((await complete(p, f)).claims.amr).toBeUndefined();
    await api("actions/triggers/post-login/bindings", "PATCH", {
      bindings: [],
    });
    await logout();
    f = await login();
    await expect(p.locator("#code")).toBeVisible();
    await until(
      () => Math.floor(Date.now() / 30000) > firstRememberStep - 1,
      "fresh independent TOTP step",
      65000,
    );
    await p.locator("[name=remember]").check();
    await p.fill("#code", await code(seed, Math.floor(Date.now() / 30000) + 1));
    await submit();
    expect((await complete(p, f)).claims.amr).toEqual(["mfa"]);
    await api("tenants/settings", "PATCH", {
      customize_mfa_in_postlogin_action: true,
    });
    await action('api.authentication.challengeWith({type:"otp"});');
    await login();
    await expect(p.locator("#code")).toBeVisible();
    await api("actions/triggers/post-login/bindings", "PATCH", {
      bindings: [],
    });
    await m.guardian.policies.set(["all-applications"]);
    // Real operator UI: a pending one-time recovery response is discarded after
    // leaving the MFA tab; no mocked response or client is involved.
    const operator = await browser.newContext({
      proxy: { server: "http://127.0.0.1:9198" },
      ignoreHTTPSErrors: true,
    });
    const op = await operator.newPage();
    op.setDefaultNavigationTimeout(20000);
    op.setDefaultTimeout(15000);
    // Read the real upstream body before delivering it to a page that may
    // immediately navigate. No synthetic response or mocked client is used.
    await op.route("**/api/**", async (route) => {
      const response = await route.fetch({ maxRedirects: 0 });
      const path = new URL(route.request().url()).pathname;
      const body = await response.text();
      let value;
      try {
        value = JSON.parse(body);
      } catch {
        value = body;
      }
      await capture(
        "console " + route.request().method() + " " + path,
        value,
        route.request().method() === "POST" &&
          path.endsWith("/recovery-code-regeneration")
          ? ["recovery_code"]
          : [],
      );
      await appendFile(
        `${work}/browser-responses.jsonl`,
        JSON.stringify({
          path,
          status: response.status(),
          capturedIn: "responses.jsonl",
        }) + "\n",
      );
      await route.fulfill({ response });
    });
    op.on("console", (msg) =>
      pending.push(
        appendFile(
          `${work}/browser-console.jsonl`,
          JSON.stringify({ type: msg.type(), text: msg.text() }) + "\n",
        ),
      ),
    );
    const setup = (await readFile(`${work}/operator-setup.txt`, "utf8"))
      .trim()
      .split("\n")
      .at(-1);
    await op.goto(setup);
    await op.fill("#password", operatorPassword);
    await op.fill("#password_confirm", operatorPassword);
    await op.click("button[type=submit]");
    await op.goto("https://system.e2e.test/admin/");
    await op.fill("#username", "operator33@e2e.local");
    await op.fill("#password", operatorPassword);
    await op.click("button[type=submit]");
    await op.waitForURL(/\/admin\/t\//);
    await op.goto(
      `https://system.e2e.test/admin/t/mfa/users/${encodeURIComponent(uid)}`,
    );
    await op.getByRole("tab", { name: /multi.factor|mfa/i }).click();
    await expect(op.locator("#regenerate-recovery")).toBeVisible();
    await op.locator("#regenerate-recovery").click();
    await op.getByRole("dialog").locator("button[type=submit]").click();
    const shown = await secret(
      await op.locator("[data-recovery-code]").innerText(),
      "recovery_code",
    );
    await op.locator("#dismiss-recovery").click();
    await expect(op.locator("body")).not.toContainText(shown);
    let release;
    const held = new Promise((r) => {
      release = r;
    });
    let stale;
    await op.route("**/recovery-code-regeneration", async (route) => {
      const response = await route.fetch();
      const value = await response.json();
      stale = await secret(value.recovery_code, "recovery_code");
      await capture("console POST recovery-code-regeneration delayed", value, [
        "recovery_code",
      ]);
      await held;
      await route.fulfill({ response });
    });
    await op.locator("#regenerate-recovery").click();
    await op.getByRole("dialog").locator("button[type=submit]").click();
    await until(() => stale, "genuine delayed regeneration response", 15000);
    // Dismiss the confirmation while its genuine request is still in flight,
    // then leave the component through the accessible tab controls.
    await op
      .getByRole("dialog")
      .getByRole("button", { name: "Cancel", exact: true })
      .click();
    await op.getByRole("tab", { name: "Details", exact: true }).click();
    const released = op.waitForResponse((r) =>
      new URL(r.url()).pathname.endsWith("/recovery-code-regeneration"),
    );
    release();
    await released;
    await expect(op.locator("body")).not.toContainText(stale);
    await op.getByRole("tab", { name: /multi.factor|mfa/i }).click();
    await expect(op.locator("body")).not.toContainText(stale);
    await op.reload();
    await expect(op.locator("body")).not.toContainText(shown);
    await expect(op.locator("body")).not.toContainText(stale);
    // Let real API captures finish before disposing their request context.
    await op.waitForLoadState("networkidle");
    await Promise.all(pending);
    await operator.close();
  } finally {
    await context.close();
    await Promise.all(pending);
  }
});

test("verified email enrollment arrives at the configured mailbox and gates browser tokens", async ({
  browser,
}) => {
  test.setTimeout(90000);
  const m = await management();
  await m.guardian.factors.set("otp", { enabled: false });
  await m.guardian.factors.set("email", { enabled: true });
  const email = "browser-email-mfa@e2e.local";
  await m.users.create({
    connection: "Username-Password-Authentication",
    email,
    password,
    email_verified: true,
  });
  const context = await browser.newContext({
    proxy: { server: "http://127.0.0.1:9198" },
    ignoreHTTPSErrors: true,
  });
  await context.route(/^https:\/\/callback\.e2e\.test\//, (r) =>
    r.fulfill({ status: 200, body: "Plan33 email callback" }),
  );
  const page = await context.newPage(),
    pending = [];
  page.on("console", (msg) =>
    pending.push(
      appendFile(
        `${work}/browser-console.jsonl`,
        JSON.stringify({ type: msg.type(), text: msg.text() }) + "\n",
      ),
    ),
  );
  try {
    const f = authorization({
      client: "m33-spa",
      connection: "Username-Password-Authentication",
    });
    await page.goto(f.url);
    await page.fill("#username", email);
    await page.fill("#password", password);
    await page.locator("button[type=submit]").first().click();
    await expect(page.locator("#code")).toBeVisible();
    expect(new URL(page.url()).host).toBe("sdk.e2e.test");
    const { mailbox } = await import("./m33-mfa-node.mjs");
    await page.fill("#code", await mailbox(email));
    await page.locator("button[type=submit]").first().click();
    const recovery = await secret(
      await page.locator("#recovery-code").innerText(),
      "recovery_code",
    );
    expect(recovery).toMatch(/^[A-Z0-9]{24}$/);
    await page.locator("[name=ack]").check();
    await page.locator("button[type=submit]").first().click();
    expect((await complete(page, f)).claims.amr).toEqual(["mfa"]);
  } finally {
    await context.close();
    await Promise.all(pending);
    await m.guardian.factors.set("otp", { enabled: true });
    await m.guardian.factors.set("email", { enabled: false });
  }
});
