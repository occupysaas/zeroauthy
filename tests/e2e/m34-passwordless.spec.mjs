import { test, expect } from "@playwright/test";
import { createHmac } from "node:crypto";
import { appendFile, readFile } from "node:fs/promises";
import { authorization, complete } from "./social/browser.mjs";
import {
  work,
  origin,
  password,
  operatorPassword,
  clientSecret,
  fixtureFetch,
  api,
  state,
  secret,
  mailbox,
  mailCheckpoint,
  emailBody,
  start,
  phoneCheckpoint,
  phoneCode,
  phoneRecords,
  provider,
  deploy,
  capture,
  until,
} from "./m34-node.mjs";
test.skip(!process.env.E2E_M34_WORK, "Run make e2e-passwordless");
test.use({ proxy: { server: "http://127.0.0.1:9198" }, trace: "off" });
async function contextFor(browser) {
  const ctx = await browser.newContext({
    proxy: { server: "http://127.0.0.1:9198" },
    ignoreHTTPSErrors: true,
  });
  await ctx.route(/^https:\/\/callback\.e2e\.test\//, (r) =>
    r.fulfill({ status: 200, body: "Plan34 local callback" }),
  );
  const pending = [];
  const page = await ctx.newPage();
  page.setDefaultTimeout(15000);
  page.setDefaultNavigationTimeout(20000);
  page.on("console", (m) =>
    pending.push(
      appendFile(
        `${work}/browser-console.jsonl`,
        JSON.stringify({ type: m.type(), text: m.text() }) + "\n",
      ),
    ),
  );
  return { ctx, page, flush: () => Promise.all(pending) };
}
const submit = (page) => page.locator("button[type=submit]").first().click();
async function begin(page, connection = "email", extra = {}) {
  const f = authorization({ client: "m34-spa", connection });
  const u = new URL(f.url);
  u.searchParams.set("prompt", "login");
  for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
  await page.goto(u.href);
  return f;
}
async function emailLogin(page, email) {
  const before = await mailCheckpoint();
  const f = await begin(page);
  await page.fill("#username", email);
  await submit(page);
  await expect(page.locator("#code")).toBeVisible();
  return { f, code: await mailbox(email, before) };
}
test("hosted email signup/existing user, wrong code, resend invalidation, real expiry and brute force block", async ({
  browser,
}) => {
  test.setTimeout(180000);
  const { ctx, page, flush } = await contextFor(browser);
  const { emailConnection } = await state();
  try {
    const email = "browser34@e2e.local";
    let flow = await emailLogin(page, email);
    await page.fill("#code", flow.code === "000000" ? "111111" : "000000");
    await submit(page);
    await expect(page.getByRole("alert")).toBeVisible();
    const before = await mailCheckpoint();
    await page.locator("button[value=resend]").click();
    const second = await mailbox(email, before);
    expect(second).not.toBe(flow.code);
    await page.fill("#code", flow.code);
    await submit(page);
    await expect(page.getByRole("alert")).toBeVisible();
    await page.fill("#code", second);
    await submit(page);
    const first = await complete(page, flow.f);
    expect(first.claims.sub).toMatch(/^email\|/);
    flow = await emailLogin(page, email);
    await page.fill("#code", flow.code);
    await submit(page);
    expect((await complete(page, flow.f)).claims.sub).toBe(first.claims.sub);
    await api(`connections/${emailConnection}`, "PATCH", {
      options: { totp: { time_step: 60, length: 6 } },
    });
    flow = await emailLogin(page, "expiry34@e2e.local");
    console.log("Plan34 browser stage: real 60-second email OTP expiry");
    await page.waitForTimeout(61000);
    await page.fill("#code", flow.code);
    await submit(page);
    await expect(page.getByRole("alert")).toBeVisible();
    expect(page.url()).toContain("/u/login-passwordless-email-code");
    await api(`connections/${emailConnection}`, "PATCH", {
      options: { totp: { time_step: 300, length: 6 } },
    });
    await api("attack-protection/brute-force-protection", "PATCH", {
      enabled: true,
      max_attempts: 3,
      shields: ["block"],
    });
    flow = await emailLogin(page, "blocked34@e2e.local");
    const wrong = flow.code === "123456" ? "654321" : "123456";
    for (let i = 0; i < 4; i++) {
      await page.fill("#code", wrong);
      const response = page.waitForResponse(
        (r) =>
          r.request().method() === "POST" &&
          r.url().includes("/u/login-passwordless-email-code"),
      );
      await submit(page);
      const r = await response;
      expect(r.status()).toBe(i < 3 ? 400 : 429);
    }
  } finally {
    await api(`connections/${emailConnection}`, "PATCH", {
      options: { totp: { time_step: 300, length: 6 } },
    });
    await api("attack-protection/brute-force-protection", "PATCH", {
      enabled: false,
    });
    await ctx.close();
    await flush();
  }
});
test("magic-link scanner GET preserves proof, real browser confirmation reaches callback, reuse fails", async ({
  browser,
}) => {
  const { ctx, page, flush } = await contextFor(browser);
  try {
    const email = "link34@e2e.local",
      before = await mailCheckpoint();
    await start({
      connection: "email",
      email,
      send: "link",
      authParams: {
        redirect_uri: "https://callback.e2e.test/",
        response_type: "code",
        scope: "openid email",
        state: "plan34-link-state",
      },
    });
    const body = (await emailBody(email, before))
      .replace(/=\r?\n/g, "")
      .replace(/=3D/g, "=");
    const match = body.match(
      /https:\/\/sdk\.e2e\.test\/passwordless\/verify_redirect[^\s"<>]+/,
    );
    expect(match).toBeTruthy();
    const link = match[0].replaceAll("&amp;", "&");
    await secret(
      new URL(link).searchParams.get("verification_code"),
      "link token",
    );
    const scanner = await fixtureFetch(link);
    expect(scanner.status).toBe(200);
    expect(await scanner.text()).toContain("state_token");
    await page.goto(link);
    await submit(page);
    await page.waitForURL(/^https:\/\/callback/);
    const callback = new URL(page.url());
    expect(callback.searchParams.get("state")).toBe("plan34-link-state");
    expect(callback.searchParams.get("code")).toBeTruthy();
    const redeemed = await fixtureFetch(origin + "/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: "m34-password",
        client_secret: clientSecret,
        redirect_uri: "https://callback.e2e.test/",
        code: callback.searchParams.get("code"),
      }),
    });
    expect(redeemed.status).toBe(200);
    await page.goto(link);
    await expect(page.locator("form")).toHaveCount(0);
    expect(new URL(page.url()).host).toBe("sdk.e2e.test");
  } finally {
    await ctx.close();
    await flush();
  }
});
test("hosted SMS Twilio, SNS, custom Action and gateway route to real local transports", async ({
  browser,
}) => {
  test.setTimeout(120000);
  const { ctx, page, flush } = await contextFor(browser);
  const { smsConnection } = await state();
  try {
    await deploy(
      "custom-phone-provider",
      `exports.onExecuteCustomPhoneProvider=async(event,api)=>{console.log('Plan34 phone privacy probe',event.notification.recipient,event.notification.code);const r=await fetch('http://127.0.0.1:9184/gateway',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({recipient:event.notification.recipient,body:event.notification.as_text})});if(!r.ok)throw Error('local gateway failed');};`,
    );
    for (const [i, name, kind] of [
      [0, "twilio", "twilio_message"],
      [1, "sns", "sns_publish"],
      [2, "custom", "gateway"],
      [3, "sms_gateway", "gateway"],
    ]) {
      if (name === "sms_gateway") {
        await api("tenants/settings", "PATCH", {
          phone_consolidated_experience: false,
        });
        await api(`connections/${smsConnection}`, "PATCH", {
          options: {
            provider: "sms_gateway",
            gateway_url: "https://gateway.e2e.test/gateway",
            gateway_authentication: {
              method: "bearer",
              secret: "Plan34-Gateway-Secret-2026",
              audience: "local-gateway",
            },
          },
        });
      } else {
        await provider(name);
        await api(`connections/${smsConnection}`, "PATCH", {
          options: { provider: "twilio" },
        });
      }
      const number = await secret(`+1415555340${i}`, "phone number"),
        before = await phoneCheckpoint();
      const f = await begin(page, "sms");
      await page.fill("#username", number);
      await submit(page);
      await expect(page.locator("#code")).toBeVisible();
      const delivered = await phoneCode(number, before, kind);
      if (name === "sms_gateway") {
        const record = (await phoneRecords())
          .slice(before)
          .find(
            (r) =>
              r.kind === "gateway" && JSON.parse(r.body).recipient === number,
          );
        expect(record.authorization).toMatch(/^Bearer /);
        const jwt = record.authorization.slice(7),
          [header, payload, signature] = jwt.split(".");
        expect(JSON.parse(Buffer.from(header, "base64url")).alg).toBe("HS256");
        expect(JSON.parse(Buffer.from(payload, "base64url")).aud).toBe(
          "local-gateway",
        );
        expect(signature).toBe(
          createHmac("sha256", "Plan34-Gateway-Secret-2026")
            .update(`${header}.${payload}`)
            .digest("base64url"),
        );
      }
      if (name === "twilio") await provider("sns"); // outstanding proofs survive a provider switch
      await page.fill("#code", delivered);
      await submit(page);
      expect((await complete(page, f)).claims.sub).toMatch(/^sms\|/);
    }
    await api("tenants/settings", "PATCH", {
      phone_consolidated_experience: true,
    });
    // Both provider and Action logs now carry actual sensitive inputs to scrub.
    await api(`connections/${smsConnection}`, "PATCH", {
      options: { provider: "twilio" },
    });
    await provider("twilio");
  } finally {
    await api("tenants/settings", "PATCH", {
      phone_consolidated_experience: true,
    });
    await ctx.close();
    await flush();
  }
});
test("hosted SMS MFA enrollment and challenge; passwordless primary login cannot bypass MFA", async ({
  browser,
}) => {
  test.setTimeout(90000);
  await provider("twilio");
  await api("guardian/policies", "PUT", ["all-applications"]);
  const { ctx, page, flush } = await contextFor(browser);
  try {
    let flow = await emailLogin(page, "hostedmfa34@e2e.local");
    await page.fill("#code", flow.code);
    await submit(page);
    await expect(page.locator("#phone_number")).toBeVisible();
    const before = await phoneCheckpoint(),
      number = await secret("+14155553420", "phone number");
    await page.fill("#phone_number", number);
    await page.selectOption("[name=method]", "sms");
    await submit(page);
    await page.fill("#code", await phoneCode(number, before, "twilio_message"));
    await submit(page);
    await expect(page.locator("#recovery-code")).toBeVisible();
    await secret(
      await page.locator("#recovery-code").innerText(),
      "recovery_code",
    );
    await page.locator("[name=ack]").check();
    await submit(page);
    expect((await complete(page, flow.f)).claims.amr).toEqual(["mfa"]);
    const checkpoint = await phoneCheckpoint();
    flow = await emailLogin(page, "hostedmfa34@e2e.local");
    await page.fill("#code", flow.code);
    await submit(page);
    await expect(page).toHaveURL(/mfa-sms-challenge/);
    await page.fill(
      "#code",
      await phoneCode(number, checkpoint, "twilio_message"),
    );
    await submit(page);
    expect((await complete(page, flow.f)).claims.amr).toEqual(["mfa"]);
  } finally {
    await api("guardian/policies", "PUT", []);
    await ctx.close();
    await flush();
  }
});
test("database phone signup verification, phone login and code-based phone password reset", async ({
  browser,
}) => {
  test.setTimeout(90000);
  await provider("twilio");
  const db = (await api("connections")).find(
    (c) => c.name === "Username-Password-Authentication",
  );
  await api(`connections/${db.id}`, "PATCH", {
    options: {
      attributes: {
        phone_number: {
          identifier: { active: true },
          signup: { status: "required" },
          verification: { active: true },
        },
      },
    },
  });
  const { ctx, page, flush } = await contextFor(browser);
  try {
    const number = await secret("+14155553430", "phone number");
    let checkpoint = await phoneCheckpoint(),
      f = await begin(page, db.name, { screen_hint: "signup" });
    await page.fill("#phone_number", number);
    await page.fill("#password", password);
    await submit(page);
    const code = await phoneCode(number, checkpoint, "twilio_message");
    await page.fill("#phone_code", code);
    await page.fill("#password", password);
    await submit(page);
    const created = await complete(page, f);
    expect(created.claims.sub).toMatch(/^auth0\|/);
    f = await begin(page, db.name);
    await page.fill("#username", number);
    await page.fill("#password", password);
    await submit(page);
    expect((await complete(page, f)).claims.sub).toBe(created.claims.sub);
    await begin(page, db.name);
    await page.locator('a[href*="reset-password/request"]').click();
    checkpoint = await phoneCheckpoint();
    await page.fill("#phone_number", number);
    await submit(page);
    await expect(page.locator("#phone_code")).toBeVisible();
    await page.fill(
      "#phone_code",
      await phoneCode(number, checkpoint, "twilio_message"),
    );
    await submit(page);
    await expect(page.locator("#password_confirm")).toBeVisible();
    const replacement = await secret(
      "Plan34-Replacement-Password-2026",
      "password",
    );
    await page.fill("#password", replacement);
    await page.fill("#password_confirm", replacement);
    await submit(page);
    f = await begin(page, db.name);
    await page.fill("#username", number);
    await page.fill("#password", replacement);
    await submit(page);
    expect((await complete(page, f)).claims.sub).toBe(created.claims.sub);
  } finally {
    await ctx.close();
    await flush();
  }
});
test("hosted country deny, per-number send budget and bot policy stop transport", async ({
  browser,
}) => {
  test.setTimeout(90000);
  const { ctx, page, flush } = await contextFor(browser);
  try {
    await api("tenants/settings", "PATCH", {
      country_codes: { mode: "deny", list: ["US"] },
    });
    let before = await phoneCheckpoint();
    await begin(page, "sms");
    await page.fill("#username", "+14155553450");
    await submit(page);
    await expect(page.getByRole("alert")).toBeVisible();
    expect(await phoneCheckpoint()).toBe(before);
    await api("tenants/settings", "PATCH", {
      country_codes: { mode: "deny", list: [] },
    });
    await begin(page, "sms");
    const number = await secret("+14155553451", "phone number");
    await page.fill("#username", number);
    await submit(page);
    await phoneCode(number, before);
    for (let i = 0; i < 9; i++)
      await page.locator("button[value=resend]").click();
    before = await phoneCheckpoint();
    await page.locator("button[value=resend]").click();
    await expect(page.getByRole("alert")).toBeVisible();
    expect(await phoneCheckpoint()).toBe(before);
    await api("attack-protection/bot-detection", "PATCH", {
      challenge_passwordless_policy: "always",
    });
    await begin(page, "sms");
    await expect(page.getByRole("alert")).toContainText(/unavailable/i);
    expect(await phoneCheckpoint()).toBe(before);
    await until(async () => {
      const logs = await api("logs?q=type%3Alimit_phone&per_page=100");
      return logs.some((l) => l.type === "limit_phone");
    }, "persisted limit_phone");
  } finally {
    await api("attack-protection/bot-detection", "PATCH", {
      challenge_passwordless_policy: "never",
    });
    await api("tenants/settings", "PATCH", {
      country_codes: { mode: "deny", list: [] },
    });
    await ctx.close();
    await flush();
  }
});
test("operator phone console responses and Action execution logs contain no cleartext secrets", async ({
  browser,
}) => {
  test.setTimeout(90000);
  const { ctx, page, flush } = await contextFor(browser),
    pending = [];
  try {
    await page.route("**/api/**", async (route) => {
      const r = await route.fetch({ maxRedirects: 0 });
      const body = await r.text();
      await appendFile(
        `${work}/browser-responses.jsonl`,
        JSON.stringify({
          path: new URL(route.request().url()).pathname,
          status: r.status(),
          body,
        }) + "\n",
      );
      await route.fulfill({ response: r });
    });
    const setup = (await readFile(`${work}/operator-setup.txt`, "utf8"))
      .trim()
      .split("\n")
      .at(-1);
    await page.goto(setup);
    await page.fill("#password", operatorPassword);
    await page.fill("#password_confirm", operatorPassword);
    await submit(page);
    await page.goto("https://system.e2e.test/admin/");
    await page.fill("#username", "operator34@e2e.local");
    await page.fill("#password", operatorPassword);
    await submit(page);
    await page.waitForURL(/\/admin\/t\//);
    await page.goto(
      "https://system.e2e.test/admin/t/passwordless/phone-providers",
    );
    await page.waitForLoadState("networkidle");
    // Capture the actual console execution endpoint (all Action console logs).
    const executionResponse = page.waitForResponse(
      (r) =>
        r.url().includes("/actions/executions") &&
        r.request().method() === "GET",
    );
    await page.goto(
      "https://system.e2e.test/admin/t/passwordless/actions-logs",
    );
    const executions = await executionResponse;
    expect(executions.status()).toBe(200);
    const executionBody = JSON.stringify(await executions.json());
    expect(executionBody).toContain("custom-phone-provider");
    expect(executionBody).toContain("Plan34 phone privacy probe");
    await page.waitForLoadState("networkidle");
  } finally {
    await ctx.close();
    await flush();
    await Promise.all(pending);
  }
});

test("passwordless sign-in waits for third-party consent before issuing a code", async ({
  browser,
}) => {
  const { ctx, page, flush } = await contextFor(browser);
  try {
    const client = await api("clients", "POST", {
      name: "Plan34 consent client",
      app_type: "spa",
      is_first_party: false,
      third_party_security_mode: "permissive",
      grant_types: ["authorization_code"],
      callbacks: ["https://callback.e2e.test/"],
    });
    const saved = await state();
    await api(`connections/${saved.emailConnection}`, "PATCH", {
      is_domain_connection: true,
    });
    await api(`connections/${saved.emailConnection}/clients`, "PATCH", [
      { client_id: client.client_id, status: true },
    ]);
    const flow = authorization({
        client: client.client_id,
        connection: "email",
      }),
      before = await mailCheckpoint();
    await page.goto(flow.url + "&prompt=login");
    await page.fill("#username", "consent34@e2e.local");
    await submit(page);
    await expect(page.locator("#code")).toBeVisible();
    await page.fill("#code", await mailbox("consent34@e2e.local", before));
    await submit(page);
    await expect(page).toHaveURL(/\/u\/consent/);
    await page.locator("button[value=accept]").click();
    expect((await complete(page, flow)).claims.aud).toBe(client.client_id);
  } finally {
    await ctx.close();
    await flush();
  }
});
