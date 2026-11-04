import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { AuthClient, isMfaRequiredError } from "@auth0/auth0-auth-js";
import {
  origin,
  fixtureFetch,
  clientSecret,
  password,
  otpGrant,
  start,
  api,
  capture,
  secret,
  mailbox,
  mailCheckpoint,
  phoneCode,
  phoneCheckpoint,
  provider,
} from "./m34-node.mjs";
export async function raw(body, status = 200) {
  const r = await fixtureFetch(origin + "/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_id: "m34-password",
      client_secret: clientSecret,
      scope: "openid profile email",
      ...body,
    }),
  });
  const b = await r.json();
  assert.equal(r.status, status, `grant ${r.status} ${JSON.stringify(b)}`);
  await capture("token", b, [
    ...(b.mfa_token ? ["mfa_token"] : []),
    ...(b.recovery_code ? ["recovery_code"] : []),
  ]);
  return b;
}
export async function mfaCall(path, body, mt, status = 200) {
  const r = await fixtureFetch(origin + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(path === "/mfa/associate" ? { authorization: `Bearer ${mt}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const b = await r.json();
  assert.equal(r.status, status, `${path} ${r.status} ${JSON.stringify(b)}`);
  await capture(
    path === "/mfa/associate" ? "phone associate" : "phone challenge",
    b,
    [
      ...(b.oob_code ? ["oob_code"] : []),
      ...(b.recovery_codes ? ["recovery_codes"] : []),
    ],
  );
  return b;
}
async function grants() {
  assert.equal(
    JSON.parse(
      await readFile(
        new URL("../package.json", import.meta.resolve("@auth0/auth0-auth-js")),
      ),
    ).version,
    "1.16.1",
  );
  const auth = new AuthClient({
    domain: "sdk.e2e.test",
    clientId: "m34-password",
    clientSecret,
    customFetch: fixtureFetch,
  });
  const email = "authjs34@e2e.local";
  let before = await mailCheckpoint();
  await auth.passwordless.sendEmail({ email, send: "code" });
  const code = await mailbox(email, before);
  const tokens = await auth.getTokenByPasswordlessEmail({
    email,
    code,
    scope: "openid profile email",
  });
  assert.ok(tokens.accessToken);
  assert.ok(tokens.idToken);
  const reuse = await raw(
    { grant_type: otpGrant, realm: "email", username: email, otp: code },
    400,
  );
  assert.equal(reuse.error, "invalid_grant");
  before = await mailCheckpoint();
  await start({ connection: "email", email: "raw34@e2e.local", send: "code" });
  const c = await mailbox("raw34@e2e.local", before);
  assert.ok(
    (
      await raw({
        grant_type: otpGrant,
        realm: "email",
        username: "raw34@e2e.local",
        otp: c,
      })
    ).access_token,
  );
  await provider("twilio");
  let checkpoint = await phoneCheckpoint();
  const number = await secret("+14155553470", "phone number");
  await auth.passwordless.sendSms({ phoneNumber: number });
  const sms = await auth.getTokenByPasswordlessSms({
    phoneNumber: number,
    code: await phoneCode(number, checkpoint, "twilio_message"),
    scope: "openid profile",
  });
  assert.ok(sms.accessToken);
  await api("tenants/settings", "PATCH", {
    flags: { enforce_client_authentication_on_passwordless_start: true },
  });
  assert.equal(
    (await start({ connection: "email", email: "clientauth34@e2e.local" }, 401))
      .error,
    "invalid_client",
  );
  before = await mailCheckpoint();
  await start({
    connection: "email",
    email: "clientauth34@e2e.local",
    send: "code",
    client_secret: clientSecret,
  });
  await mailbox("clientauth34@e2e.local", before);
  await api("tenants/settings", "PATCH", {
    flags: { enforce_client_authentication_on_passwordless_start: false },
  });
  // Replacement codes share one persisted credential; concurrent redemption has one winner.
  const raceEmail = "race34@e2e.local";
  before = await mailCheckpoint();
  await start({ connection: "email", email: raceEmail, send: "code" });
  const oldCode = await mailbox(raceEmail, before);
  before = await mailCheckpoint();
  await start({ connection: "email", email: raceEmail, send: "code" });
  const latest = await mailbox(raceEmail, before);
  assert.equal(
    (
      await raw(
        {
          grant_type: otpGrant,
          realm: "email",
          username: raceEmail,
          otp: oldCode,
        },
        400,
      )
    ).error,
    "invalid_grant",
  );
  const raced = await Promise.all(
    [0, 1].map(() =>
      fixtureFetch(origin + "/oauth/token", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_id: "m34-password",
          client_secret: clientSecret,
          grant_type: otpGrant,
          realm: "email",
          username: raceEmail,
          otp: latest,
          scope: "openid",
        }),
      }),
    ),
  );
  assert.deepEqual(raced.map((r) => r.status).sort(), [200, 400]);
  for (const r of raced) await capture("token", await r.json());
  // MFA on a passwordless OTP grant must suspend token issuance in both clients.
  await api("guardian/policies", "PUT", ["all-applications"]);
  before = await mailCheckpoint();
  await start({ connection: "email", email, send: "code" });
  let mt;
  try {
    await auth.getTokenByPasswordlessEmail({
      email,
      code: await mailbox(email, before),
      scope: "openid",
    });
    assert.fail("MFA required");
  } catch (e) {
    assert.ok(isMfaRequiredError(e));
    mt = await secret(e.cause.mfa_token, "mfa_token");
  }
  checkpoint = await phoneCheckpoint();
  const mfaNumber = await secret("+14155553471", "phone number");
  const assoc = await mfaCall(
    "/mfa/associate",
    {
      authenticator_types: ["oob"],
      oob_channels: ["sms"],
      phone_number: mfaNumber,
    },
    mt,
  );
  let success = await raw({
    grant_type: "http://auth0.com/oauth/grant-type/mfa-oob",
    mfa_token: mt,
    oob_code: assoc.oob_code,
    binding_code: await phoneCode(mfaNumber, checkpoint, "twilio_message"),
  });
  assert.ok(success.access_token);
  assert.deepEqual(
    JSON.parse(Buffer.from(success.id_token.split(".")[1], "base64url")).amr,
    ["mfa"],
  );
  before = await mailCheckpoint();
  await start({ connection: "email", email, send: "code" });
  const pending = await raw(
    {
      grant_type: otpGrant,
      realm: "email",
      username: email,
      otp: await mailbox(email, before),
    },
    403,
  );
  assert.equal(pending.error, "mfa_required");
  mt = pending.mfa_token;
  const rr = await fixtureFetch(origin + "/mfa/authenticators", {
    headers: { authorization: `Bearer ${mt}` },
  });
  assert.equal(rr.status, 200);
  const methods = await rr.json();
  await capture("MFA authenticators", methods);
  const method = methods.find((x) => x.authenticator_type === "oob");
  assert.ok(method);
  // Voice uses a distinct per-number budget; proof travels over the fake Calls API.
  checkpoint = await phoneCheckpoint();
  const challenge = await mfaCall(
    "/mfa/challenge",
    {
      client_id: "m34-password",
      client_secret: clientSecret,
      mfa_token: mt,
      challenge_type: "oob",
      authenticator_id: method.id.replace(/^sms\|/, "voice|"),
    },
    mt,
  );
  success = await raw({
    grant_type: "http://auth0.com/oauth/grant-type/mfa-oob",
    mfa_token: mt,
    oob_code: challenge.oob_code,
    binding_code: await phoneCode(mfaNumber, checkpoint, "twilio_call"),
  });
  assert.ok(success.access_token);
  // SNS's lack of voice is explicit, not a silent fallback to text.
  await provider("sns");
  before = await mailCheckpoint();
  await start({
    connection: "email",
    email: "snsvoice34@e2e.local",
    send: "code",
  });
  const snsPending = await raw(
    {
      grant_type: otpGrant,
      realm: "email",
      username: "snsvoice34@e2e.local",
      otp: await mailbox("snsvoice34@e2e.local", before),
    },
    403,
  );
  await mfaCall(
    "/mfa/associate",
    {
      authenticator_types: ["oob"],
      oob_channels: ["voice"],
      phone_number: "+14155553472",
    },
    snsPending.mfa_token,
    400,
  );
  await api("guardian/policies", "PUT", []);
  await provider("twilio");
  console.log(
    "Plan34 pinned auth-js/raw OTP, client authentication, MFA SMS enrollment/voice challenge/SNS unsupported passed",
  );
}
if (process.argv[1] === import.meta.filename) await grants();
