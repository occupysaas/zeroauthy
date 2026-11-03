import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { AuthClient, isMfaRequiredError } from "@auth0/auth0-auth-js";
import {
  origin,
  work,
  password,
  clientSecret,
  fixtureFetch,
  management,
  api,
  code,
  secret,
  capture,
  mailbox,
  mailCheckpoint,
  totp,
  until,
} from "./m33-mfa-node.mjs";
const grant = (factor) => `http://auth0.com/oauth/grant-type/mfa-${factor}`;
export async function raw(body, expected = 200, allowed = []) {
  const r = await fixtureFetch(`${origin}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_id: "m33-password",
      client_secret: clientSecret,
      ...body,
    }),
  });
  const b = await r.json();
  assert.equal(r.status, expected, `token ${r.status}: ${JSON.stringify(b)}`);
  await capture("raw token", b, allowed);
  return b;
}
async function pending(email) {
  const b = await raw(
    {
      grant_type: "password",
      username: email,
      password,
      scope: "openid profile email",
    },
    403,
    ["mfa_token"],
  );
  assert.equal(b.error, "mfa_required");
  return b.mfa_token;
}
const call = async (path, body, mfa) => {
  const r = await fixtureFetch(`${origin}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(mfa ? { authorization: `Bearer ${mfa}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const b = await r.json();
  assert.equal(r.status, 200, `${path}: ${r.status} ${JSON.stringify(b)}`);
  await capture(path, b, [
    "secret",
    "barcode_uri",
    "recovery_codes",
    "oob_code",
  ]);
  return b;
};
async function grants() {
  assert.equal(
    JSON.parse(
      await readFile(
        new URL("../package.json", import.meta.resolve("@auth0/auth0-auth-js")),
      ),
    ).version,
    "1.16.1",
  );
  assert.equal(
    totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1),
    "287082",
    "RFC 6238 SHA1 t=59 six digits",
  );
  const m = await management();
  await m.guardian.policies.set(["all-applications"]);
  await m.guardian.factors.set("otp", { enabled: true });
  const email = "grants-otp@e2e.local";
  await m.users.create({
    connection: "Username-Password-Authentication",
    email,
    password,
    email_verified: true,
  });
  const auth = new AuthClient({
    domain: "sdk.e2e.test",
    clientId: "m33-password",
    clientSecret,
    customFetch: fixtureFetch,
  });
  let mt;
  try {
    await auth.getTokenByPassword({
      username: email,
      password,
      scope: "openid profile email",
    });
    assert.fail("MFA required");
  } catch (e) {
    assert.ok(isMfaRequiredError(e));
    mt = await secret(e.cause.mfa_token, "mfa_token");
  }
  const enrollment = await auth.mfa.enrollAuthenticator({
    authenticatorTypes: ["otp"],
    mfaToken: mt,
  });
  await capture("SDK associate", enrollment, [
    "secret",
    "barcodeUri",
    "recoveryCodes",
  ]);
  await secret(enrollment.secret, "TOTP seed");
  for (const recovery of enrollment.recoveryCodes ?? [])
    await secret(recovery, "recovery_code");
  const proof = await code(enrollment.secret);
  const tokens = await auth.mfa.verify({
    factorType: "otp",
    mfaToken: mt,
    otp: proof,
  });
  assert.ok(tokens.accessToken);
  assert.deepEqual(
    JSON.parse(Buffer.from(tokens.idToken.split(".")[1], "base64url")).amr,
    ["mfa"],
  );
  const retry = await raw(
    { grant_type: grant("otp"), mfa_token: mt, otp: proof },
    400,
  );
  assert.equal(retry.error, "invalid_grant");
  const next = await pending(email);
  const other = await raw(
    {
      client_id: "m33-other",
      grant_type: grant("otp"),
      mfa_token: next,
      otp: proof,
    },
    400,
  );
  assert.equal(other.error, "invalid_grant");
  const authenticators = await auth.mfa.listAuthenticators({ mfaToken: next });
  await capture("SDK authenticators", authenticators);
  assert.ok(authenticators.some((a) => a.authenticatorType === "otp"));
  const challenge = await auth.mfa.challengeAuthenticator({
    challengeType: "otp",
    mfaToken: next,
  });
  await capture("SDK challenge", challenge);
  const recovery = enrollment.recoveryCodes[0];
  const recovered = await raw(
    {
      grant_type: grant("recovery-code"),
      mfa_token: next,
      recovery_code: recovery,
    },
    200,
    ["recovery_code"],
  );
  assert.match(recovered.recovery_code, /^[A-Z0-9]{24}$/);
  assert.notEqual(recovered.recovery_code, recovery);
  const old = await raw(
    {
      grant_type: grant("recovery-code"),
      mfa_token: await pending(email),
      recovery_code: recovery,
    },
    400,
  );
  assert.equal(old.error, "invalid_grant");
  // The raw client independently exercises enrollment and successful OTP grant.
  const rawEmail = "grants-raw-otp@e2e.local";
  const rawUser = await m.users.create({
    connection: "Username-Password-Authentication",
    email: rawEmail,
    password,
    email_verified: true,
  });
  const rawPending = await pending(rawEmail);
  const rawEnrollment = await call(
    "/mfa/associate",
    { authenticator_types: ["otp"] },
    rawPending,
  );
  const rawSuccess = await raw({
    grant_type: grant("otp"),
    mfa_token: rawPending,
    otp: await code(rawEnrollment.secret),
  });
  assert.ok(rawSuccess.access_token);
  assert.deepEqual(
    JSON.parse(Buffer.from(rawSuccess.id_token.split(".")[1], "base64url")).amr,
    ["mfa"],
  );
  // Email uses the configured tenant SMTP transport and a real pinned SDK verifier.
  await m.guardian.factors.set("otp", { enabled: false });
  await m.guardian.factors.set("email", { enabled: true });
  const e = "grants-email@e2e.local";
  await m.users.create({
    connection: "Username-Password-Authentication",
    email: e,
    password,
    email_verified: true,
  });
  const et = await pending(e);
  const firstEmailSent = Date.now();
  const firstMailbox = await mailCheckpoint();
  const associated = await call(
    "/mfa/associate",
    { authenticator_types: ["oob"], oob_channels: ["email"], email: e },
    et,
  );
  const emailCode = await mailbox(e, firstMailbox);
  const verified = await auth.mfa.verify({
    factorType: "oob",
    mfaToken: et,
    oobCode: associated.oob_code,
    bindingCode: emailCode,
  });
  assert.ok(verified.accessToken);
  assert.match(
    verified.recoveryCode,
    /^[A-Z0-9]{24}$/,
    "first email enrollment returns its new one-time recovery code",
  );
  await secret(verified.recoveryCode, "recovery_code");
  // A later login challenges the confirmed email method, rather than associating again.
  await until(
    () => Date.now() >= firstEmailSent + 31000,
    "documented email resend window",
    33000,
  );
  const emailPending = await pending(e);
  const emailMethods = await auth.mfa.listAuthenticators({
    mfaToken: emailPending,
  });
  const method = emailMethods.find((a) => a.authenticatorType === "oob");
  assert.ok(method);
  const secondMailbox = await mailCheckpoint();
  const emailChallenge = await auth.mfa.challengeAuthenticator({
    mfaToken: emailPending,
    authenticatorId: method.id,
    challengeType: "oob",
  });
  await capture("SDK email challenge", emailChallenge, ["oobCode"]);
  const emailTokens = await raw({
    grant_type: grant("oob"),
    mfa_token: emailPending,
    oob_code: emailChallenge.oobCode,
    binding_code: await mailbox(e, secondMailbox),
  });
  assert.ok(emailTokens.access_token);
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.factors.set("email", { enabled: false });
  // Ten wrong OTP proofs share the persisted throttle across pending tokens.
  const throttled = await pending(rawEmail);
  const current = Math.floor(Date.now() / 30000);
  const valid = new Set(
    [-1, 0, 1].map((d) => totp(rawEnrollment.secret, current + d)),
  );
  const wrong = valid.has("834927") ? "483792" : "834927";
  await secret(wrong, "wrong OTP");
  for (let i = 0; i <= 10; i++) {
    const r = await raw(
      { grant_type: grant("otp"), mfa_token: throttled, otp: wrong },
      i === 10 ? 429 : 400,
    );
    if (i === 10) assert.equal(r.error, "too_many_attempts");
  }
  await until(async () => {
    const logs = await api(
      "logs?q=" +
        encodeURIComponent(
          `type:gd_otp_rate_limit_exceed AND user_id:"${rawUser.user_id}"`,
        ) +
        "&per_page=100",
    );
    return logs.some((l) => l.type === "gd_otp_rate_limit_exceed");
  }, "persisted MFA throttle log");
  // Actual ten-minute expiry, without a test clock or database mutation. The
  // dedicated token belongs to a fresh user so proof throttling is irrelevant.
  const exp = "grants-expiry@e2e.local";
  await m.users.create({
    connection: "Username-Password-Authentication",
    email: exp,
    password,
    email_verified: true,
  });
  const expires = await pending(exp);
  await writeFile(
    `${work}/expiry-stage.json`,
    JSON.stringify({
      started: new Date().toISOString(),
      waitMilliseconds: 601000,
    }),
  );
  console.log(
    "Plan33 grants stage: waiting for the real 10-minute mfa_token expiry",
  );
  await new Promise((resolve) => setTimeout(resolve, 601000));
  const expired = await raw(
    { grant_type: grant("otp"), mfa_token: expires, otp: "123456" },
    400,
  );
  assert.equal(expired.error, "invalid_grant");
  console.log(
    "Plan33 pinned auth-js/raw OTP/email/recovery, token reuse/client binding/real expiry/throttle passed",
  );
}
if (process.argv[1] === import.meta.filename) await grants();
