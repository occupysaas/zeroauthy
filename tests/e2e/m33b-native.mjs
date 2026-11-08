// Plan 33b journey 9: native Passkey APIs with pinned @auth0/auth0-auth-js
// 1.16.1 against a custom domain. Credentials come from a real Chromium page
// on an allowed web origin (the client's web origin under the shared RP ID)
// with a CDP virtual authenticator; the form-body (SDK) and raw JSON-body
// token requests are both exercised.
import assert from "node:assert/strict";
import { chromium } from "@playwright/test";
import { AuthClient } from "@auth0/auth0-auth-js";
import {
  api, appOrigin, capture, credentialSecrets, domains, ensurePasskeys, fixtureFetch, management, mgmt, mobile,
  nativeSecret, newTOTPSeed, optionsSecrets, realm, secret, sharedRP, totp, waitLog, saveState,
} from "./m33b-node.mjs";

const host = domains.primary;
const grant = "urn:okta:params:oauth:grant-type:webauthn";
const browser = await chromium.launch({ executablePath: process.env.E2E_CHROMIUM || undefined });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
await context.route(`${appOrigin}/**`, (r) => r.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>Plan33b native web origin</title>" }));
const page = await context.newPage();
await page.goto(`${appOrigin}/`);
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
  protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  automaticPresenceSimulation: true, defaultBackupEligibility: true, defaultBackupState: true } });
// The page runs exactly what a native app's credential manager would: the
// server's JSON options in, the serialized credential out.
async function ceremony(kind, publicKey) {
  const credential = await page.evaluate(async ([kind, publicKey]) => {
    const enc = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const options = kind === "create" ? PublicKeyCredential.parseCreationOptionsFromJSON(publicKey) : PublicKeyCredential.parseRequestOptionsFromJSON(publicKey);
    const c = await navigator.credentials[kind]({ publicKey: options });
    const r = c.response;
    const response = kind === "create"
      ? { clientDataJSON: enc(r.clientDataJSON), attestationObject: enc(r.attestationObject), transports: r.getTransports() }
      : { clientDataJSON: enc(r.clientDataJSON), authenticatorData: enc(r.authenticatorData), signature: enc(r.signature), userHandle: r.userHandle ? enc(r.userHandle) : undefined };
    return { id: c.id, rawId: enc(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment, response, clientExtensionResults: c.getClientExtensionResults() };
  }, [kind, publicKey]);
  await credentialSecrets(credential, `native ${kind}`);
  return credential;
}
const raw = async (h, path, body, json = true) => {
  const r = await fixtureFetch(`https://${h}${path}`, {
    method: "POST",
    headers: { "content-type": json ? "application/json" : "application/x-www-form-urlencoded" },
    body: json ? JSON.stringify(body) : new URLSearchParams(body).toString(),
  });
  const value = await r.json().catch(() => null);
  await capture(`native ${h} ${path}`, { status: r.status, value: value?.auth_session ? { ...value, auth_session: "<secret>" } : value });
  return { status: r.status, body: value };
};
const claims = (t) => JSON.parse(Buffer.from(t.split(".")[1], "base64url"));
try {
  await ensurePasskeys();
  const m = await management();
  await m.guardian.policies.set([]);
  const auth = new AuthClient({ domain: host, clientId: "m33b-native", clientSecret: nativeSecret, customFetch: fixtureFetch });
  const email = `native-${process.env.E2E_M33B_BACKEND}@e2e.local`;

  // The canonical host has no usable native RP: refused.
  const canonical = await raw("sdk.e2e.test", "/passkey/register", { client_id: "m33b-native", client_secret: nativeSecret, realm, user_profile: { email } });
  assert.equal(canonical.status, 400, JSON.stringify(canonical.body));

  // Signup: SDK register, browser create, SDK getTokenByPasskey (form body
  // with a stringified authn_response).
  const signup = await auth.passkey.register({ email, name: "Native Person", realm });
  await secret(signup.authSession, "auth_session");
  await optionsSecrets(signup.authnParamsPublicKey);
  assert.equal(signup.authnParamsPublicKey.rp.id, sharedRP);
  assert.equal(signup.authnParamsPublicKey.rp.name, sharedRP);
  assert.deepEqual(signup.authnParamsPublicKey.pubKeyCredParams.map((p) => p.alg), [-8, -7, -257]);
  const created = await ceremony("create", signup.authnParamsPublicKey);
  const tokens = await auth.passkey.getTokenByPasskey({ authSession: signup.authSession, credential: created, realm, scope: "openid profile email" });
  await secret(tokens.accessToken, "native access token");
  const idClaims = claims(tokens.idToken);
  assert.equal(idClaims.iss, `https://${host}/`);
  assert.equal(idClaims.email, email);
  assert.equal(idClaims.amr, undefined);
  const uid = idClaims.sub;
  await saveState({ nativeUser: uid });
  // The same auth_session cannot be redeemed twice.
  const reused = await raw(host, "/oauth/token", { grant_type: grant, client_id: "m33b-native", client_secret: nativeSecret, auth_session: signup.authSession, authn_response: JSON.stringify(created), realm }, false);
  assert.ok(reused.status === 400 || reused.status === 403, `reused auth_session: ${reused.status}`);
  // An existing identifier is refused at register.
  const existing = await raw(host, "/passkey/register", { client_id: "m33b-native", client_secret: nativeSecret, realm, user_profile: { email } });
  assert.equal(existing.status, 400, JSON.stringify(existing.body));
  const methods = await api(`users/${encodeURIComponent(uid)}/authentication-methods`);
  const pk = methods.find((x) => x.type === "passkey");
  assert.equal(pk.relying_party_identifier, sharedRP);
  assert.equal(pk.credential_device_type, "multi_device");
  assert.equal(pk.credential_backed_up, true);

  // Login: SDK challenge, browser get, raw JSON-body token request.
  const login = await auth.passkey.challenge({ realm });
  await secret(login.authSession, "auth_session");
  await optionsSecrets(login.authnParamsPublicKey);
  assert.equal(login.authnParamsPublicKey.rpId, sharedRP);
  assert.equal(login.authnParamsPublicKey.timeout, 60000);
  const asserted = await ceremony("get", login.authnParamsPublicKey);
  const jsonBody = await raw(host, "/oauth/token", { grant_type: grant, client_id: "m33b-native", client_secret: nativeSecret, auth_session: login.authSession, authn_response: asserted, realm, scope: "openid" });
  assert.equal(jsonBody.status, 200, JSON.stringify(jsonBody.body));
  await secret(jsonBody.body.access_token, "native access token");
  assert.equal(claims(jsonBody.body.id_token).sub, uid);
  await waitLog("s", (r) => r.user_id === uid && JSON.stringify(r.details ?? {}).includes("phr"), "native passkey s log with performed_amr phr");

  // mfa_required, then the mfa-otp grant: logged as sepkotpft.
  const seed = newTOTPSeed();
  await secret(seed, "TOTP seed");
  await api(`users/${encodeURIComponent(uid)}/authentication-methods`, "POST", { type: "totp", totp_secret: seed });
  await m.guardian.factors.set("otp", { enabled: true });
  await m.guardian.policies.set(["all-applications"]);
  const again = await auth.passkey.challenge({ realm });
  await secret(again.authSession, "auth_session");
  const second = await ceremony("get", again.authnParamsPublicKey);
  const required = await raw(host, "/oauth/token", { grant_type: grant, client_id: "m33b-native", client_secret: nativeSecret, auth_session: again.authSession, authn_response: JSON.stringify(second), realm, scope: "openid" }, false);
  assert.equal(required.status, 403, JSON.stringify(required.body));
  assert.equal(required.body.error, "mfa_required");
  await secret(required.body.mfa_token, "mfa_token");
  const otp = await raw(host, "/oauth/token", { grant_type: "http://auth0.com/oauth/grant-type/mfa-otp", client_id: "m33b-native", client_secret: nativeSecret, mfa_token: required.body.mfa_token, otp: totp(seed) });
  assert.equal(otp.status, 200, JSON.stringify(otp.body));
  await secret(otp.body.access_token, "native access token");
  await waitLog("sepkotpft", (r) => r.user_id === uid, "sepkotpft after passkey + OTP");
  await m.guardian.policies.set([]);

  // .well-known association files for the client's mobile settings.
  const aasa = await (await fixtureFetch(`https://${host}/.well-known/apple-app-site-association`)).json();
  assert.ok(aasa.webcredentials.apps.includes(`${mobile.ios.team_id}.${mobile.ios.app_bundle_identifier}`), JSON.stringify(aasa));
  const links = await (await fixtureFetch(`https://${host}/.well-known/assetlinks.json`)).json();
  const android = links.find((s) => s.target?.package_name === mobile.android.app_package_name);
  assert.ok(android, JSON.stringify(links));
  assert.deepEqual(android.target.sha256_cert_fingerprints, mobile.android.sha256_cert_fingerprints);
  assert.deepEqual(android.relation, ["delegate_permission/common.get_login_creds"]);

  // Organization required and honoured.
  const org = await api("organizations", "POST", { name: `passkey-org-${process.env.E2E_M33B_BACKEND}`, display_name: "Passkey organization" });
  const conn = (await api(`connections?name=${encodeURIComponent(realm)}`))[0];
  await api(`organizations/${org.id}/enabled_connections`, "POST", { connection_id: conn.id, assign_membership_on_login: false });
  await api(`organizations/${org.id}/members`, "POST", { members: [uid] });
  const orgAuth = new AuthClient({ domain: host, clientId: "m33b-org-native", clientSecret: nativeSecret, customFetch: fixtureFetch });
  const missing = await raw(host, "/passkey/challenge", { client_id: "m33b-org-native", client_secret: nativeSecret, realm });
  assert.equal(missing.status, 400, JSON.stringify(missing.body));
  const orgLogin = await orgAuth.passkey.challenge({ realm, organization: org.id });
  await secret(orgLogin.authSession, "auth_session");
  const orgCredential = await ceremony("get", orgLogin.authnParamsPublicKey);
  const orgTokens = await orgAuth.passkey.getTokenByPasskey({ authSession: orgLogin.authSession, credential: orgCredential, realm, organization: org.id, scope: "openid" });
  await secret(orgTokens.accessToken, "native access token");
  assert.equal(claims(orgTokens.idToken).org_id, org.id);
  const outsider = await mgmt(`organizations/${org.id}/members`, "DELETE", { members: [uid] });
  assert.ok(outsider.status < 300);
  const notMember = await orgAuth.passkey.challenge({ realm, organization: org.id });
  await secret(notMember.authSession, "auth_session");
  const refusedCredential = await ceremony("get", notMember.authnParamsPublicKey);
  const refused = await raw(host, "/oauth/token", { grant_type: grant, client_id: "m33b-org-native", client_secret: nativeSecret, auth_session: notMember.authSession, authn_response: JSON.stringify(refusedCredential), realm, organization: org.id }, false);
  assert.ok(refused.status >= 400, `non-member organization login: ${refused.status}`);
  console.log(`Plan33b native auth-js 1.16.1 register/getTokenByPasskey/challenge, JSON body, MFA OTP, .well-known and organizations passed on ${process.env.E2E_M33B_BACKEND}`);
} finally {
  await browser.close();
}
