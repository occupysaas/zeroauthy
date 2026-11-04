# Testing with zeroauthy

Use zeroauthy as a disposable, Auth0-compatible login server in end-to-end
tests. A container seeded with known tenants, applications and users lets your
test suite run real login flows (the hosted login page, the code exchange,
refresh tokens, MFA, password reset) locally and in CI, with the same Auth0
SDKs your application uses in production.

The kit is in [examples/testing](../examples/testing):

| File | What it is |
|---|---|
| [seed.yaml](../examples/testing/seed.yaml) | One tenant, a SPA, a regular web app, an M2M client, an API, the database connection and two users |
| [compose.yaml](../examples/testing/compose.yaml) | zeroauthy with memory storage, self-signed TLS, the seed, emails in the log and a healthcheck |
| [smoke.mjs](../examples/testing/smoke.mjs) | Password grant, ID token signature and claims, Management API (Node 22+, no dependencies) |
| [login.spec.mjs](../examples/testing/login.spec.mjs) | Playwright: a browser login through the hosted login page, then the code exchange and claim checks |
| [github-actions.yml](../examples/testing/github-actions.yml) | A GitHub Actions job running all of it |

## When to use it

- **Your app's login in E2E tests.** Point the app's Auth0 SDK at zeroauthy
  instead of a shared Auth0 development tenant: no network dependency, no
  rate limits from a shared tenant, no leftover users between runs.
- **CI.** Every run starts from the same seeded state in a few seconds.
- **Flows that are awkward against a hosted tenant:** password reset and
  email verification (links appear in the log), MFA enrollment, blocked
  users, wrong passwords.

It is not a test double: zeroauthy is a full identity server, so your tests
exercise real OAuth and OpenID Connect behaviour. It is also not Auth0: check
[the differences](#differences-from-auth0) before treating a passing test as
proof of production behaviour.

## Start it

```bash
docker compose -f examples/testing/compose.yaml up -d --wait zeroauthy
docker compose -f examples/testing/compose.yaml cp zeroauthy:/data/zeroauthy-ca.pem ./zeroauthy-ca.pem
NODE_EXTRA_CA_CERTS=./zeroauthy-ca.pem node examples/testing/smoke.mjs
```

```
password grant: auth0|… alice@example.test (iss https://localhost:8443/)
management API: found auth0|… bob@example.test
smoke test passed
```

With Podman, `podman compose` or `podman-compose` run the same file. If your
compose tool does not support `--wait`, poll `docker compose ps` (or
`podman healthcheck run <container>`) until zeroauthy is healthy. To build your own checkout instead of the published
image, uncomment `build: ../..` in `compose.yaml` or set
`ZEROAUTHY_IMAGE` to a local tag. Stop and discard everything with:

```bash
docker compose -f examples/testing/compose.yaml down -v
```

What you get:

| | |
|---|---|
| Tenant domain | `localhost:8443` from the host, `zeroauthy:8443` from containers on the compose network |
| Issuer | `https://localhost:8443/` or `https://zeroauthy:8443/`: the host the request used |
| Management API audience | `https://localhost:8443/api/v2/` (the first domain, whichever host you call) |
| SPA | `test-spa`, callback `http://localhost:3000` |
| Regular web app | `test-web` / `test-web-secret-not-for-production`, callback `http://localhost:3000/callback`, `client_secret_post` |
| M2M | `test-m2m` / `test-m2m-secret-not-for-production`, Management API and `https://api.example.test` (`read:messages`) |
| Users | `alice@example.test` / `Test-Password-Alice-1` (verified), `bob@example.test` / `Test-Password-Bob-1` (unverified) |

Edit `seed.yaml` for your own apps: add your callback URLs, enable the
connection for each client, add users. The full seed format, including roles,
organizations, Actions, social connections and MFA settings, is in
[tests/e2e/seed.yaml](../tests/e2e/seed.yaml) and `internal/seed`. A seed
error stops the server at startup, and the log names the problem.

## Point an Auth0 SDK at it

Use the tenant domain wherever the SDK asks for the Auth0 domain, and the
seeded client IDs and secrets:

| SDK | Setting |
|---|---|
| auth0-spa-js, auth0-react, auth0-vue, auth0-angular | `domain: 'localhost:8443'`, `clientId: 'test-spa'` |
| express-openid-connect | `issuerBaseURL: 'https://localhost:8443'`, `clientID: 'test-web'`, `clientSecret`, `clientAuthMethod: 'client_secret_post'` |
| nextjs-auth0 | `AUTH0_DOMAIN=localhost:8443`, `AUTH0_CLIENT_ID=test-web`, `AUTH0_CLIENT_SECRET=…` |
| node-auth0 (`ManagementClient`, `AuthenticationClient`) | `domain: 'localhost:8443'`, `clientId: 'test-m2m'`, `clientSecret` |
| Any OIDC library | discovery at `https://localhost:8443/.well-known/openid-configuration` |
| APIs validating access tokens (express-oauth2-jwt-bearer and others) | `issuerBaseURL: 'https://localhost:8443/'`, `audience: 'https://api.example.test'` |

express-openid-connect defaults to `client_secret_basic`, but the seeded web
app, like a new Auth0 application, uses `client_secret_post`; pass
`clientAuthMethod: 'client_secret_post'` or change
`token_endpoint_auth_method` in the seed.

Use one host per test environment. A token issued on `localhost:8443` names
that issuer, and an API configured for `https://zeroauthy:8443/` rejects it.
If your app runs in a container and your browser on the host, give the
tenant a name both can resolve, or run the browser in the compose network
too.

## Trust the certificate

`server.tls_self_signed` generates a new CA and certificate at every start,
covering `localhost`, the tenant domains in the seed and the names in
`server.tls_self_signed_hosts` (here the compose service name `zeroauthy`).
The CA certificate is written to `/data/zeroauthy-ca.pem`; copy it out after
the server is healthy, never before, because it changes every start. See
[deployment](deployment.md#self-signed-tls-for-testing).

| Runtime | How |
|---|---|
| Node.js | `NODE_EXTRA_CA_CERTS=./zeroauthy-ca.pem` (added to the built-in roots; must be set when Node starts) |
| Python `requests` | `REQUESTS_CA_BUNDLE=./zeroauthy-ca.pem` (replaces the default bundle) |
| Python `ssl`, `urllib`, `httpx` | `SSL_CERT_FILE=./zeroauthy-ca.pem` |
| Go | `SSL_CERT_FILE=./zeroauthy-ca.pem` on Linux (replaces the system roots), or add the PEM to an `x509.CertPool` in your test's `http.Client` |
| Java | `keytool -importcert -noprompt -alias zeroauthy -file zeroauthy-ca.pem -keystore test.jks -storepass changeit`, then `-Djavax.net.ssl.trustStore=test.jks` |
| curl | `curl --cacert zeroauthy-ca.pem …` |
| Playwright browsers | `ignoreHTTPSErrors: true` in the config (browsers do not read `NODE_EXTRA_CA_CERTS`), as in [playwright.config.mjs](../examples/testing/playwright.config.mjs) |

Inside the compose network, a test container mounts the `zeroauthy-data`
volume read-only and sets `NODE_EXTRA_CA_CERTS=/zeroauthy/zeroauthy-ca.pem`;
see the `smoke` service in `compose.yaml`:

```bash
docker compose -f examples/testing/compose.yaml --profile test run --rm smoke
```

## Fresh state or persistent

The kit uses `memory://` storage: every start is a clean tenant built from the
seed, and nothing survives a restart. That is what most test suites want.
Within one run, tests share the server, so give each test its own users
(create them through the Management API) or restart between suites.

To keep data across restarts, for example while developing tests, use SQLite
on a volume and a fixed master key:

```yaml
    environment:
      ZEROAUTHY_STORAGE__DSN: sqlite:///data/zeroauthy.db
      ZEROAUTHY_SECURITY__MASTER_KEY: "dGVzdC1vbmx5LW1hc3Rlci1rZXktMzItYnl0ZXMhISE="  # 32 bytes, test only
      ZEROAUTHY_SEED_MODE: create_only   # keep changes made since the first start
```

With `seed_mode: apply` (the default) the seed overwrites the objects it names
at every start; `create_only` only creates missing ones.

## Read emails from the log

The kit sets `email.driver: log` and `email.log_links: true`, so verification
and password-reset emails, including their links, are written to the
container log as JSON:

```bash
docker compose -f examples/testing/compose.yaml logs zeroauthy | grep 'email (log driver)'
```

```json
{"level":"INFO","msg":"email (log driver)","to":"alice@example.test","subject":"Reset your Test Tenant password","text":"… https://localhost:8443/u/reset-password?ticket=…\n"}
```

A test triggers the email (the hosted "forgot password" page,
`POST /dbconnections/change_password`, or the Management API's
`POST /api/v2/jobs/verification-email`), then reads the newest matching line
for that address and opens the link. Passwordless email codes are logged the
same way. Without `log_links`, reset and verification tickets are replaced by
`ticket=REDACTED`.

The log driver does **not** print email MFA codes, MFA enrollment emails or
organization invitations. For those, use the `dir` driver, which writes
every message as an `.eml` file, and share the directory with your tests:

```yaml
      ZEROAUTHY_EMAIL__DRIVER: dir
      ZEROAUTHY_EMAIL__DIR: /data/mail   # read the .eml files through the zeroauthy-data volume
```

Never enable `log_links` or these drivers outside tests: a logged link signs
its reader in.

## Get a Management API token for test setup

The seeded M2M client is authorized for the tenant's Management API, so tests
can create users, change settings or look up IDs before driving the browser:

```bash
TOKEN=$(curl -s --cacert zeroauthy-ca.pem https://localhost:8443/oauth/token \
  -d grant_type=client_credentials -d client_id=test-m2m \
  -d client_secret=test-m2m-secret-not-for-production \
  -d audience=https://localhost:8443/api/v2/ | jq -r .access_token)

curl -s --cacert zeroauthy-ca.pem -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' https://localhost:8443/api/v2/users \
  -d '{"connection":"Username-Password-Authentication","email":"carol@example.test","password":"Test-Password-Carol-1","email_verified":true}'
```

node-auth0's `ManagementClient` works the same way (`domain: 'localhost:8443'`).
Add scopes to the `client_grants` entry in the seed as your setup needs them.
User IDs are random on every start: look users up by email
(`GET /api/v2/users-by-email?email=…`) rather than hard-coding IDs.

## MFA in tests

Enable one-time passwords for every application in the seed:

```yaml
    guardian:
      factors: {otp: true}
      policies: [all-applications]
```

A user's TOTP secret is created when they enroll, so a seed cannot give a
user a known secret. Enroll in the test instead: after the password, the
hosted page shows the secret in `#mfa-secret`; compute the code, submit it,
acknowledge the recovery code and continue. Keep the secret for later logins.

```js
import { createHmac } from 'node:crypto';

// RFC 6238 TOTP: SHA-1, 6 digits, 30-second steps.
function totp(secret, time = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.replace(/[\s=]/g, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time / 30000)));
  const h = createHmac('sha1', key).update(counter).digest();
  return String((h.readUInt32BE(h[h.length - 1] & 15) & 0x7fffffff) % 1e6).padStart(6, '0');
}

// After submitting username and password:
const secret = (await page.locator('#mfa-secret').innerText()).trim();
await page.fill('#code', totp(secret));
await page.click('button[type=submit]');
await page.locator('[name=ack]').check();   // "I saved my recovery code"
await page.click('button[type=submit]');
// On the next login, the challenge page asks for #code again.
```

A code is accepted once: a second login within the same 30-second step needs
to wait for the next step. To require MFA only for some users or tests, keep
`otp: true` with `policies: []` and call `api.multifactor.enable('any')` from
a post-login Action for the users you choose, or switch the policy during the
run with `PUT /api/v2/guardian/policies` (body `["all-applications"]` or
`[]`, scope `update:mfa_policies`). See [MFA](mfa.md) for email and SMS
factors (read email codes with the `dir` driver above).

## Differences from Auth0

zeroauthy follows Auth0's documented behaviour, but it is not Auth0. Keep
these in mind when a test passes here:

- Features listed under "Not supported in 1.0" on the
  [compatibility page](compatibility.md) (WebAuthn and passkeys, SAML,
  enterprise connections, some social providers, implicit flow and others)
  are missing; test those against Auth0.
- The issuer, domain and Management API audience are your test host, not
  `*.auth0.com`. Code that hard-codes Auth0 hostnames will not work.
- User IDs, signing keys and the CA change on every start.
- Attack protection is on, as on Auth0: ten wrong passwords block a user
  from that IP, password-reset emails are limited to three per hour, and the Authentication API is rate limited per IP
  (`security.rate_limit`, default 50 requests per second, burst 200).
  Suites that fail logins on purpose should use their own users, or raise
  `attack_protection` limits in the seed. See
  [attack protection](attack-protection.md).
- Emails are not delivered; they go to the log (above).

## Run it in CI

[github-actions.yml](../examples/testing/github-actions.yml) starts zeroauthy
with `docker run` in a step (service containers start before the checkout,
so they cannot mount the seed), waits until `/healthz` answers over TLS with
the copied CA, exports `NODE_EXTRA_CA_CERTS` for later steps, then runs the
smoke test and the Playwright login test, and prints the zeroauthy log at the
end. The same steps work in any CI that can run a container:

```bash
docker run -d --name zeroauthy -p 8443:8443 \
  -v "$PWD/examples/testing/seed.yaml:/seed/seed.yaml:ro" \
  -e ZEROAUTHY_SERVER__LISTEN=:8443 \
  -e ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:8443 \
  -e ZEROAUTHY_SERVER__TLS_SELF_SIGNED=true \
  -e ZEROAUTHY_SERVER__TLS_SELF_SIGNED_CA_FILE=/data/zeroauthy-ca.pem \
  -e ZEROAUTHY_STORAGE__DSN=memory:// \
  -e ZEROAUTHY_SEED=/seed/seed.yaml \
  -e ZEROAUTHY_EMAIL__DRIVER=log -e ZEROAUTHY_EMAIL__LOG_LINKS=true \
  ghcr.io/occupysaas/zeroauthy:1.0.0-rc.1

until docker cp zeroauthy:/data/zeroauthy-ca.pem ./zeroauthy-ca.pem 2>/dev/null &&
      curl -fsS --cacert zeroauthy-ca.pem https://localhost:8443/healthz; do sleep 1; done
NODE_EXTRA_CA_CERTS=./zeroauthy-ca.pem npm test
```

`server.system_host` is required whenever `server.base_domain` is not set;
the console is not needed for tests, but the setting is. On SELinux hosts add
`,Z` to the seed mount.
