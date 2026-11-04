# Quickstart

This guide takes you from nothing to a working login with an Auth0 SDK on your
own machine: one container, a first operator, a tenant, an application with a
connection enabled, a user, and an
[express-openid-connect](https://github.com/auth0/express-openid-connect) app
that signs that user in. It takes about ten minutes.

zeroauthy 1.0 is an **early preview**. Check the
[compatibility page](compatibility.md) for what is not supported yet.

Want zeroauthy as a throwaway login server for automated tests instead? The
[testing guide](testing.md) starts a seeded tenant with one command, no
certificates or console steps needed.

## What you need

- Docker or Podman (or a release binary, see [Without a container](#without-a-container))
- `openssl` (or [mkcert](https://github.com/FiloSottile/mkcert))
- Node.js 20.19 or later, for the sample app only
- A browser. Browsers resolve `*.localhost` to your own machine, and the
  console lives on `system.localhost`.

## Why HTTPS, even locally

Every token zeroauthy issues names an `https://` issuer, and Auth0 SDKs talk
to `https://<domain>`. The admin console also calls tenant APIs over HTTPS.
So zeroauthy needs TLS even on your laptop: either it terminates TLS itself
(this guide) or a reverse proxy does it for it ([deployment](deployment.md)).
Plain HTTP is fine only for `/healthz`.

## 1. Make a local certificate and a master key

```bash
mkdir zeroauthy-local && cd zeroauthy-local
mkdir certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:system.localhost" \
  -keyout certs/key.pem -out certs/cert.pem
chmod 0644 certs/key.pem   # the container user must read it; local use only

openssl rand -base64 32 > master.key
chmod 0600 master.key
```

`localhost` will be your tenant's domain and `system.localhost` the console's.
Your browser will warn about this self-signed certificate; accept it for both
`https://localhost:8443` and `https://system.localhost:8443`, or add
`certs/cert.pem` to your system's trust store. With mkcert, `mkcert -install`
and `mkcert -cert-file certs/cert.pem -key-file certs/key.pem localhost
system.localhost` give you a certificate your browser already trusts.

The master key encrypts signing keys and secrets in the database. Keep it: the
data volume is unreadable without it.

## 2. Start zeroauthy

```bash
docker run -d --name zeroauthy -p 8443:8443 \
  -v zeroauthy-data:/data \
  -v "$PWD/certs:/certs:ro" \
  -e ZEROAUTHY_SERVER__LISTEN=:8443 \
  -e ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:8443 \
  -e ZEROAUTHY_SERVER__TLS_CERT_FILE=/certs/cert.pem \
  -e ZEROAUTHY_SERVER__TLS_KEY_FILE=/certs/key.pem \
  -e ZEROAUTHY_SECURITY__MASTER_KEY="$(cat master.key)" \
  ghcr.io/occupysaas/zeroauthy:1.0.0-rc.1
```

Use the newest tag from the
[releases page](https://github.com/occupysaas/zeroauthy/releases). On
SELinux hosts add `:Z` to the certificate mount (`/certs:ro,Z`). The image
stores SQLite in the `/data` volume and migrates it at start. Check it:

```bash
curl --cacert certs/cert.pem https://localhost:8443/healthz
# {"status":"ok"}
```

Emails (verification, password reset) go to the container log until you set
up an email provider (`docker logs zeroauthy`); see [email](email.md).

## 3. Create the first operator

Operators are the console's users. Create one inside the running container:

```bash
docker exec zeroauthy zeroauthy admin create --email you@example.com
```

It prints a one-time link to `https://system.localhost:8443/...`, valid for an
hour. Open it, choose a password of at least 12 characters, then sign in at
<https://system.localhost:8443/admin/>.

## 4. Create a tenant

In the console, open the tenant switcher in the header and choose **Create
tenant**:

- **Name:** `acme`
- **Domains:** `localhost:8443`

A tenant is reached by its host. With no `server.base_domain` configured (as
here), you give each tenant its domains yourself, port included. In production
you set `base_domain` and tenant `acme` is served at `acme.<base_domain>`
([deployment](deployment.md#dns-and-hosts)).

The new tenant already has a database connection named
`Username-Password-Authentication`.

## 5. Create an application and enable the connection

Switch to the `acme` tenant, open **Applications → Create**, name it
`My Web App` and choose **Regular web app**. On its **Settings** tab:

- **Allowed callback URLs:** `http://localhost:3000/callback`
- **Allowed logout URLs:** `http://localhost:3000`

Save. Then open the application's **Connections** tab and switch on
`Username-Password-Authentication`. Until a connection is enabled, nobody can
sign in to the application.

Note the **Domain** (`localhost:8443`), **Client ID** and **Client secret**
from the Settings tab.

## 6. Create a user

Open **Users → Create user**, pick `Username-Password-Authentication`, and
enter an email and a password that meets the connection's policy. (Or leave
users to sign up from the login page.)

## 7. Log in from an app

```bash
mkdir my-app && cd my-app
npm init -y >/dev/null
npm install express express-openid-connect
```

Save this as `server.js`:

```js
const express = require('express');
const { auth, requiresAuth } = require('express-openid-connect');

const app = express();
app.use(auth({
  issuerBaseURL: process.env.ISSUER_BASE_URL, // https://localhost:8443
  baseURL: 'http://localhost:3000',
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  clientAuthMethod: 'client_secret_post',    // the application's default token endpoint method
  secret: process.env.SESSION_SECRET,         // any long random string
  authRequired: false,
  authorizationParams: { response_type: 'code', scope: 'openid profile email' },
}));

app.get('/', (req, res) => res.send(req.oidc.isAuthenticated()
  ? `Hello ${req.oidc.user.email} <a href="/logout">Log out</a>`
  : '<a href="/login">Log in</a>'));
app.get('/profile', requiresAuth(), (req, res) => res.json(req.oidc.user));

app.listen(3000, () => console.log('http://localhost:3000'));
```

Run it, trusting your local certificate (with mkcert, use
`"$(mkcert -CAROOT)/rootCA.pem"` instead):

```bash
NODE_EXTRA_CA_CERTS=../certs/cert.pem \
ISSUER_BASE_URL=https://localhost:8443 \
CLIENT_ID=<client id> CLIENT_SECRET=<client secret> \
SESSION_SECRET="$(openssl rand -hex 32)" \
node server.js
```

Open <http://localhost:3000>, click **Log in**, and sign in on zeroauthy's
login page with the user from step 6. You land back on the app with
"Hello you@…", and <http://localhost:3000/profile> shows the ID token claims.

The app itself can stay on `http://localhost`; only zeroauthy needs HTTPS.
Other SDKs (auth0-spa-js, auth0-react, nextjs-auth0) take the same domain
(`localhost:8443`) and client ID; each application's **Quick start** tab in
the console has snippets.

## Do the same with the API

Steps 4–6 call the same APIs that scripts can use. To automate them, get a
Management API token for the tenant: create a **Machine to machine**
application and, on its **APIs** tab, authorize it for the tenant's
Management API (`https://localhost:8443/api/v2/`) with the permissions it
needs (for example `read:users`). Then:

```bash
TOKEN=$(curl -s --cacert certs/cert.pem https://localhost:8443/oauth/token \
  -d grant_type=client_credentials -d client_id=<m2m client id> \
  -d client_secret=<m2m client secret> -d audience=https://localhost:8443/api/v2/ \
  | jq -r .access_token)

curl -s --cacert certs/cert.pem https://localhost:8443/api/v2/users \
  -H "Authorization: Bearer $TOKEN"
```

node-auth0, the Auth0 CLI and the Deploy CLI work against that domain too
([Management API](management-api.md)). To create tenants from a script or
keep them in version control, use a [seed file](../tests/e2e/seed.yaml) with
`seed:` and `seed_mode: create_only` (see README, "Configuration").

## Clean up

```bash
docker rm -f zeroauthy
docker volume rm zeroauthy-data
```

## Without a container

Download `zeroauthy_<version>_<os>_<arch>.tar.gz` for linux/amd64,
linux/arm64 or darwin/arm64 from the
[releases page](https://github.com/occupysaas/zeroauthy/releases) and check
it against `SHA256SUMS`. The binary is static. Node.js 22.13 or later is
needed only for Actions and custom database scripts (the container image
includes Node).

```bash
tar xzf zeroauthy_*_linux_amd64.tar.gz && cd zeroauthy_*_linux_amd64
ZEROAUTHY_SERVER__LISTEN=:8443 \
ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:8443 \
ZEROAUTHY_SERVER__TLS_CERT_FILE=../certs/cert.pem \
ZEROAUTHY_SERVER__TLS_KEY_FILE=../certs/key.pem \
ZEROAUTHY_SECURITY__MASTER_KEY="$(cat ../master.key)" \
ZEROAUTHY_STORAGE__DSN=sqlite://zeroauthy.db \
ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
  ./zeroauthy serve
```

In a second terminal, `./zeroauthy admin create --email you@example.com`
with the same `ZEROAUTHY_*` variables creates the operator. Then continue at
step 4. For a real server, start from
[examples/zeroauthy.yaml](../examples/zeroauthy.yaml) and
[deployment](deployment.md).
