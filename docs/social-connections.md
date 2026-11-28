# Social and OpenID Connect connections

For complete enterprise OIDC/Okta configuration, connection keys and home realm
discovery, see [enterprise connections](enterprise-connections.md).

Plan 24 adds the federation core; Plan 39a adds Apple web and native login;
Plan 39c adds GitHub; Plan 39b adds the remaining Tier 1 social providers,
generic OAuth 1.0a and native Google and Facebook sign-in; Plan 39d adds
Tier 2:

| Strategy | Kind | Identity key | Public user ID |
|---|---|---|---|
| `apple` | social (`isSocial: true`) | Apple `sub` | `apple|<sub>` |
| `github` | social (`isSocial: true`) | GitHub numeric user `id` | `github|<id>` |
| `google-oauth2` | social (`isSocial: true`) | Google `sub` | `google-oauth2|<sub>` |
| `oauth2` | social (`isSocial: true`) | `user_id` returned by the profile script | `oauth2|<connection>|<subject>` |
| `oauth1` | social (`isSocial: true`) | `user_id` returned by the profile script | `oauth1|<connection>|<subject>` |
| `amazon` | social (`isSocial: true`) | Amazon `user_id` | `amazon|<id>` |
| `bitbucket` | social (`isSocial: true`) | Bitbucket `uuid` | `bitbucket|<id>` |
| `box` | social (`isSocial: true`) | Box user `id` | `box|<id>` |
| `dropbox` | social (`isSocial: true`) | Dropbox `account_id` | `dropbox|<id>` |
| `facebook` | social (`isSocial: true`) | Facebook user `id` | `facebook|<id>` |
| `line` | social (`isSocial: true`) | LINE `userId` | `line|<id>` |
| `linkedin` | social (`isSocial: true`) | LinkedIn OpenID `sub` | `linkedin|<id>` |
| `paypal` | social (`isSocial: true`) | PayPal `user_id` | `paypal|<id>` |
| `paypal-sandbox` | social (`isSocial: true`) | PayPal sandbox `user_id` | `paypal-sandbox|<id>` |
| `salesforce` | social (`isSocial: true`) | Salesforce `user_id` | `salesforce|<id>` |
| `salesforce-community` | social (`isSocial: true`) | Salesforce `user_id` | `salesforce-community|<id>` |
| `salesforce-sandbox` | social (`isSocial: true`) | Salesforce `user_id` | `salesforce-sandbox|<id>` |
| `shopify` | social (`isSocial: true`) | the shop's `id` | `shopify|<id>` |
| `twitter` | social (`isSocial: true`) | X user `id` (`id_str` on OAuth 1.0a) | `twitter|<id>` |
| `yahoo` | social (`isSocial: true`) | Yahoo `sub` | `yahoo|<id>` |
| `baidu` | social (`isSocial: true`) | Baidu `userid` | `baidu|<id>` |
| `bitly` | social (`isSocial: true`) | Bitly `login` | `bitly|<id>` |
| `daccount` | social (`isSocial: true`) | d Account `sub` | `daccount|<id>` |
| `dwolla` | social (`isSocial: true`) | Dwolla account ID | `dwolla|<id>` |
| `evernote` | social (`isSocial: true`) | Evernote `edam_userId` | `evernote|<id>` |
| `evernote-sandbox` | social (`isSocial: true`) | Evernote `edam_userId` | `evernote-sandbox|<id>` |
| `exact` | social (`isSocial: true`) | Exact `UserID` | `exact|<id>` |
| `fitbit` | social (`isSocial: true`) | retired: sign-in refused | `fitbit|<id>` |
| `instagram` | social (`isSocial: true`) | retired: sign-in refused | `instagram|<id>` |
| `planningcenter` | social (`isSocial: true`) | Planning Center person `id` | `planningcenter|<id>` |
| `soundcloud` | social (`isSocial: true`) | SoundCloud `id` | `soundcloud|<id>` |
| `thirtysevensignals` | social (`isSocial: true`) | 37signals identity `id` | `thirtysevensignals|<id>` |
| `untappd` | social (`isSocial: true`) | Untappd `uid` | `untappd|<id>` |
| `vkontakte` | social (`isSocial: true`) | VK `user_id` | `vkontakte|<id>` |
| `weibo` | social (`isSocial: true`) | Weibo `idstr` | `weibo|<id>` |
| `wordpress` | social (`isSocial: true`) | WordPress.com `ID` | `wordpress|<id>` |
| `yandex` | social (`isSocial: true`) | Yandex `id` | `yandex|<id>` |
| `oidc` (front or back channel) | enterprise (`isSocial: false`) | ID token `sub` | `oidc|<connection>|<sub>` |

The frozen option inventory is `internal/federation/inventory.json`; the
design is `docs/superpowers/specs/2026-10-26-zeroauthy-social-connections-design.md`.

## Configure a connection

Create connections through `POST /api/v2/connections`, the seed (`options:`
plus `display_name`/`show_as_button`), or the console (**Social**). Every
strategy needs your own provider credentials (`client_id` and `client_secret`,
or Apple’s `app_secret` signing key described below); zeroauthy has
no shared development keys.

- **Google:** `email` and `profile` flags (both default `true`); scopes are
  `openid` plus those. Additional Google API scope flags, freeform scopes and
  domain restrictions (`allowed_domains`, `hd`, …) are refused. Google's `hd`
  claim is never an authorization decision.
- **Custom OAuth 2:** `authorizationURL`, `tokenURL`, `scope` (space-separated
  string) and `scripts.fetchUserProfile`.
- **OIDC:** `discovery_url` and `scopes` (space-separated, must include
  `openid`). Front-channel, manual issuer/endpoint metadata, claim mapping and
  other enterprise features belong to Plan 36.

Endpoint URLs must be absolute `https` without credentials or fragments and
must name public hosts. The authorization URL may not preset reserved protocol
parameters (`state`, `nonce`, `prompt`, `max_age`, …).

`upstream_params`, `authParams` and `authParamsMap` are stored but never
forwarded. Any entry naming or aliasing a reserved parameter, including every
value of `acr_values`, `max_age`, `claims` and `prompt`, is refused rather than
silently weakening assurance.

### Immutable bindings and revisions

`client_id`, the OAuth endpoints, the OIDC discovery URL, the profile script and
the OIDC issuer pinned at first successful discovery cannot change; create a
new connection instead. Scopes, display, enablement, `authentication.active`,
profile-sync mode and secret rotation stay editable. Every effective change
(and every enabled-client change) increments the connection's internal
revision; login attempts started under an older revision are rejected.

`PATCH` with `options` replaces the non-secret options whole: send every option
you read back (the immutable ones included). Omitting `client_secret` keeps the
stored secret; an empty or null secret is refused.

## Register the callback

The provider must allow, for every origin your users log in on:

```
https://<canonical host>/login/callback
https://<each active custom domain>/login/callback
```

The callback always uses the login transaction's own origin; an application's
`redirect_uri` is never sent upstream. The console lists the URLs on each
connection.

## Login behavior

- Enabled federated connections appear as **Continue with …** buttons beside the
  database form. `show_as_button: false` hides a button; `/authorize?connection=<name>`
  still selects it. An application with only federated connections gets a
  provider-only page.
- `prompt=none` never starts an upstream interaction. `prompt=login` always
  starts a fresh upstream attempt.
- Upstream requests use S256 PKCE, a 32-byte state and nonce, and an attempt
  bound to the browser (a per-attempt cookie), the transaction, the origin and
  the connection revision. Attempts expire after five minutes or with the
  login transaction, whichever is first. A callback is accepted once.
- When bot detection requires a challenge, explicit selection shows the login
  page first and the social choice must pass the challenge.
- The suspicious-IP pre-login budget is spent when the browser is sent to the
  provider; the registration budget applies to a first login that provisions a
  user. Provider errors never count as bad passwords.

## Identities, profile sync and linking

A durable index unique by `(tenant, connection ID, subject)` decides who owns an
upstream identity. Email never links accounts: two subjects with the same
email are two users. `set_user_root_attributes` controls synchronization:
`on_each_login` (default) refreshes present root fields; `on_first_login` and
`never_on_login` keep the profile created at first login. A changed email
without `email_verified` becomes unverified. Operator metadata and blocking are
preserved.

Only the Management API link endpoint merges accounts. Linking moves index
ownership to the primary; unlinking recreates the secondary user. Deleting a
user or connection removes index entries and stored tokens. Each user deletion
and identity removal or transfer increments a tenant identity epoch: in-flight
attempts from before it fail, so a deleted user is never resurrected by an old
callback, while a fresh login may provision the subject again.

Identities imported before upgrading are indexed by migration `0021`. The
migration stops with a report of tenant/user/connection IDs (never tokens) when
an identity names an unknown connection, a connection of another strategy, or
is held by two users; correct those users and run it again.

## Upstream tokens

The latest access token, refresh token (an omitted refresh token keeps the
previous one; GitHub clears it instead, see GitHub below), token type, scope and expiry are stored encrypted per identity
(master-key envelope, AAD bound to tenant/connection/subject). They are returned
only by `GET /api/v2/users/{id}` to a client granted both `read:users` and
`read:user_idp_tokens`, as `identities[].access_token`/`refresh_token`, with
`Cache-Control: no-store`. `read:user_idp_tokens` must be granted explicitly:
`allow_all_scopes` never implies it, and console operators never see tokens.
Lists, search, link responses, exports, jobs and userinfo never include them.
zeroauthy does not refresh, revoke or proxy upstream tokens. Backups contain the
ciphertext; protect the master key accordingly.

## Custom OAuth profile scripts

```js
function fetchUserProfile(accessToken, context, callback) {
  request.get({ url: 'https://api.provider.example/me',
                headers: { Authorization: 'Bearer ' + accessToken }, json: true },
    function (err, response, body) {
      if (err || response.statusCode !== 200) return callback(new Error('profile'))
      callback(null, { user_id: String(body.id), email: body.email, name: body.name })
    })
}
```

`context` holds the token response's `access_token`, `refresh_token`,
`token_type`, `scope`, `expires_in` and an opaque `id_token`. Only
`request.get(options, cb)` and `request({method: 'GET', …}, cb)` exist, at most
four calls, literal `https` targets, no redirects. There is no `require`,
`fetch`, `process`, filesystem, dynamic import or npm module. `user_id` is
required; `email`, `email_verified`, `name`, `nickname`, `given_name`,
`family_name`, `picture` (https) and a bounded `user_metadata` object are used;
other claims are ignored; `app_metadata`, `identities`, `blocked` and other local
attributes are refused. Console output is discarded and script error messages
never reach users.

The runner needs **Node 25 or later** (`custom_db.node`). At startup zeroauthy
proves that Node's permission model denies sockets and `fetch`; if the version or
the probe fails, custom OAuth login alone is unavailable (a warning is logged)
and Google, OIDC and database login continue. Each execution is a fresh process
with an empty environment, a 64 MiB heap and a five-second deadline; at most 8
run per tenant and 64 in total. This is a restricted compatibility runtime, not a
general hostile-code sandbox.

## Network policy

Discovery, JWKS, token, UserInfo and script-broker requests use one bounded
client: `https` only, no environment proxy, no redirects, 10 seconds per request
(30 seconds for a whole callback), 1 MiB decoded responses, and every dial pinned
to resolved public addresses (any private, loopback, link-local, metadata or
mixed answer refuses the request, at every dial). Discovery and keys are cached
for at most five minutes per tenant, connection, revision and issuer (256
entries); an unknown `kid` triggers one coalesced refresh. OIDC accepts RS256 ID
tokens only, with 60 seconds of clock skew. No configuration option relaxes the
policy; local harnesses inject theirs at construction.

## Storage, upgrade and rollback

Migration `0021_federation` adds attempt, identity-index and token tables, the
connection revision and sealed credentials, and the tenant identity epoch. On
MySQL it widens every user-ID column to `VARBINARY(1280)` (and subjects to
`VARBINARY(1024)`), rebuilding the user-grant key; it resumes safely if
interrupted. Drain old application writers before starting migrated nodes:
older binaries do not maintain the identity index. Storage plugins built before
Plan 24 answer the new RPCs `Unimplemented`; social login then stays unavailable
instead of running without atomic attempts. Rollback means draining new traffic
and restoring a compatible backup, not dropping live identity data.

## Migration with the Deploy CLI

Provider secrets are write-only: exports never contain `client_secret`, so a
migration must reinject each provider secret explicitly. OAuth profile scripts
must be materialized into the connection (`scripts.fetchUserProfile` string);
the pinned Deploy CLI social handlers do not expand `.js` file paths. `make
e2e-deploy` runs a strict lane over all federated strategies with explicit
secret reinjection and post-import logins; see
[Microsoft and Google account sign-in](email-account-connections.md#migration-with-the-deploy-cli).

## Not included

Microsoft accounts (see [email-account-connections.md](email-account-connections.md)),
One Tap, automatic linking,
provider-initiated login, federated logout or revocation, organizations, MFA,
Actions, Token Vault, development keys, arbitrary upstream parameter
forwarding, front-channel OIDC and the remaining enterprise OIDC features (Plan
36).

## Sign in with Apple

In the Apple developer account, enable Sign in with Apple on the primary
App ID. Associate a Services ID for web sign-in, configure the tenant domain
and the return URL `https://<tenant-domain>/login/callback`, and create a
Sign in with Apple signing key for that App ID. Download the `.p8` key and
record its Key ID and the developer Team ID. For native iOS, enable the
capability on the app and use its bundle identifier in the zeroauthy
application device settings. These credentials belong to the operator;
zeroauthy supplies no developer account or borrowed keys (LR39a-1).

Create an Apple connection in **Social** or through the Management API and
enable it for the application. The hosted login button and
`/authorize?connection=apple` start the same flow. With either name or email
requested (both default true), Apple returns a cross-site form POST to
`/login/callback`; the attempt cookie uses `SameSite=None; Secure`. With both
scopes disabled, the callback uses query mode. Only `name` and `email` scopes
are accepted. Web tokens require the saved nonce; S256 is sent only when
Apple discovery advertises it. Endpoints are fixed to Apple in production.

The Services ID is immutable. Team ID and Key ID are exactly ten uppercase
alphanumerics. Credential rotation invalidates pending login attempts and
the client-secret cache. zeroauthy signs an ES256 client-secret JWT with a
five-minute lifetime and caches it for at most four minutes (LR39a-4–8).
The posted name is used only after the signed ID token validates and only
on the first identity creation, even with root synchronization on every
login. The name JSON is limited to 1 KiB and 150 characters per component.
Email comes from the verified ID token, never the posted form. Private-relay
addresses are preserved; only boolean `true` or string `"true"` marks email
verified. Identity `profileData` exposes `is_private_email` and
`real_user_status`. Identities never link automatically by email.

There is no Apple server-notification endpoint and no automatic upstream
token revocation on deletion or unlink (LR39a-2–3). Applications can retrieve
sealed upstream tokens with the explicit scopes described above. Optional
compatibility observations A1–A7 remain unobserved; local fixture results
do not establish live Apple interoperability or certification.

### Seed credentials and native client settings

An `apple` connection uses its Services ID as `options.client_id`, a 10-character
uppercase alphanumeric `team_id` and `kid`, and a PKCS#8 PEM EC P-256 signing key
as the write-only `app_secret`. The console accepts a pasted `.p8` key and
name/email switches. Omitting `app_secret` on a Management API PATCH preserves
the stored key; replacing it rotates the sealed credential.

Seed files require an explicit reference for the Apple signing key:

- `env://NAME` reads the complete PEM from that environment variable. `NAME`
  must be an environment variable name, such as `APPLE_SIGNING_KEY`.
- `file://path` reads the complete PEM from a file. `seed.Load` resolves a
  relative path against the seed file's directory; `seed.Parse` requires an
  absolute path because it has no seed filename.

Inline Apple keys in seed YAML are refused. Reference errors omit the variable
name, file path and key contents. Protect referenced files and environment
variables like other credentials. Reapplying the same key keeps its connection
identity and revision; changing it rotates the credential on that connection.

```yaml
tenants:
  - name: example
    domains: [login.example.test]
    clients:
      - client_id: native-app
        name: Native app
        app_type: native
        token_endpoint_auth_method: none
        native_social_login:
          apple: {enabled: true}
        mobile:
          ios:
            team_id: ABCDE12345
            app_bundle_identifier: test.example.app
    connections:
      - name: apple
        strategy: apple
        enabled_clients: [native-app]
        options:
          client_id: test.example.web
          team_id: ABCDE12345
          kid: ABCDE67890
          app_secret: env://APPLE_SIGNING_KEY # or file://keys/apple.p8
          name: true
          email: true
```

`native_social_login` accepts `apple`, `facebook` and `google`, each with a
boolean `enabled`; only Apple native exchange is implemented here. An empty
object enables no providers. Native Apple login also needs the iOS bundle ID
and an enabled Apple connection. Android and iOS mobile settings retain their
existing seed shape.

The Apple Deploy CLI lane is `bash tests/e2e/run-m39a-apple-deploy.sh`. It runs
the pinned CLI through YAML/directory exports and generated/preserved client
IDs. Public exports omit both `app_secret` and `client_secret`; the private
migration staging step must explicitly reinject the Apple PEM as `app_secret`.

### Native authorization-code exchange

Enable **Native Social Login: Apple** in the application's device settings,
set `mobile.ios.app_bundle_identifier`, and enable an Apple connection for
that client. If several are enabled, the first in the store's documented `LOWER(name), id` order
is selected (LR39a-9). An iOS application obtains a fresh Apple authorization
code without a nonce, then posts this JSON to `/oauth/token`:

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token_type": "http://auth0.com/oauth/token-type/apple-authz-code",
  "subject_token": "<Apple authorization code>",
  "client_id": "<zeroauthy native client ID>",
  "scope": "openid profile email",
  "user_profile": {"name": {"firstName": "Ada", "lastName": "Example"}}
}
```

Public native clients use authentication method `none`; confidential clients
must authenticate normally. `audience` and `organization` are optional.
`user_profile` is optional bounded name JSON (JSON-encoded in a form field
for form requests). It cannot change a later login's name (LR39a-10).
Apple's token-request client ID, signed client-secret subject and verified
ID-token audience must all match the stored bundle ID. A wrong-bundle code
fails without creating a user. Missing prerequisites produce `invalid_request`;
bad or expired Apple codes produce `invalid_grant`. The reserved Apple type
never runs a custom token exchange profile; normal post-login Actions, MFA
and organization policy still apply.

`make e2e-apple` runs the complete local acceptance lane: genuine cross-site
browser POSTs and repeated names; private relay and email verification;
raw Node native exchange, authentication and failure cases; node-auth0 7.4.0
connection CRUD; Auth0 CLI 1.37.0 list/show; a scan against actual runtime
secret values; seed file/environment references; and all four Deploy CLI
9.1.0 cells. No live Apple account is used.

## GitHub

Strategy `github` signs users in through a GitHub **OAuth app** (the supported
setup) and, optionally, lets the application act on GitHub for the user. The
public user ID is `github|<numeric id>`; the login name can change and is never
the identity key. Email never links accounts.

### Set up the OAuth app

1. In GitHub, create an OAuth app (Settings, Developer settings, OAuth Apps) and
   register **every** callback URL exactly, without wildcards: the canonical
   `https://<host>/login/callback` and one for each active custom domain. An
   OAuth app accepts up to 10. zeroauthy always sends the exact callback of the
   origin the user logged in on as `redirect_uri`, so one app and one connection
   serve every origin. The console lists the URLs on the connection.
2. Create the connection with `strategy: "github"`, your `client_id` and
   `client_secret` (write-only; an omitted secret on PATCH keeps the stored one).
   `client_id` cannot change afterward.
3. Set the flags. `email` (default `true`) requests `user:email`. The scope flags
   `admin_org`, `admin_public_key`, `admin_repo_hook`, `delete_repo`, `follow`,
   `gist`, `notifications`, `public_repo`, `read_org`, `read_public_key`,
   `read_repo_hook`, `read_user`, `repo`, `repo_deployment`, `repo_status`,
   `write_org`, `write_public_key` and `write_repo_hook` default to `false` and
   add the matching GitHub scope (for example `repo_status` adds `repo:status`).
   zeroauthy never requests `offline_access`. `freeform_scopes` must be empty.

A **GitHub App** works for sign-in only: its permissions come from its own
registration, so the scope flags have no effect, and `/user/emails` needs the
app's "Email addresses" read permission. Without it the login is refused (see
below). GitHub Enterprise, the device flow, and endpoint or host overrides are
not supported and are rejected.

### Email is required

With `email` on, a login is accepted only when GitHub reports a **verified
primary** email through `/user/emails` (the public profile email is never used),
on the first and on every later login. A user without one sees "Your GitHub
account needs a verified primary email address to sign in" (HTTP 403) and nothing
is stored. A missing `user:email` grant, a truncated list and a rate limit never
count as proof of a verified email. With `email: false` no email is requested and
users are created without one. Auth0 documents none of this; the rule is
zeroauthy's own (D-0181).

### `scope` and `profile`

The flags are the only source of the requested scope. `scope` is returned on read
as the effective scope and is accepted on input only when it equals the scope the
flags produce, as a set. `PATCH` replaces `options` whole, so a client that sends
back a stale `scope` together with changed flags gets "options.scope must match":
send the flags without `scope`. `profile` is stored and round-tripped only: it
adds no scope and does not stop profile attributes from syncing (a local
difference, see the compatibility matrix).

Scope changes apply from a user's **next** login; tokens stored earlier keep
their old grants. GitHub can also grant more than was requested (a user who
authorized the app before keeps the scopes they granted then), and zeroauthy
stores the granted scope verbatim. Check GitHub's `X-OAuth-Scopes` response
header when you depend on a permission, and treat a 401 from GitHub as a revoked
token.

### Tokens

The latest GitHub access token (and refresh token, when GitHub sends one) is
available through `GET /api/v2/users/{id}` to a client granted `read:users` and
`read:user_idp_tokens`, as described under [Upstream tokens](#upstream-tokens).
GitHub tokens may expire (when the OAuth app forces expiring tokens); zeroauthy
stores the expiry, **does not refresh** them, and clears a stored refresh token
when a login returns none. Users sign in again to get a new token.

### Not supported

GitHub Enterprise Server and GHE.com, the device flow, token refresh and
revocation, `connected_accounts`, and an application-supplied `redirect_uri`.

`make e2e-github` runs the local acceptance lane against a fixture provider:
Chromium logins through a real code exchange, the email-required refusals,
token access rules and the Deploy CLI 9.1.0 YAML and directory round trips. No
live GitHub account is used.

## Tier 1 social providers (Plan 39b)

`amazon`, `bitbucket`, `box`, `dropbox`, `facebook`, `line`, `linkedin`,
`paypal`, `paypal-sandbox`, `salesforce`, `salesforce-community`,
`salesforce-sandbox`, `shopify`, `twitter` and `yahoo` each run on a JSON
descriptor (`internal/federation/providers/*.json`): fixed endpoints, client
authentication, PKCE use, the permission flags, the profile map and the email
rule, with the provider documentation each comes from. D-0180 records the
rulings. Tier 2 follows below (Plan 39d).

Create one with `client_id` and `client_secret` of your app at the provider;
the secret is sealed and never returned, `client_id` cannot change, and
endpoint or script overrides are refused. Register
`https://<host>/login/callback` for every host users sign in on.

| Strategy | Scope | `email_verified` | Notes |
|---|---|---|---|
| `facebook` | `public_profile` plus one permission per true flag, comma-separated | true when Facebook returns an email | Graph API v24.0; every Graph call carries `appsecret_proof` |
| `linkedin` | `openid profile`, plus `email` | from LinkedIn's `email_verified` | `strategy_version` 3 (default); 1 and 2 are stored but sign-in is refused |
| `twitter` | `tweet.read users.read` (flags), plus `offline.access` | never (no email on OAuth 2.0) | `protocol: oauth1` uses OAuth 1.0a and reads `include_email` (needs X's elevated access) |
| `amazon` | `profile`, plus `postal_code` | false | |
| `paypal`, `paypal-sandbox` | `openid`, plus `profile`, `email`, `address`, `phone` | from the primary email's `confirmed` | sandbox hosts for `paypal-sandbox` |
| `salesforce`, `salesforce-sandbox`, `salesforce-community` | `id`, plus `profile` (default on) | from Salesforce's `email_verified` | the profile is read from the token response's identity URL, only on the token endpoint's host; `salesforce-community` requires `community_base_url` (https, public host) |
| `yahoo` | `openid profile email` | from Yahoo's `email_verified` | |
| `line` | `openid`, plus `profile` (default on) and `email` | false | the email comes from the ID token through LINE's verify endpoint |
| `dropbox` | `account_info.read` | from Dropbox's `email_verified` | |
| `box` | none | false | the email is Box's login |
| `bitbucket` | `account email` | from the primary address's `is_confirmed` | |
| `shopify` | none | false | the user is the shop; send the shop (`my-shop` or `my-shop.myshopify.com`) as `login_hint` on `/authorize`, or sign-in is refused |

`scope` is returned on read as the effective scope: the base scopes, the
scope of each true flag, then `freeform_scopes` (at most 20) where the
strategy accepts them (not Box, Dropbox, Shopify or Yahoo). An input `scope`
must equal it as a set. Users are never linked by email. A storage plugin
must declare the `social.v1` capability before these strategies (and
`oauth1`) are written; an older plugin refuses them instead of storing
unindexed identities.

### Providers from the Auth0 Marketplace

Discord, Slack, Twitch and other providers Auth0 offers only through its
Marketplace use the generic `oauth2` strategy with a `fetchUserProfile`
script (LR39b-1). Discord, for example:

```json
{
  "strategy": "oauth2",
  "name": "discord",
  "options": {
    "client_id": "<Discord application ID>",
    "client_secret": "<Discord client secret>",
    "authorizationURL": "https://discord.com/oauth2/authorize",
    "tokenURL": "https://discord.com/api/oauth2/token",
    "scope": "identify email",
    "scripts": {
      "fetchUserProfile": "function fetchUserProfile(accessToken, context, callback) { request.get({url: 'https://discord.com/api/users/@me', headers: {Authorization: 'Bearer ' + accessToken}, json: true}, function (err, resp, body) { if (err || resp.statusCode !== 200) return callback(new Error('profile')); callback(null, {user_id: body.id, nickname: body.username, email: body.email, email_verified: body.verified === true}); }); }"
    }
  }
}
```

Twitch is the same with `https://id.twitch.tv/oauth2/authorize`,
`https://id.twitch.tv/oauth2/token`, scope `user:read:email` and
`https://api.twitch.tv/helix/users` (with the `Client-Id` header) in the
script; Slack uses its OpenID Connect endpoints through the `oidc` strategy.

### Generic OAuth 1.0a (`oauth1`)

Requires `requestTokenURL`, `accessTokenURL` and `userAuthorizationURL`
(https, public hosts) and `scripts.fetchUserProfile`. Requests are signed
with HMAC-SHA1, or with RSA-SHA1 when `signatureMethod` is `RSA-SHA1` and
`client_secret` is a PEM RSA private key of at least 2048 bits; PLAINTEXT is
refused. The request-token secret stays sealed in the login attempt. The
script is called as `fetchUserProfile(token, tokenSecret, context, callback)`
with the access-token response's other fields in `context`; a
`request.get({url, oauth: true}, …)` (or Auth0's `oauth: {…}` object, whose
values are ignored) is signed by zeroauthy with the connection's consumer
credentials, which never reach the script. The token secret is returned as
`identities[].access_token_secret` beside `access_token` under
`read:user_idp_tokens`. The console lists `oauth1` connections; create and
change them through the Management API.

### Native Google and Facebook

With the application's `native_social_login.google.enabled` and an enabled
`google-oauth2` connection, a native app exchanges a Google ID token at
`/oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
`subject_token_type=http://auth0.com/oauth/token-type/google-id-token`). Auth0
documents no Google type, so this URN is zeroauthy's (SP-3). The token must be
signed by a key from Google's JWKS, issued by Google, unexpired, and its
`aud` must be the connection's `client_id` (an Android `azp` beside it is
fine).

With `native_social_login.facebook.enabled` and an enabled `facebook`
connection, the app exchanges a Facebook session-info token
(`subject_token_type=http://auth0.com/oauth/token-type/facebook-info-session-access-token`)
with an optional `user_profile` JSON. zeroauthy checks the token with Graph's
`debug_token` for the connection's app and uses its `user_id`; `user_profile`
must name the same user and its email is never marked verified.

Both run post-login Actions and MFA like Apple native login, and with the
switch off the request is `400 invalid_request` before any provider call.

## Tier 2 social providers (Plan 39d)

`baidu`, `bitly`, `daccount`, `dwolla`, `evernote`, `evernote-sandbox`,
`exact`, `planningcenter`, `soundcloud`, `thirtysevensignals`, `untappd`,
`vkontakte`, `weibo`, `wordpress` and `yandex` run on descriptors like Tier 1
(D-0182). Auth0 gives most of them only a `scope` option: the operator's
`scope` (an array or a space- or comma-separated string, at most 20 scopes)
is what is requested, and it is returned as stored; without one, the
provider's default is requested.

| Strategy | Default scope | `email_verified` | Notes |
|---|---|---|---|
| `baidu` | `basic` | no email | the token travels as a query parameter |
| `bitly` | none | from the primary email's `is_verified` | |
| `daccount` | `openid` | no email | NTT docomo d Account Connect (endpoints SD-2) |
| `dwolla` | `AccountInfoFull` | no email | the account comes from the token response (SD-3) |
| `evernote`, `evernote-sandbox` | none (OAuth 1.0a) | no email | consumer key and secret only; the user is `edam_userId` (SD-4) |
| `exact` | none | false | `baseUrl` is required: `https://start.exactonline.nl`, `.be`, `.co.uk`, `.com`, `.de`, `.fr` or `.es` |
| `planningcenter` | `people` | no email | |
| `soundcloud` | none | no email | S256 PKCE |
| `thirtysevensignals` | none | false | Basecamp's Launchpad |
| `untappd` | none | false | SD-5 |
| `vkontakte` | none | false | request `email` in `scope` to receive it (SD-6) |
| `weibo` | none | no email | |
| `wordpress` | `auth` | from WordPress's `email_verified` | |
| `yandex` | none | false | |

**Retired:** `fitbit` (Fitbit turned off its legacy Web API and OAuth on
2026-11-02; sign-in moved to the Google Health API) and `instagram` (Meta shut
down the Basic Display API on 2024-12-04). Their connections are created,
returned, changed and exported like any other, so Auth0 exports import
unchanged, but `/authorize` refuses them before any provider call. The
console shows the reason. GitHub stays on its own adapter (Plan 39c).
