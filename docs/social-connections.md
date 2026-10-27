# Social and OpenID Connect connections

Plan 24 adds three federated connection strategies:

| Strategy | Kind | Identity key | Public user ID |
|---|---|---|---|
| `google-oauth2` | social (`isSocial: true`) | Google `sub` | `google-oauth2|<sub>` |
| `oauth2` | social (`isSocial: true`) | `user_id` returned by the profile script | `oauth2|<connection>|<subject>` |
| `oidc` (`type: back_channel`) | enterprise (`isSocial: false`), supported subset | ID token `sub` | `oidc|<connection>|<sub>` |

The frozen option inventory is `internal/federation/inventory.json`; the
design is `docs/superpowers/specs/2026-10-26-zeroauthy-social-connections-design.md`.

## Configure a connection

Create connections through `POST /api/v2/connections`, the seed (`options:`
plus `display_name`/`show_as_button`), or the console (**Social**). Every
strategy needs your own provider `client_id` and `client_secret`; zeroauthy has
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
previous one), token type, scope and expiry are stored encrypted per identity
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
the remaining social providers (deferred; no plan number assigned), One Tap/native token exchange, automatic linking,
provider-initiated login, federated logout or revocation, organizations, MFA,
Actions, Token Vault, development keys, arbitrary upstream parameter
forwarding, front-channel OIDC and the remaining enterprise OIDC features (Plan
36).
