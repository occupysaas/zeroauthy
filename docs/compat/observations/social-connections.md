# Social connections compatibility inventory

Reviewed 2026-10-26 for Plan 24 Task 1. The executable contract is
`internal/federation/inventory.json`. It freezes intended implementation behavior;
Task 1 does not implement or prove provider login.

## Evidence boundary

This is a public-source review, not a tenant observation. No separate observer
report for these strategies was supplied, and this implementer made no tenant,
provider authorization/token, dashboard or hosted-page request. No live success,
undocumented default, provider error identifier or conformance claim is inferred.
Existing connection/user observations describe previous database behavior only.
All local restrictions below are implementation decisions, not observed parity.

## Public contracts

- [Create connection](https://auth0.com/docs/api/management/v2/connections/post-connections)
  and its `.md` OpenAPI expansion define the strategy enum, purpose objects and
  immutable connection name. `ConnectionAuthenticationPurpose` requires
  `active: boolean`; `authentication.active: false` denies authentication.
  `connected_accounts.active` does not enable authentication. Scalar
  `authentication: false`, null, or an invented `enabled` alias is malformed.
  Existing connrules already persists `authentication.active`, so this spelling
  preserves the current model.
- [Custom OAuth](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/oauth2)
  documents `authorizationURL`, `tokenURL`, `scope`, `scripts.fetchUserProfile`,
  `pkce_enabled`, `authParams`, `authParamsMap` and `customHeaders`. Scope is a
  space-separated configured string. Its Google example confirms boolean `email`
  and `profile` plus a `scope` array. Only these two Google scope flags are active
  locally; their default is true and the resulting default is
  `openid profile email`. `openid` is mandatory locally. An explicitly supplied
  Google scope array must agree with the flags. Extra API scopes and enabled
  permission flags are rejected, rather than silently failing to request them.
- [OIDC connection configuration](https://auth0.com/docs/authenticate/identity-providers/enterprise-identity-providers/oidc)
  identifies back-channel/discovery and requires openid; its currently fetched
  back-channel example headings lack code. The separate
  [PKCE configuration reference](https://auth0.com/docs/authenticate/identity-providers/enterprise-identity-providers/configure-pkce-claim-mapping-for-oidc)
  supplies an actual Management create example with `type: back_channel`,
  `discovery_url`, `client_id`, `client_secret`, **`scopes: "openid profile"`**,
  and `connection_settings.pkce`. This resolves spelling independently of SDK
  guesses. Locally only back-channel discovery is supported; `scopes` is a
  required space-separated string containing openid. `scope` is not an alias.
  `connection_settings.pkce` accepts s256/auto, both requiring S256; disabled and
  plain are rejected. Nonce is always sent and checked. Manual issuer metadata,
  arbitrary claim mapping, front-channel and other client-auth overrides fail
  configuration rather than being accepted inertly.
- [Update connection](https://auth0.com/docs/api/management/v2/connections/patch-connections-by-id),
  the OAuth documentation's complete-options warning, and the pinned CLI agree
  that supplying options replaces the object. Local exception: omitted
  client_secret preserves sealed credentials; empty/null fails. Omitted options
  preserves all options. A supplied replacement must retain required immutable
  client ID/endpoints/script. Other omitted nonsecret values are removed/defaulted
  under validation; no merge that accidentally retains an omitted unknown field.
  Strategy, name, provider client identity and upstream binding are immutable.
- Connection CRUD uses existing create/read/update/delete:connections scopes.
  [Enabled-client GET](https://auth0.com/docs/api/management/v2/connections/get-connection-clients)
  returns `{clients:[{client_id}],next?}`; [PATCH](https://auth0.com/docs/api/management/v2/connections/patch-clients)
  accepts `{client_id,status}` entries and returns 204. Connection create returns
  201, update/read 200 and delete 204. Existing page/totals behavior remains.
  [Connection listing](https://auth0.com/docs/api/management/v2/connections/get-connections)
  also has checkpoint `{connections:[...],next?}` responses. Presence of take or
  from selects checkpoint locally and wins over page/per_page. Start with take
  and no from; take defaults to 50 when omitted and accepts 1–100. Continue with
  the previous next unchanged as from. Terminal/empty pages omit next entirely.
  Checkpoint mode ignores include_totals even when true and omits offset
  start/limit/length/total fields. This preserves the existing handler and the
  pinned SDK's connections/next iteration; it is now frozen in the operation row. Public schemas gate
  options with read:connections_options, and Deploy CLI warns about both read
  and update options scopes. This plan preserves existing local nonsecret options
  projections under ordinary connection scopes; that is a recorded difference,
  not a claim to implement these additional gates. Provider secrets are always
  write-only, including exports, regardless of scope.

## IDs, profiles and tokens

Public [user profile structure](https://auth0.com/docs/manage-users/user-accounts/user-profiles/user-profile-structure)
explains identity connection/provider/user_id/isSocial/profileData fields.
[Unlink reference](https://auth0.com/docs/api/management/v2/users/delete-user-identity-by-user-id)
uses `google-oauth2|<subject>` as its example. The reviewed permitted documentation
does not establish all generic OAuth/OIDC serialization/delimiter behavior.
These are explicitly local formats: Google `google-oauth2|<sub>`, custom OAuth
`oauth2|<connection-name>|<subject>`, OIDC `oidc|<connection-name>|<sub>`.
Identity.user_id is the suffix after the first provider separator: Google raw
subject, OAuth/OIDC `connection-name|subject`. Internal uniqueness is always
immutable connection ID plus raw subject, never public ID or email.

Connection names cannot contain `|`. Subjects are case-sensitive valid UTF-8,
nonempty, at most 1024 bytes and without NUL; embedded `|` is allowed. Parse only
the fixed provider and connection prefixes, preserving the remaining subject
bytes exactly (for example an upstream subject `auth0|abc` stays intact).
Do not split all separators, trim, lowercase, escape or remap imports. An import
must resolve exactly one connection and matching prefix; ambiguous/unresolvable
rows stop backfill/activation. A public-ID collision, including the same Google
subject through two connections, fails closed with a conflict; it never merges.
Existing MySQL user_id columns are VARCHAR(255) across users and dependent
tables; Task 3 must reconcile the larger composed public IDs and index-byte
limits across every reference before enabling this contract. This inventory does
not claim those old columns already support 1024-byte subjects.
Explicit linking retains its separate authorization and transactional ownership
rules. Unlink identifies the complete suffix, URL-encoded as one path segment.

[Get User](https://auth0.com/docs/api/management/v2/users/get-users-by-id)'s expanded
`UserIdentitySchema` defines **string** `access_token`, `refresh_token`, and
`access_token_secret`, each gated by read:user_idp_tokens. The
[IdP API guide](https://auth0.com/docs/authenticate/identity-providers/calling-an-external-idp-api)
requires read:users plus read:user_idp_tokens and individual GET. Therefore the
local projection is exactly `identities[].access_token` and
`identities[].refresh_token`, omitted when absent or unauthorized, with no-store.
OAuth2/OIDC has no access_token_secret. No invented nested tokenset, refresh-token
array, expires_in or token_type response property is added. Persist token type,
scopes and expiry only in encrypted records. Omitted refresh preserves the
previous token; a new refresh replaces it. No refresh scheduling is implemented.
The upstream unlink schema also declares scoped token fields; local link/unlink,
all list/search/by-email/job/export responses, userinfo, local tokens and console
exclude tokens even with the scope. This stricter projection is intentional.
Google/OAuth have isSocial=true; OIDC has isSocial=false.

## Script compatibility and unsupported settings

The public OAuth example supplies
`function fetchUserProfile(accessToken, context, callback)` and
`request.get(options, callback)` with Authorization headers, response.statusCode
and a JSON string body. Callback profile user_id is required. The local broker
also supports `request({method:'GET', ...}, callback)` and optional boolean json
parsing. Four requests, five seconds, bounded headers/body and the shared public
network policy apply; redirect following is disabled. Arbitrary npm/direct
fetch/http/net/files/subprocesses are unavailable. Node >=25 and a real network
denial probe are prerequisites, without fallback to customdb's process.

Public documentation does not enumerate the full context shape. The explicit
local allowlist is scalar token response access_token, refresh_token, token_type,
scope, expires_in and id_token, only when present. id_token is opaque here;
custom OAuth is not an OIDC validation mode. No client secret or unrelated
configuration enters context. Only stable user_id and typed email,
email_verified, name, nickname, given_name, family_name and picture become root
fields. Explicit user_metadata is bounded to 16 KiB/depth 8; arbitrary extra
claims are ignored. Privileged app_metadata, blocked, identities, passwords and
local authorization claims cannot be assigned. Field/size limits are local and
machine-readable in the inventory. Profile sync defaults on_each_login;
on_first_login/never_on_login retain the initial profile locally. The SDK's
never_on_login prose suggests no provisioning upstream; first provisioning here
is an approved local difference.

[Parameter forwarding](https://auth0.com/docs/authenticate/identity-providers/pass-parameters-to-idps)
documents upstream_params value/alias maps; OAuth docs also document authParams
and authParamsMap. Locally these maps can round-trip only as explicitly diagnosed
inert settings. Known OAuth protocol overrides, domain restriction or required
custom authentication settings are rejected (inventory has the exact reserved
keys). Assurance parameters acr_values, max_age, claims and prompt are explicitly
rejected for every value, including max_age=0, null/empty and all prompt values
(login, consent, select_account, none). This applies to map targets and dynamic
aliases before inert storage, so an unsupported assurance or reauthentication
request cannot silently become inert. Unknown harmless Extra values may
round-trip but never affect login.
customHeaders and fieldsMap cannot silently substitute for client authentication
or the required script. Google hd is a provider hint only. Configured Google
social domain restrictions are rejected because this task freezes no supported
restriction option. Extra scopes, development keys, Token Vault and federated
logout/revocation remain unavailable. Google offline issuance is not promised:
no arbitrary access_type/connection_scope forwarding is implemented.

## Pinned licensed tools: source review, not executed compatibility lanes

No vendor code was copied or adapted. License texts were inspected; these are
MIT source/test clients permitted by CLEAN_ROOM.md. Paths below are package paths.

- **node-auth0 7.4.0**, [repository/tag](https://github.com/auth0/node-auth0/tree/v7.4.0),
  package.json and LICENSE; inspected
  `dist/esm/management/api/{types/types.d.mts,resources/connections/client/Client.mjs,resources/connections/resources/clients/client/Client.mjs,resources/users/client/Client.mjs}`.
  Connections list/create/get/update/delete send GET/POST/GET/PATCH/DELETE;
  list uses strategy array/name/fields/include_fields and take/from checkpoint
  pagination, default take=50/include_totals=true. `connections.clients.get(id)`
  and `.update(id, entries)` use dedicated clients endpoints. `users.get(id)` is
  the scoped token lane; link/unlink preserve their distinct authorization.
  OptionsOAuth2 confirms scripts.fetchUserProfile, authorizationURL/tokenURL and
  accepts scope string or array; local support is string only. OptionsGoogleOAuth2
  has many API flags beyond the local email/profile subset. OptionsCommonOidc
  calls its scope field **scope**, conflicting with the documented **scopes**.
  The index signature permits sending documented scopes; no SDK-only alias is
  implemented. Public primary docs govern.
- **auth0-cli 1.37.0**, MIT,
  [commit a6239f9](https://github.com/auth0/auth0-cli/tree/a6239f907a81238e081a4abb1882c028558b2655),
  Go module download metadata and LICENSE; inspected `internal/cli/connections.go`
  and JSON-input helpers. Exact commands: `auth0 connections list --query`,
  `create --data @connection.json`, `show <id>`, `update <id> --data @connection.json`,
  `delete <id>`, `enabled-clients show <id>`, `enabled-clients update <id> --data @clients.json`,
  all with --json where supported. Create/update accept inline/@file/stdin JSON;
  they do not load a nested profile script path. Scripts must be source inside
  options.scripts.fetchUserProfile in the JSON. Show/update use raw JSON to retain
  strategy-specific options; immutable id/name/strategy are stripped from the
  interactive update editor. `auth0 api get users/<encoded-id>` exercises GET user.
- **auth0-deploy-cli 9.1.0**, MIT,
  [commit b8178b4](https://github.com/auth0/auth0-deploy-cli/tree/b8178b4bf48f31d05e61f55918bba75d4c846c37),
  LICENSE/package source provenance also recorded in management-deploy-cli.md.
  Inspected `lib/tools/auth0/handlers/connections.js`,
  `lib/context/{yaml/index.js,yaml/handlers/connections.js,directory/handlers/connections.js,defaults.js}`.
  Exact resource key **connections** excludes strategy auth0 (databases has its
  own handler), matches IDs/names and remaps enabled client names to IDs. Its
  enabled-client helper reads checkpoint pages and writes chunks of 50 statuses;
  an empty desired ID list is skipped by the helper, a gap Tasks 11–12 must test.
  `getType` also fetches connection directory-provisioning discovery and applies
  SCIM enrichment. This is an extra required tool dependency, not a claim it is
  supported or safely replaced by an empty successful shim.

The Deploy connection YAML/directory handlers special-case email template files,
not social profile scripts. YAML's general !include parses YAML, so a script file
must be a YAML scalar source file (for example a `.yaml` literal block); a `.js`
path string is not automatically loaded. Directory JSON has no profile-script
file expander. Tasks 11–12 must explicitly materialize external JS source into
options.scripts.fetchUserProfile for directory JSON, and use a YAML scalar include
or explicit materialization for YAML. Export keeps profile scripts inline; the
strict comparison must compare source, not discard it or normalize it away.
`connectionDefaults` masks client_secret unless AUTH0_EXPORT_SECRETS is enabled;
zeroauthy never supplies provider secrets even in that mode. Migrations therefore
need explicit protected provider-secret reinjection in all four
YAML/directory × generated/preserved application credential lanes. CLI runtime,
round-trip scripts and post-import provider login are deferred to Tasks 11–12.

## Google protocol and changelog evidence

[Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect)
explicitly sends client_id/client_secret in the form POST body: client_secret_post
is the selected client authentication. It describes stable sub, issuer aliases,
optional refresh_token and offline requirements. Its hd warning means hints do
not enforce domain policy. [Google PKCE](https://developers.google.com/identity/protocols/oauth2/native-app)
documents S256 challenge/verifier behavior at the Google OAuth endpoints. That
page targets public desktop clients; the confidential-web-client combination
has not been live-tested. S256 remains the mandatory local subset, not observed
provider compatibility. No downgrade is permitted. [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
sets basic as the omitted client-auth default; advertised basic is preferred,
otherwise advertised post is used; unsupported-only discovery fails closed.

The earlier design's oversized web-tool changelog retrieval remains unsuccessful.
A separate urllib public HTML retrieval on 2026-10-26 succeeded: 4,434,886 bytes,
SHA256 `af39d38106c49af3aecee7ededf8a02808897e03cdc8f8a6717fa3713a79f1a8`.
Text extraction included dated entries, not just search snippets. One entry newer
than October 22: October 26 Identity Conversion Suite EA (anonymous sessions and
experimentation), outside Plan 24 and recorded in changelog backlog. The
reviewed-through date advances to October 26. No new social wire-contract change
was found in this interval. Raw third-party HTML remains outside the repository.
