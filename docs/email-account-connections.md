# Microsoft and Google account sign-in

Use these connections to let people sign in with their Microsoft or Google
account. They authenticate accounts; they do not connect an inbox, send mail,
read calendars or synchronize directories. Outbound email configuration is
covered separately in [email.md](email.md).

| Accounts | Strategy | Console section |
|---|---|---|
| Microsoft personal, including Outlook.com, Hotmail and Live | `windowslive` | Social |
| Microsoft Entra / Microsoft 365 work and school | `waad` | Enterprise |
| Gmail, Google accounts using another email address, Google Workspace | `google-oauth2` | Social |

Google Workspace uses the existing Google connection. This does not add the
separate `google-apps` enterprise strategy. Microsoft personal accounts can
also use addresses outside the Outlook/Hotmail domains. Email suffixes do not
select account type or authorize membership.

## Configure the upstream application

Register a confidential Web application in the provider's administration
portal. For Microsoft, choose supported account types that match the
connection: personal accounts for `windowslive`, one organizational directory
for single-directory `waad`, or any organizational directory for multitenant
`waad`. This implementation uses public-cloud Microsoft identity platform v2
code flow with S256 PKCE. It does not require implicit/hybrid grants.

Register the exact callback URLs shown in the console. Each canonical or
active custom login domain needs its own `https://<host>/login/callback`.
The callback stays bound to the origin where login began; another alias is
not an interchangeable callback. Keep domains/certificates active throughout
login.

Copy the application/client ID and the client secret **value**, not its
portal identifier. For Microsoft, the client ID must be a GUID. Record secret
expiry outside zeroauthy and rotate it before expiry. Rotation invalidates
outstanding login attempts. Ordinary connection reads and exports omit the
secret; they cannot recover it for you.

Enable the connection for the intended zeroauthy applications. New
applications are not implicitly enabled on a connection. Users can select a
visible button, or applications can choose a usable hidden connection with
`/authorize?connection=<connection-name>`.

## Microsoft personal accounts

Create a Social connection using `windowslive` with `client_id` and
`client_secret`. `strategy_version` may be omitted or integer `2`. The adapter
uses the `consumers` authority. Legacy Live Connect/version 1 is unsupported.
The requested scopes are exactly `openid profile email`. An optional `scope`
array must match that set; extra API scopes and `offline_access` are rejected.

## Microsoft work and school

Create an Enterprise connection using `waad`. Supply credentials and select:

- **Single directory:** set `tenant_domain` to the directory GUID or ASCII
  directory DNS name. The discovered concrete issuer is pinned. A GUID is
  preferred when you already know the directory identifier. The consumer
  tenant, URLs and reserved selectors are not valid directory settings.
- **Any organizational directory:** set `useCommonEndpoint: true` and omit
  `tenant_domain`. Despite that historical option name, the adapter uses
  `organizations`, not `common`. Every organizational tenant is eligible;
  there is no implicit allowlist. Personal accounts are excluded.

Optional supported fixed settings are `identity_api:
"microsoft-identity-platform-v2.0"`, `waad_protocol: "openid-connect"`,
`userid_attribute: "oid"` and `use_wsfed: false`. Omission selects those
supported defaults. `domain` is display metadata only. It does not restrict
email addresses or tenant membership. Guests authenticate as identities in
the resource tenant that issued the token.

Client ID, authority mode and directory binding are immutable. Create a new
connection for a different binding and explicitly migrate/link identities;
editing the old connection cannot silently reinterpret existing users.
Credential rotation and application enablement remain editable.

This subset does not implement Graph/group/extended profiles, directory APIs,
WS-Fed, sovereign clouds, B2C/custom policies, home-realm discovery,
certificate client authentication or email-verification trust overrides.
Unsupported authentication-critical options are rejected. Stored-only
metadata never activates those features. Arbitrary upstream `prompt`,
`claims`, `acr_values` and `max_age` forwarding is not supported.

## Profiles and account ownership

Microsoft may not return email. Login can succeed without it; the adapter
does not substitute `preferred_username` or UPN. Microsoft email is not marked
verified by this subset, including when an optional upstream verification
claim appears. Google retains its existing validated email verification.
Email changes do not change account identity and equal emails never merge
accounts automatically.

The local identity contracts are:

| Strategy/mode | Indexed subject | New public user ID |
|---|---|---|
| Microsoft personal | case-sensitive `sub` | `windowslive\|<sub>` |
| Entra single directory | lowercase `oid` | `waad\|<connection>\|<oid>` |
| Entra any organization | lowercase `tid:oid` | `waad\|<connection>\|<tid>:<oid>` |
| Google | case-sensitive `sub` | `google-oauth2\|<sub>` |

Personal and Google `identities[].user_id` contain the raw subject. Entra
contains `<connection>|<indexed-subject>`. These are explicit local migration
contracts; do not assume legacy Live/Graph IDs or every Auth0 multitenant
configuration has the same encoding. See the [compatibility observations](compat/observations/email-account-connections.md).

Database-destination bulk imports can explicitly include canonical secondary
federated identities with exactly `connection`, `provider` and `user_id`.
Unknown connections, malformed/mode-inconsistent subjects and ownership
conflicts reject the record before mutation. An upsert may retain the same
identity set; it cannot transfer or remove identities implicitly. Federated
bulk-import destinations remain unsupported. Explicit linking is available
through the existing identity endpoints.

Upstream tokens are encrypted. Ordinary list/search/user reads do not expose
them. Individual-user reads require `read:user_idp_tokens` for token
projection. No refresh-token issuance or refresh worker is promised because
this subset does not request offline access.

## Upgrade and plugin compatibility

Back up before rollout and drain all old writers. Upgrade every serving node
and storage plugin before enabling Microsoft connections. A new additive
capability probe checks the actual backing store's Microsoft identity-index
support; Plan 24 federation RPCs alone are insufficient. An old plugin fails
closed for Microsoft operations. A predecessor-only deployment can continue
using its existing strategies without the new capability.

Startup runs a read-only preflight before applying seed data or serving
traffic. Existing Microsoft connections require the capability. Existing
Microsoft identities must already have resolvable canonical encodings and
matching index ownership. Unindexed or ambiguous legacy identities stop
startup with a sanitized operator diagnostic; there is no automatic
conversion. Resolve mappings explicitly before restarting. Historical
migration 0021 is not rewritten to guess these mappings.

After upgrade, register callbacks, apply configuration/secret values and
perform a sign-in through each enabled connection. A capability probe cannot
fence an independently running old binary. Do not roll back to an old writer
against data using new Microsoft identity semantics; restore/reconcile under
maintenance instead.

## Rollout checklist

1. Back up the database and drain every old writer (nodes and plugins).
2. Run the read-only preflight (normal startup performs it before seeding
   or listening) and resolve any reported unknown Microsoft identities
   explicitly.
3. Upgrade every node and storage plugin.
4. Seed or create the Microsoft connections, enable them for applications
   and register each exact callback upstream.
5. Sign in through every enabled connection before serving traffic.

Rolling back to a binary that does not maintain Microsoft federation indexes
is unsafe; restore a compatible backup and reconcile instead.

## Migration with the Deploy CLI

Exports never contain `client_secret` or a mask. Import fails for a federated
connection without a secret, so a migration that loses credentials cannot
produce a configuration that looks complete but cannot log in. Stage a
private copy of the export and reinject each provider secret by connection
name from a separate private map before `a0deploy import`. Custom OAuth 2
profile scripts are exported inline by the pinned 9.1.0 tool; an explicit
`.js`/`file://` reference must point to a materialized file inside the
export, or staging fails. Both Microsoft modes and their immutable bindings
round trip. Identity user IDs embed the connection name, so keep connection
names identical across tenants. The local acceptance lane covers YAML and
directory formats with generated and preserved application credentials, and
signs in through every migrated connection afterward.

Users are not migrated by the Deploy CLI. There is no Graph or legacy
Live/Azure AD identifier compatibility; imported users must use the
canonical identity formats above.

## Validation and troubleshooting

Provider denial, malformed tokens, timeouts or failed tenant/key-issuer checks
require a fresh attempt. Token POSTs are not retried after ambiguous delivery.
Check application account types, callback registration, secret value/expiry,
connection enablement and single/any-directory mode first. Do not paste tokens
or secrets into logs or diagnostic reports. Local fixture acceptance is
separate from optional live-provider checks; see the [implementation record](superpowers/2026-10-26-plan-25-implementation-record.md)
for actual results and remaining checks.
