# Email-account connection contract — 2026-10-26

Plan 25 Task 1 freezes `internal/federation/email_accounts_inventory.json` as an
extension of Plan 24's inventory, not proof of runtime implementation. No live
Auth0 tenant observation or authenticated Microsoft/Google flow was performed.
Public discovery/JWKS metadata retrieval is source review, not sign-in evidence.
No vendor source was copied or adapted.

## Public-source review

- [Microsoft OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
  describes v2 authorities and discovery/code flow. The explicit public
  [organizations metadata](https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration)
  retrieved during this review advertises the exact tenantid issuer template,
  RS256, query response mode and client_secret_post. It also advertises other
  authentication methods/scopes; our fixed secret-post/scopes subset is local.
- [Microsoft validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
  describes GUID tenant binding, exact expanded issuer matching and JWK issuer
  restrictions. The public [JWKS](https://login.microsoftonline.com/common/discovery/v2.0/keys)
  was retrievable. Preserve key issuer metadata; never treat access tokens as
  authentication claims. Strict single-key eligibility and network/cache bounds
  are local policy, not Auth0 parity evidence.
- [ID-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)
  and [Google reference](https://developers.google.com/identity/openid-connect/reference)
  distinguish account identifiers from optional mutable profile data. Google
  `hd` does not introduce a local domain restriction. Microsoft verification
  remains conservative false/absent under our explicit local trust policy.
- [Auth0 Entra guide](https://auth0.com/docs/authenticate/identity-providers/enterprise-identity-providers/azure-active-directory/v2)
  documents enterprise setup/callbacks. The public
  [configuration troubleshooting article](https://support.auth0.com/center/s/article/Azure-Entra-Connection-Error-AADSTS900023-Specified-tenant-identifier-undefined-is-neither-a-valid-DNS-name-nor-a-valid-external-domain)
  contains string `identity_api`, `waad_protocol`, `tenant_domain`, and boolean
  `useCommonEndpoint`/`use_wsfed` in JSON examples. This confirms casing/types,
  not all server validation/defaults. It also shows trust/Graph options that
  this implementation explicitly rejects when enabled.
- [Personal account troubleshooting](https://support.auth0.com/center/s/article/Windows-Live-Error-Error-retrieving-AzureAD-profile)
  was retrievable; it distinguishes modern AzureAD-profile behavior from legacy
  Live Connect. It does not establish our `strategy_version: 2` validation or
  legacy identifier equivalence. The [userid option article](https://support.auth0.com/center/s/article/Updating-userid-attribute-in-Connection-not-Allowed)
  returned only a loading/CSS-error shell, so it supplies no confirmed evidence
  here. The Management create `.md` URL was inaccessible through the web tool.
  The draft's guessed personal-account docs URL remains unreviewed.

## Pinned MIT clients — source hints only

Reviewed installed package/source files; licenses and pins retain the predecessor
provenance in [social-connections.md](social-connections.md). No compatibility
lane was run for this documentation task.

- [node-auth0 v7.4.0](https://github.com/auth0/node-auth0/tree/v7.4.0),
  `dist/cjs/management/api/types/types.d.ts`: WindowsLive strategy_version is
  **number**; local validation deliberately narrows it to integer 2. AzureAd
  identity_api/waad_protocol/userid_attribute are string enums; tenant_domain
  is string-shaped and useCommonEndpoint is boolean. SDK hints list oid/sub,
  v1/v2 and WS-Fed/OIDC; their existence does not authorize implementing them.
  In particular its common-endpoint prose requires **sub**, whereas this local
  design selects **tid:oid**, organizations-only. No Auth0 parity is claimed
  for that choice. Public retrieval did not confirm userid_attribute semantics;
  oid support/default here is an explicit local contract.
- [auth0-cli v1.37.0, a6239f907a81238e081a4abb1882c028558b2655](https://github.com/auth0/auth0-cli/tree/a6239f907a81238e081a4abb1882c028558b2655),
  `internal/cli/connections.go`: JSON --data create/update path and raw show
  preserve strategy-specific options; schema validation is a client dependency,
  not evidence of provider runtime behavior. No new interactive Microsoft
  semantics were inferred from the tool.
- [auth0-deploy-cli v9.1.0, b8178b4bf48f31d05e61f55918bba75d4c846c37](https://github.com/auth0/auth0-deploy-cli/tree/b8178b4bf48f31d05e61f55918bba75d4c846c37),
  `lib/tools/auth0/handlers/connections.js` and
  `lib/context/{yaml,directory}/handlers/connections.js`: generic connections
  resources preserve option objects, remap enabled clients and apply secret
  defaults. Passwordless email file expansion is not a Microsoft profile script
  facility. Required secret reinjection and strict five-strategy migration
  acceptance remain later plan tasks, not passing results here.

## Deliberate local contract

The machine inventory lists four audiences, exact scopes, identity encodings,
immutable options, false-only inert flags, rejected security options and trust
rules. Rows ending `_false` or `_true`, `_1`, `_v1`, `_sub`, `_extra`, `_wsfed`
are value-specific policy cases of the named wire option, not new wire keys.
For example ext_groups is accepted inert only for false; true is rejected.
No unknown Extra field may bypass these policy cases. Authentication and
application enablement rows describe existing connection fields rather than
new nested options.

Microsoft is public-cloud v2 only, ID-token-only, with no Graph/profile script,
mailbox access or required email. No implicit linking/merging, trust override,
arbitrary upstream assurance, endpoint override, domain authorization or
refresh-token guarantee is offered. Personal sub is case-sensitive; Entra oid
and tid are canonical lowercase GUIDs. Single-directory public IDs are
`waad|<connection>|<oid>`; organizations IDs are
`waad|<connection>|<tid>:<oid>`. Personal and Google retain raw-subject formats.
These encodings are local, with no legacy Live/Graph/Auth0 migration claim.
A capability/preexisting-data preflight precedes activation; old writers must
be drained. No migration 0021 rewrite is authorized.

## Changelog boundary

The actual preceding reviewed-through date is already **2026-10-26** (Plan 24
Task 1), not October 22. On this same date, a fresh public changelog web-tool
request exceeded its size limit. No newer interval exists to claim reviewed;
coverage remains 2026-10-26 on the prior successful full-page review. This
failed retrieval does not advance coverage or establish absence of new entries.
