# zeroauthy — Plan 25: Microsoft and Google email-account sign-in

- **Status:** Draft for review; implementation has not started.
- **Date:** 2026-10-26.
- **Predecessor:** [Plan 24 implementation record](../2026-10-26-plan-24-implementation-record.md).
- **Plan:** [Implementation tasks](../plans/2026-10-26-zeroauthy-plan-25-email-account-connections.md).
- **Requested scope:** Prioritize Microsoft work/school, Outlook/Hotmail and Google accounts. Move the remaining social providers to a later plan.

## 1. Intent and boundaries

An operator can offer Microsoft personal-account, Microsoft work/school-account and Google sign-in to an application. A person chooses a provider, authenticates there and returns through the existing zeroauthy authorization flow. The provider establishes identity; an email address is optional profile data, not an account key or a reason to merge users.

This is authentication using accounts offered by email providers. It does not connect to an inbox, send email, import contacts or grant mailbox/calendar access. Plan 21's outbound email-provider configuration is separate.

Build on Plan 24's working Google, generic OAuth2 and back-channel OIDC support. Add two built-in Microsoft adapters over the shared federation service. Do not require operators to write profile scripts for Microsoft. Preserve existing Google identities, configuration and login behavior.

| Audience | Strategy | Classification | Deliverable |
|---|---|---|---|
| Microsoft personal, including Outlook.com, Hotmail and Live accounts | `windowslive` | Social, `isSocial: true` | Modern Microsoft identity platform v2 code flow through `consumers` |
| Microsoft 365 / Entra work and school | `waad` | Enterprise, `isSocial: false` | Single directory and explicitly enabled organizational multitenancy |
| Gmail and Google accounts using another email address | `google-oauth2` | Social | Retain adapter; add explicit acceptance coverage and setup guidance |
| Google Workspace work and school | `google-oauth2` | Social | Same existing adapter; prove Workspace profiles work without requiring a Gmail address |

Google Workspace sign-in here does not implement the separate enterprise `google-apps` strategy, directory synchronization or domain-restricted membership. Outlook and Hotmail are account brands, not separate strategies. Microsoft accounts registered with another email domain also work; suffixes do not classify accounts.

Designer choices, proposed for review: use the current Go 1.26.7 / Vue / JOSE / store stack, no new production OAuth framework; retain separate personal and work/school choices; use Microsoft's public cloud only; request only `openid profile email`; use ID-token claims without Graph profile calls. These choices keep the plan centered on sign-in and make missing email a supported result.

Alternatives considered: generic OIDC presets alone cannot provide safe organizational multitenancy or compatible strategy identities; one combined `common` Microsoft button obscures the personal/organizational policy boundary; implementing every social provider now would dilute the requested priority. Dedicated Microsoft adapters on the existing service are the selected approach.

## 2. Explicit non-goals and roadmap movement

- Apple, Facebook, GitHub, LinkedIn, X/Twitter, Amazon, Discord, Slack and other social providers move to an unnumbered future **Additional social providers** plan. Keep Plans 26–39 numbered as they are.
- Bring the `waad` sign-in subset forward from Plan 36. Plan 36 retains Okta, remaining enterprise OIDC, front-channel flows, home-realm discovery, connection keys/status and enterprise lifecycle features.
- No Azure AD v1, Live Connect, WS-Fed, SAML, B2C/External ID custom policies, sovereign clouds, custom signing keys, certificate client assertions, Graph groups/extended profiles, SCIM, HRD/domain aliases or automatic tenant onboarding.
- No automatic email linking, Microsoft-to-Google linking, domain-based authorization, email-verification override, upstream MFA assurance translation, arbitrary upstream parameters, refresh scheduling, Token Vault, One Tap, native token exchange, federated logout or revocation.
- Google domain restrictions remain rejected. No new `hd` or email-suffix policy; organizations/domains are not inferred from email. Required unsupported authentication/security options fail validation rather than being silently stored.

## 3. Evidence and compatibility discipline

Read `CLEAN_ROOM.md`. Public documentation consulted for this draft:

- [Microsoft OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc): account authorities and code-flow/discovery architecture.
- [Microsoft token validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens): tenant-independent issuer templates, tenant GUID binding and signing-key issuer restrictions. Apply its issuer/key rules to ID-token validation; do not authenticate with access-token contents.
- [Microsoft ID-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference): tenant/subject/object identity and optional, mutable email/profile fields.
- [Auth0 Entra connection guide](https://auth0.com/docs/authenticate/identity-providers/enterprise-identity-providers/azure-active-directory/v2): enterprise strategy scope and callback setup.
- [Auth0 Entra configuration troubleshooting](https://support.auth0.com/center/s/article/Azure-Entra-Connection-Error-AADSTS900023-Specified-tenant-identifier-undefined-is-neither-a-valid-DNS-name-nor-a-valid-external-domain) and [object-ID option](https://support.auth0.com/center/s/article/Updating-userid-attribute-in-Connection-not-Allowed): wire option names and `userid_attribute: oid`.
- [Auth0 Microsoft personal-account guidance](https://support.auth0.com/center/s/article/Windows-Live-Error-Error-retrieving-AzureAD-profile): modern personal-account strategy versus deprecated Live Connect. The guessed Microsoft-account docs URL was inaccessible; do not count it as reviewed evidence.
- [Google OIDC reference](https://developers.google.com/identity/openid-connect/reference): stable `sub`, optional profile fields and Workspace `hd` semantics.

No live Auth0, Microsoft or Google authentication observation was performed for this draft. Task 1 public-source review and retrieval limitations are recorded in [email-account evidence](../../compat/observations/email-account-connections.md). The pinned SDK describes common-endpoint `sub` selection; this plan deliberately retains organizations-only `tid:oid` as a local difference. The userid-attribute support page could not be retrieved as article content, so its semantics are not counted as confirmed public evidence. Task 1 records exact wire contracts, pinned SDK/tool provenance, documentation limitations and local deviations in a new email-account observation note and machine-readable inventory. SDK-only facts require public confirmation or authorized observation before being treated as compatibility. Read the predecessor's inventory rather than resetting its verified contracts. Review changelog entries since the recorded reviewed-through date; advance that date only for pages actually reviewed.

This plan targets a documented local subset, not full `windowslive`/`waad` parity. In particular: fixed scopes, no Graph enrichment, conservative email verification, organization-only multitenancy, and the multitenant identity encoding below are deliberate local decisions. Imported legacy Live IDs and Graph IDs must not be guessed from v2 `sub`. If source review contradicts a compatibility claim, correct the inventory/spec/plan together before implementing that claim; do not silently change account identity behavior.

## 4. Connection configuration and management

Use the existing `/api/v2/connections` CRUD, strategy filters, pagination, enabled-client endpoints, seed path and secret sealing. Add `windowslive` and `waad` to the same validation authority and generated API schema. Do not introduce a parallel provider resource. Existing PATCH replaces supplied nonsecret options and preserves an omitted sealed secret; null/empty secrets fail. Secrets remain write-only on reads/exports. Every effective authentication, credential or enabled-client change advances `FederationRevision` and invalidates outstanding attempts.

Common supported options: required `client_id` and `client_secret` on create, existing profile-sync policy (`on_each_login`, `on_first_login`, `never_on_login`), display/button settings, application enablement and `authentication.active`. Microsoft client IDs must be GUIDs. Keep database-only defaults out of these strategies.

| Strategy | Supported options and defaults | Immutable identity binding |
|---|---|---|
| `windowslive` | `strategy_version` absent or integer `2`; optional `scope` array must equal the set `openid`, `profile`, `email` | Strategy and client ID; personal authority is fixed |
| `waad` | `identity_api` absent or `microsoft-identity-platform-v2.0`; `waad_protocol` absent or `openid-connect`; `use_wsfed` absent or false; `userid_attribute` absent or `oid`; `useCommonEndpoint` boolean default false; required `tenant_domain` for single directory; optional `domain` is stored display metadata only | Strategy, client ID, authority mode, normalized tenant identifier and pinned single-directory issuer |

Single-directory `tenant_domain` accepts a GUID or a bounded ASCII DNS name (at most 253 bytes, standard DNS labels). Reject URLs, slashes, ports, query strings, reserved selectors `common`/`organizations`/`consumers`, and whitespace. Normalize GUIDs and DNS names to lowercase. Reject the consumer tenant GUID for single-directory waad as well. Discover against that configured authority, pin its concrete issuer with the existing connection-revision CAS, and subsequently require that exact issuer. A DNS alias does not become an email restriction.

For `useCommonEndpoint: true`, derive authority `organizations`, accept work/school tenants only and reject a supplied `tenant_domain` to avoid conflicting configuration. Despite the historical option name, this local subset never sends `common`: personal accounts use `windowslive`. Operators must register a multitenant upstream application explicitly. All organizational tenants are eligible in this mode; there is no inferred tenant allowlist. A guest authenticated in an allowed resource tenant belongs to that tenant's identity namespace; the guest's home email or `idp` claim does not change ownership.

Do not accept endpoint/discovery/issuer overrides for either Microsoft strategy. Reject version 1, different identity APIs/protocols, true Graph/group/API-enable flags, `offline_access`, extra scopes/freeform scopes, domain aliases, email-verification trust overrides and unsupported identity selectors. False optional capability flags may round-trip as inert only when named in the inventory. Existing reserved-parameter/assurance rejection applies, including `prompt`, `claims`, `acr_values`, `max_age` and aliases inside upstream maps. Unknown nonessential metadata follows existing bounded Extra rules with an explicit stored-only disposition; it must never alter runtime policy.

No single-directory/multitenant mode change, tenant change or client-ID change in place. Create a new connection and explicitly migrate/link identities. Credential rotation remains supported.

## 5. Microsoft protocol and trust boundary

Use HTTPS `login.microsoftonline.com` authorities and Microsoft v2 discovery with code/query response mode, S256 PKCE, independent state and nonce. Personal uses `consumers`; single-directory uses its validated identifier; multitenant uses `organizations`. Discovery issuer may be concrete or the exact Microsoft template `https://login.microsoftonline.com/{tenantid}/v2.0`. A template is allowed only in the Microsoft adapter, never generic `oidc`. Organizational multitenant discovery must return the exact template, not a concrete first-user issuer. Pin the template as a policy snapshot for a multitenant attempt; never pin a multitenant connection to the first user's tenant.

Before accepting discovery, require authorization/token/JWKS URLs to have host `login.microsoftonline.com`, HTTPS, default port, no credentials/fragments and the expected authority paths. Discovery may use `common` for a shared JWKS path; allow only the documented `/common/discovery/v2.0/keys` or the configured authority's `/discovery/v2.0/keys`, without query parameters. Authorize/token paths are `/{authority}/oauth2/v2.0/{authorize,token}`. Do not fetch UserInfo or Graph in this subset. Reject unexpected endpoint changes instead of broadening network access. Constructor-injected fixture endpoints remain available only to tests/harnesses, with no production API/environment switch.

Send exactly one client-auth method: `client_secret_post`, requiring advertised support. Keep upstream access tokens opaque. Validate the ID token using RS256 and a key fetched from the pinned JWKS; preserve raw JWK `issuer` metadata alongside the parsed JOSE key. Require one unambiguous eligible signing key. Reject token-supplied keys/URLs, `none`, HS256, mismatched algorithms/use, bad signatures, missing/invalid `kid`, and keys with missing/invalid Microsoft issuer metadata.

After signature verification require:

1. `ver: "2.0"`, a canonical lowercase GUID `tid`, and exact issuer `https://login.microsoftonline.com/{tid}/v2.0`.
2. Issuer matches the attempt's concrete issuer or the exact template expanded using verified `tid`. No arbitrary template/host/path substitution.
3. Signing-key issuer is the same concrete issuer, or the exact Microsoft template expanded to it. A consumer-scoped key cannot validate another tenant's token.
4. Personal `tid` equals `9188040d-6c67-4c5b-b112-36a304b66dad`; organizational multitenant rejects that `tid`; single-directory token matches the pinned directory issuer, including guest login in that resource directory, and rejects the consumer tenant GUID.
5. Audience/azp, exp, iat, nonce, nonempty case-sensitive sub and optional at_hash satisfy existing validation. Also validate present `nbf`; numeric dates use the existing 60-second skew. Work/school `oid` is a GUID. No user or token writes occur before all checks succeed.

Unverified `tid`, `iss` or other claims never choose a discovery host, request URL or persistent identity. Reuse bounded network access: public pinned IPs, no redirects/proxy, 10 seconds/request, 30 seconds callback total, 1 MiB decoded response, 100 JWKS keys, 64 KiB token/profile values. Cache keys include tenant, immutable connection ID, revision, authority policy and JWKS URL; TTL at most five minutes, maximum 256 entries, one coalesced unknown-kid refresh. Generic OIDC retains exact-issuer matching and does not gain Microsoft exceptions.

## 6. Identity and profile behavior

Reuse `(local tenant, immutable connection ID, normalized provider subject)` index and transactional ownership checks. Identity encodings below are proposed local contracts, not verified legacy Auth0 migration formats:

| Strategy / mode | Indexed subject | `identities[].user_id` | New local public `user_id` |
|---|---|---|---|
| Microsoft personal | Verified ID-token `sub` | `<sub>` | `windowslive|<sub>` |
| Entra single-directory | Lowercase verified `oid` | `<connection>|<oid>` | `waad|<connection>|<oid>` |
| Entra organizational multitenant | `<lowercase tid>:<lowercase oid>` | `<connection>|<tid>:<oid>` | `waad|<connection>|<tid>:<oid>` |
| Google, unchanged | Verified `sub` | `<sub>` | `google-oauth2|<sub>` |

OID/tenant GUID normalization is distinct from arbitrary personal/Google `sub`, which remains case-sensitive. Multitenant identities must distinguish equal `oid` or `sub` across tenants. Both Entra modes still require valid OIDC `sub`; `oid` is the selected account key. Preserve raw `sub` in validated internal claims only; never switch lookup keys because another claim is present. Existing Google/OAuth/OIDC formats remain byte-for-byte unchanged.

Extend the store's identity formatter/parser, linking, unlinking, import and deletion paths together. Strip only the exact connection prefix. Windows Live uses the raw-subject exception alongside Google. Imported Microsoft identities must match the configured mode/encoding; malformed entries fail before mutation. Do not auto-convert preexisting unindexed `waad`/`windowslive` identities. Add a read-only upgrade preflight before enabling these strategies; abort rollout with a sanitized diagnostic if such identities exist. An operator must explicitly resolve their mapping first. Existing migration 0021 must remain unchanged; implement this as an application-level federation startup preflight covering every store, not a retroactive SQL migration. No SQL schema expansion is expected. Database-destination bulk imports may explicitly supply `identities` as an array of at most 100 secondary federated objects containing exactly `connection`, `provider` and canonical `user_id`. The database root and password-import rules remain unchanged; provider credentials and profile fields are not accepted in these objects. Validate all identities and Microsoft capability before writing the record. Omission preserves an upsert's identities; a supplied array, including an empty array, must exactly match the existing federated ownership set on upsert. Ownership changes require explicit account linking. Federated destination connections remain unsupported by the bulk importer. Add an optional store capability interface `MicrosoftFederationSupporter` with `MicrosoftFederationSupported(context.Context) error`, implemented by updated memory/SQL stores and the gRPC client. An additive gRPC `MicrosoftFederationSupported` RPC must check the actual backing store's capability, not just the wrapper version. Missing interface/RPC, Unimplemented or transient probe failure is unsupported; never infer support from an empty store or cache a failed probe as success. Probe before Microsoft connection creation/enabling (including seed/import), before Microsoft identity mutation and before starting a Microsoft attempt. At startup, an existing Microsoft connection/identity requires a successful probe before serving; a store with no Microsoft data may continue serving predecessor strategies even if this new capability is absent. Drain old writers before rollout; a capability probe does not fence an independently running old process.

Map only present, typed ID-token `email`, `name`, `given_name` and `family_name` through existing profile validation/synchronization. Email may be missing for a work/school account. Never substitute `preferred_username`, UPN, `oid`, `sub` or an `@outlook.com` suffix as a verified email. Microsoft email verification is false/absent even if an optional `email_verified` claim appears: this subset has no established verification trust policy. It must not inherit `true` from a previous changed address. Never copy upstream roles, groups or arbitrary claims into local authorization/app_metadata.

Google keeps current validated email/email_verified mapping. Prove both a Gmail fixture and a Workspace fixture carrying `hd`, plus a Google account with a non-Gmail email. No new scope or workspace restriction is required. No required-email check, automatic linking or account merging is added for any provider.

Seal tokens with existing tenant/connection/identity-bound wrapping. Ordinary user/list/search responses omit them; individual-user reads require existing `read:user_idp_tokens`. New strategies project correct `provider`/`isSocial` on primary and linked identities. No guaranteed refresh token because this plan does not request `offline_access`.

## 7. Hosted login, protection and console

Reuse `/authorize?connection=<name>`, CSRF-protected `POST /u/login/social`, GET `/login/callback` and existing local session/consent/code completion. Work/school being enterprise does not exclude it from federated choices. Support explicit hidden connections, provider-only applications and coexistence with database login. Default labels are original text: “Microsoft personal account”, “Microsoft work or school account” and “Google”; a configured display name takes precedence.

Preserve state/cookie/origin/tenant binding, single-use claims, attempts expiring at min(transaction expiry, five minutes), identity epoch and final transactional config/user checks. Both new strategies must participate in every existing federation strategy dispatch, including seed, callback, identity/token cleanup and import. Disabled client/connection, secret rotation, user block/deletion, unlink/transfer or custom-domain removal during exchange fails closed. No network I/O inside a store transaction and no ambiguous token-exchange retry.

Preserve Plan 24's attack protection, CAPTCHA and suspicious-IP checks; provider failures never count as bad local passwords. `prompt=none` cannot initiate upstream interaction. Do not claim stronger `prompt=login`/upstream reauthentication assurance than the shared flow currently supports; arbitrary assurance forwarding stays rejected.

Console keeps Google and Microsoft personal under Social and shows Microsoft work/school under Enterprise. Generic OIDC retains its current subset label/route. Add provider selection, v2-only guidance, explicit single-directory versus any-organization mode, tenant/client/secret fields, app enablement and callback URLs for canonical/custom domains. Explain that any-organization mode accepts every organizational directory and that email may be missing. Never present stored-only options as functional or show secret placeholders as actual credentials. Provider-specific validation and field serialization must agree with API/seed rules; no profile script editor for Microsoft.

## 8. Migration and acceptance

Carry forward Plan 24's missing strict Deploy CLI federation lane. Cover YAML and directory formats, generated and preserved application credentials, provider-secret reinjection and materialized generic OAuth scripts. Include all five strategies (`google-oauth2`, `oauth2`, `oidc`, `windowslive`, `waad`); this retains baseline coverage while focusing new runtime work on email accounts. Imports must still authenticate; an export/import that only preserves labels does not pass. Missing secret injection or script bodies fails with an actionable sanitized diagnostic.

Use local Microsoft/Google fixtures and real code exchange for deterministic CI. A fixture constructor may replace endpoints and trust roots but must retain tenant/issuer/key policy checks. Browser acceptance includes work, school, Outlook, Hotmail, Gmail and Workspace profiles; these are fixture personas, not proof that real tenants were contacted. Optional manual live checks require available approved credentials and exact registered callback URLs. Report unavailable live evidence as not run.

Acceptance criteria:

1. Sourced inventory names every accepted/rejected option, identity format and known compatibility difference; roadmap deferrals are explicit.
2. API/seed/console create and manage the two Microsoft strategies with identical validation, secret redaction, strategy filtering and revision behavior.
3. Microsoft signature/issuer/key/tenant/nonce/audience/time failures never provision users or persist tokens; generic OIDC validation stays strict.
4. All account audiences complete actual fixture code flows; repeat login and changed/missing email retain identity without merging accounts.
5. Microsoft linking/import/unlink/deletion, races and token scope gates work on memory, SQLite/PostgreSQL/MySQL and gRPC, including independent-handle SQL races, startup preflight and explicit old-plugin capability denial.
6. Hosted choices, protection, consent/device continuation and custom-domain callbacks preserve the predecessor's behavior with the new adapters.
7. Pinned SDK, CLI and strict Deploy CLI lanes exercise the new strategies and preservation of predecessor strategies; console tests/build and generated contracts pass.
8. An implementation record reports commands, actual results, known gaps and optional live checks separately. This draft records no implementation test as passing.

No database tests are run while authoring this spec/plan. Plan 19's repository hold remains specific to Plan 19; it is not silently extended or revoked here. Implementation verification for Plan 25 is defined in its plan.
