# Plan 42b Phase B — My Organization API: domains, identity providers, provisioning

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the 24 Phase B operations of Auth0's My Organization API
(OpenAPI 1.0.0, Early Access) under `/my-org/v1`. With them, organization
administrators can claim and verify their domains, create and manage their
organization's own enterprise identity providers, link domains to those
providers for home realm discovery, and set up SCIM provisioning and its
tokens.

**Architecture:**
- Phase B extends `internal/myorg`, which Phase A built: its auth, the
  organization from `org_id`, problem errors and logs.
- **Domains** are the organization's existing Plan 30 discovery domains,
  with real DNS TXT verification through `customdomain.DNSResolver`.
- **Identity providers** are enterprise connections enabled on the
  organization. Every write goes in-process through the Management API
  handlers, so connection validation, secret sealing, SCIM and logging stay
  in one place. This is the seam Plan 37c's self-service assistant uses
  (`internal/mgmt/assistant.go`), generalised to a caller per surface.
- A new `internal/orgidp` package maps the OpenAPI's per-strategy option
  shapes to and from connection options, using allowlists, so no secret is
  ever returned.

**Tech Stack:**
- Go 1.26.10, with no new module.
- `golang.org/x/net/dns/dnsmessage`, already used by the custom-domain resolver.
- Vue/TypeScript console.
- Playwright 1.64.0 and `@auth0/auth0-spa-js` 2.28.3.

**Spec:** [Plan 42b design](../specs/2026-11-16-zeroauthy-my-organization-api-design.md)
§1 Phase B, §5, LR42b-3. **Phase A:** D-0220,
[operator guide](../../my-organization-api.md),
[record](../2026-11-16-plan-42b-implementation-record.md).

**Gate:**
- Maintainer request (2026-11-26) to plan Phase B. Spec §8.2 is satisfied:
  F1/F2/F4 (Plans 36, 37a, 37c) have merged.
- **Depends on:** Phase A (PR #99) merged to `main`. Rebase this branch
  onto `main` after it merges.

## Global Constraints

- **Toolchain.** Keep Go `1.26.10` and every pin. No new Go module or npm
  package.
- **Contract.**
  - Extend `api/myorg.yaml` with exactly the 24 operations below, each with
    an `x-source`. Pin the same OpenAPI: version `1.0.0`, SHA-256
    `1f5a90535df8c932c98ea7de66b1516a912e5b695bd3aafe1465e8a43d7d0dbe`
    (re-read 2026-11-26, unchanged).
  - Extend `api/myorg_contract_test.go`.
  - If Task 1 finds a newer OpenAPI, record the diff in D-0221 before
    building.
- **Decisions.** Write D-0221 (Phase B), LR42b-15… and MO-9…. Add the
  follow-ups to the record.
- **Operations and scopes**, copied from the OpenAPI:

| Operation | Scope |
|---|---|
| `GET /config/identity-providers` | `read:my_org:configuration` |
| `GET /domains`, `GET /domains/{domain_id}` | `read:my_org:domains` |
| `POST /domains` | `create:my_org:domains` |
| `DELETE /domains/{domain_id}` | `delete:my_org:domains` |
| `POST /domains/{domain_id}/verify` (202) | `update:my_org:domains` |
| `GET /domains/{domain_id}/identity-providers` | `read:my_org:domains` and `read:my_org:identity_providers` |
| `GET /identity-providers` (`member_access_level`, `is_enabled`), `GET /identity-providers/{idp_id}` | `read:my_org:identity_providers` |
| `POST /identity-providers` | `create:my_org:identity_providers` |
| `PATCH /identity-providers/{idp_id}`, `PUT …/update-attributes` | `update:my_org:identity_providers` |
| `DELETE /identity-providers/{idp_id}` | `delete:my_org:identity_providers` |
| `POST …/detach` (204) | `update:my_org:identity_providers_detach` |
| `POST …/domains` (201), `DELETE …/domains/{domain}` | `create:`/`delete:my_org:identity_providers_domains` |
| `GET`/`POST`/`DELETE …/provisioning`, `PUT …/provisioning/update-attributes` | `read:`/`create:`/`delete:`/`update:my_org:identity_providers_provisioning` |
| `GET`/`POST …/provisioning/scim-tokens`, `GET`/`DELETE …/scim-tokens/{idp_scim_token_id}` | `read:`/`create:`/`delete:my_org:identity_providers_scim_tokens` |

- **New system API scopes.** Add these to `tenantsetup.MyOrgAPIScopes`,
  which goes from 12 to 31 (19 new):
  - `read:`/`create:`/`update:`/`delete:my_org:domains`
  - `read:`/`create:`/`update:`/`delete:my_org:identity_providers`
  - `update:my_org:identity_providers_detach`
  - `create:`/`delete:my_org:identity_providers_domains`
  - `read:`/`create:`/`update:`/`delete:my_org:identity_providers_provisioning`
  - `read:`/`create:`/`delete:my_org:identity_providers_scim_tokens`

  Not added: the OpenAPI's `…_tests`, clients, client grants, groups and
  organization deletion scopes, which have no operations in 1.0.0.
  Activation updates existing My Organization APIs to the new scope list.
- **Shapes.**
  - Domain ID: `ord_` + 22 alphanumerics.
  - Domain name pattern: `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$`.
  - Domain status: `pending|verified|failed`.
  - Identity provider strategies: `adfs, google-apps, oidc, okta, pingfederate, samlp, waad`.
  - Access levels: `none|readonly|limited|full`.
  - SCIM token scopes: `get:users post:users patch:users delete:users put:users`.
  - `token_lifetime` > 900 or `null`.
  - Domains are paged with `take` (1–100, default 50) and a `from` cursor.
- **Isolation.**
  - The organization comes from `org_id` only.
  - An identity provider is in scope only when it is enabled on that
    organization with `organization_access_level` ≠ `none`. Otherwise it
    is `404`, even when it exists elsewhere in the tenant.
- **Secrets.**
  - Responses never contain `client_secret`, signing keys or SCIM token
    hashes.
  - A SCIM token value is returned once, in the create response, and
    never logged.
  - Verification TXT values are not secret, but are not logged either.
- **Verification** per `AGENTS.md`:
  - focused tests per task;
  - fast tier `TMPDIR=/dev/shm/za42bB GOTMPDIR=/dev/shm/za42bB go test -p 4 ./...`;
  - `make e2e-my-org e2e-organizations-ii e2e-scim e2e-enterprise-oidc`;
  - push `plan-42b-phase-b` and report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-42bB`, branch `plan-42b-phase-b`.
  Record in `docs/superpowers/2026-11-26-plan-42b-phase-b-implementation-record.md`.
- **Commits** signed off. Run `gofmt -l .` repo-wide before every push.

## Local rulings to record in D-0221

| ID | Ruling |
|---|---|
| LR42b-15 | **Domains.** My Organization domains are the organization's discovery domains (one list, Plan 30 rows). New ones get `ord_` IDs; existing `dd_` IDs stay valid in paths. `verification_host` stays `_zeroauthy-org.{domain}`. The Management API's `PATCH … status: verified` attestation stays available to operators. |
| LR42b-16 | **Verification.** `verify` looks up TXT records at `verification_host` through the deployment's bounded resolver, with the five-second deadline. A match sets `verified`; no match or `NXDOMAIN` sets `failed`; a resolver error leaves the status unchanged and answers `503`. It answers `202` with the domain after the lookup. |
| LR42b-17 | **Claims.** A pending or failed domain created through this API expires 7 days after creation (LR42b-3) and is deleted lazily on read. `POST /domains` answers `409` when the organization already has the domain, or when another organization in the tenant has it `verified`. `verify` sets `failed` when another organization verified it first. |
| LR42b-18 | **Identity providers.** These are enterprise connections of the seven strategies enabled on the organization. Created ones get `organization_access_level: full`, are enabled for the token's client and the invitation landing client, and their name is the request `name` (`409` when taken in the tenant). The strategy must be in the application's `allowed_strategies`. `access_level` gates `PATCH` fields as the OpenAPI describes; a disallowed field answers `403`. `DELETE` needs `full`. |
| LR42b-19 | **Domain links.** An identity provider's `domains` are its connection's `domain_aliases`, and each must be a verified domain of the organization. `domain_verification` comes from the connection profile (`none`: links refused with `400`; `required`: create needs one or more verified domains, enabling needs one, and an enabled provider's last verified domain cannot be removed, `400`). Deleting an organization domain removes it from the organization's providers. A domain on another provider in the organization is `409`. |
| LR42b-20 | **Attributes.** zeroauthy has no User Attribute Profiles, so `attributes` is `[]` and `PUT …/update-attributes` returns the provider unchanged. Provisioning `attributes` is the SCIM mapping (`user_attribute` = Auth0 field, `provisioning_field` = SCIM path, all flags false), and its `update-attributes` returns it unchanged. Follow-up when User Attribute Profiles land. |
| LR42b-21 | **Provisioning.** Allowed when the connection profile enables `provisioning` for the strategy, or when no profile is configured and the strategy supports SCIM (Plan 37c). Tokens: the Management API's limit (2 active) answers `400`; `token_lifetime` defaults to the profile's `default_expiry`, else its `max_allowed_expiry`, else no expiry; `null` is refused when the profile sets a maximum; scopes must be a subset of the profile's (default: all five). |
| LR42b-22 | **Configuration.** `GET /config/identity-providers` reads the application's `connection_profile_id`. Without one: `organization.can_set_*` false, one entry per allowed strategy with `enabled_features: []`, `provisioning_methods: []`, and `domain_verification: optional`. A profile's `show_as_button`/`assign_membership_on_login` value `optional` maps to `can_set_* = true`; `none`/`required` force the value. |
| LR42b-23 | **Deletion.** With `connection_deletion_behavior: allow_if_empty`, deleting a provider that still has users answers `400`. `detach` removes only the organization connection, at any access level except `none`. |
| LR42b-24 | **Logs.** The local events `my_organization_api_domain_{succeeded,failed}`, `…_identity_provider_{succeeded,failed}` and `…_provisioning_{succeeded,failed}`, with operation, IDs and reason, never options or tokens. Task 1 renames them if Auth0 documents codes. The in-process Management calls also log as client `my-organization-api`. |

Observe later (MO-9…13): the verification host and TXT format at Auth0;
whether domains share Management discovery-domain IDs; the
`access_level` of providers an admin creates; how attribute refresh behaves
with User Attribute Profiles; and the SCIM token limit's error status.

## Review Focus

1. **Domain takeover.** A TXT value for another organization, a domain
   verified by another organization, a CNAME loop or an oversized answer
   never leaves a domain `verified`. Task 2 `TestDomainVerify` (table)
   covers this.
2. **Cross-organization providers.** An admin cannot read, patch, detach,
   delete, link domains to or provision a connection enabled only on
   another organization, or one at access `none`; each is `404`. Task 3
   `TestIdPIsolation` (table over every IdP route).
3. **Secret echo.** No IdP response, log line or problem detail carries
   `client_secret`, a SAML signing key or a SCIM token after creation.
   Task 3 `TestIdPNoSecrets`, Task 5 `TestSCIMTokenOnce` and the E2E log
   audit cover this.
4. **Access-level escalation.** A `readonly` provider rejects every write;
   a `limited` one rejects `display_name`, `options` and
   `use_for_third_party_client_access`. Task 4 `TestIdPAccessLevels`.
5. **Required verification lockout.** With `domain_verification: required`,
   removing an enabled provider's last verified domain (through either
   route) answers `400` and leaves it linked. Task 4
   `TestIdPRequiredDomain`.

---

### Task 1: Contract, decisions and scopes

**Files:**
- Modify: `api/myorg.yaml`, `api/myorg_contract_test.go`,
  `internal/tenantsetup/myorg.go`, `docs/compat/decisions.md` (D-0221),
  the record.
- Test: `api/myorg_contract_test.go`, `internal/tenantsetup/myorg_test.go`.

**Interfaces:**
- Produces: the 24 operations in `api/myorg.yaml`; `tenantsetup.MyOrgAPIScopes`
  (31 entries); `myorg` routes answering `501` until implemented.

- [ ] **Step 1: Failing tests.** `TestMyOrgContractPhaseB` asserts the 24
  paths, methods, scopes and status sets from the table, and that every
  operation has an `x-source`. `TestMyOrgAPIScopes` asserts 31 scopes.
  Extend Phase A's `TestMyOrgActivation` so that activating an existing API
  adds the new scopes.
- [ ] **Step 2: Run.** `go test ./api/ ./internal/tenantsetup/ -run 'MyOrg'`
  fails.
- [ ] **Step 3: Implement.** Download the OpenAPI again, check its SHA-256,
  and write the contract from its Phase B paths and schemas;
  add the scopes, and write D-0221 with LR42b-15…24 and MO-9…13. Search
  Auth0's log event type list for My Organization codes (LR42b-24).
- [ ] **Step 4: Run.** The tests pass, and `make check-sources` reaches every
  `x-source`.
- [ ] **Step 5: Commit** `docs: freeze Plan 42b Phase B contract and D-0221`.

### Task 2: Domains with DNS verification

**Files:**
- Create: `internal/myorg/domains.go`, `internal/myorg/domains_test.go`.
- Modify: `internal/store/myorg.go` plus the memory, SQL, gRPC and plugin
  backends, proto, `storetest/myorg.go` (claim timestamps), migration
  `0051_my_org_domain_claims.sql` (renumber at merge),
  `internal/myorg/router.go`, `internal/server/server.go`,
  `internal/app/app.go` (resolver).

**Interfaces:**
- Consumes: `store.OrganizationsII` discovery domains;
  `customdomain.DNSResolver.LookupTXT(ctx, name) ([]string, error)`.
- Produces:
  - `myorg.Handlers.DNS customdomain.DNSResolver`.
  - `store.MyOrgStore`:
    - `PutDomainClaim(ctx, tid, orgID, domainID string, createdAt time.Time) error`
    - `DomainClaims(ctx, tid, orgID string) (map[string]time.Time, error)`
    - `DeleteDomainClaim(ctx, tid, orgID, domainID string) error`
  - `func domainView(d *store.OrganizationDiscoveryDomain, associated bool) map[string]any`,
    which returns `id, org_id, domain, status, verification_txt, verification_host, identity_provider_association`.

- [ ] **Step 1: Failing tests.**
  - `TestDomainsCRUD`:
    - create → `201` with `status: pending` and `verification_host: _zeroauthy-org.<domain>`;
    - list paging with `take=1` → `next`;
    - get, then delete → `204`, after which get → `404`;
    - invalid name → `400` with `validation_errors`;
    - duplicate in the organization → `409`.
  - `TestDomainVerify`, a table with a fixture resolver:
    - matching TXT → `verified`;
    - another value → `failed`;
    - `ErrDNSNotFound` → `failed`;
    - `ErrDNSLimit`/timeout → `503` with status unchanged;
    - verified by another organization → `failed`.
  - `TestDomainTakeover`: once organization B has verified the domain,
    organization A's create → `409`.
  - `TestDomainClaimExpiry`: a pending claim at now−7d−1s is gone from list
    and get; a verified one stays.
  - `TestMyOrgStore/DomainClaims` in storetest: claims cascade on
    organization delete.
- [ ] **Step 2: Run.** `go test ./internal/myorg/ ./internal/store/... -run 'Domain'` fails.
- [ ] **Step 3: Implement** the handlers, the claims storage on every
  backend and the resolver wiring (the same `BoundedResolver{Server: resolver}`
  as custom domains). Verification reuses discovery-domain status writes.
  `identity_provider_association` comes from Task 4's domain links; until
  then it is `unassociated`.
- [ ] **Step 4: Run** the tests until they pass, then the storetest MyOrg
  suite on memory, SQLite and the gRPC store.
- [ ] **Step 5: Commit** `feat(myorg): organization domains with DNS verification`.

### Task 3: Identity providers: configuration, read and create

**Files:**
- Create: `internal/orgidp/options.go` with `options_test.go`,
  `internal/myorg/idps.go` with `idps_test.go`,
  `internal/mgmt/myorg_calls.go`.
- Modify: `internal/mgmt/assistant.go` (generalise the call), the
  `internal/myorgrules` config (expose `ConnectionProfileID`).

**Interfaces:**
- Produces:
  - `orgidp.Strategies = []string{"adfs","google-apps","oidc","okta","pingfederate","samlp","waad"}`.
  - `orgidp.ToConnection(strategy string, opts map[string]any) (map[string]any, error)`:
    validates against the OpenAPI request schema for that strategy, with
    `additionalProperties: false` and the required members.
  - `orgidp.FromConnection(strategy string, connOpts map[string]any) map[string]any`:
    an allowlist of the response schema, never secrets.
  - `mgmt.InProcessCaller{ClientID string; Scopes []string}`.
  - `(h *Handlers) inProcess(ctx, tn, host string, c InProcessCaller, method, target string, body any, fn http.HandlerFunc) (AssistantResult, error)`;
    the assistant's calls use it with their existing caller.
  - The exported `MyOrg*` wrappers (client ID `my-organization-api`):
    - `MyOrgCreateConnection`, `MyOrgUpdateConnection`, `MyOrgDeleteConnection`
    - `MyOrgEnableOrganization`, `MyOrgUpdateOrganizationConnection`, `MyOrgDisableOrganization`
    - `MyOrgCreateSCIM`, `MyOrgDeleteSCIM`, `MyOrgCreateSCIMToken`, `MyOrgDeleteSCIMToken`

    Each mirrors its Management route; their signatures follow
    `AssistantCreateConnection`.
  - `myorg.Handlers.Writes *mgmt.Handlers`.
  - `func (h *Handlers) idp(r *http.Request, c *Caller, id string) (*store.Connection, store.OrganizationConnection, error)`:
    the scoped lookup, which returns `404` per Global Constraints.

- [ ] **Step 1: Failing tests.**
  - `TestOrgIdPOptions`, a table per strategy: required members missing →
    error; an unknown member → error; `FromConnection` drops
    `client_secret` and the SAML `signingCert` private parts.
  - `TestIdPConfig`: without a profile, the LR42b-22 defaults; with a
    profile (`show_as_button: optional`, a SCIM override for `okta`),
    `can_set_show_as_button: true` and `okta.provisioning_methods: ["scim"]`.
  - `TestIdPCreateRead`:
    - an `oidc` create → `201` with `id` (`con_`), `access_level: full`,
      enabled on the organization and for the token's client;
    - list with `is_enabled=true` and `member_access_level=limited` filters;
    - get;
    - a strategy outside `allowed_strategies` → `400`;
    - a duplicate name → `409`.
  - `TestIdPIsolation`: a table over every IdP route (Review Focus 2).
  - `TestIdPNoSecrets`: create with `client_secret`; the create, get and
    list bodies and the captured log contain no secret value.
  - `TestAssistantUnchanged`: the Plan 37c assistant tests still pass after
    the refactor.
- [ ] **Step 2: Run.** `go test ./internal/orgidp/ ./internal/myorg/ ./internal/mgmt/ -run 'IdP|OrgIdP|Assistant'` fails.
- [ ] **Step 3: Implement.** Creation calls `MyOrgCreateConnection` and then
  `MyOrgEnableOrganization` with `organization_access_level: full`. If
  enabling fails, delete the connection, so no orphan remains.
- [ ] **Step 4: Run** until the tests pass.
- [ ] **Step 5: Commit** `feat(myorg): identity provider configuration, list and create`.

### Task 4: Identity providers: update, delete, detach and domain links

**Files:**
- Modify: `internal/myorg/idps.go`, `internal/myorg/domains.go`.
- Create: `internal/myorg/idp_domains.go`, `internal/myorg/idp_update_test.go`.

**Interfaces:**
- Consumes: the Task 3 `MyOrg*` wrappers and `idp()`; the Task 2 domains.
- Produces: `func linkedDomains(ctx, c *Caller) (map[string]string, error)`,
  mapping each domain name to the provider ID that holds it. It feeds
  `identity_provider_association` and `GET /domains/{id}/identity-providers`.

- [ ] **Step 1: Failing tests.**
  - `TestIdPAccessLevels` (Review Focus 4).
  - `TestIdPUpdate`: `PATCH` of `display_name`, `is_enabled`,
    `show_as_button` (refused when the profile forces it) and `options`
    (secret kept when omitted).
  - `TestIdPDeleteDetach`:
    - detach → the organization connection is gone and the connection
      remains;
    - delete → the connection is gone;
    - with `allow_if_empty` and one user → `400`;
    - delete at `limited` → `403`.
  - `TestIdPDomains`:
    - linking a verified domain → `201` with `{domain}`, after which the
      domain shows `associated` and is listed by
      `/domains/{id}/identity-providers`;
    - an unverified domain → `400`;
    - a domain on another provider → `409`;
    - `domain_verification: none` → `400`;
    - unlink → `204`;
    - deleting the organization domain removes the link.
  - `TestIdPRequiredDomain` (Review Focus 5).
  - `TestIdPUpdateAttributes` → `200`, unchanged, `attributes: []`.
- [ ] **Step 2: Run.** `go test ./internal/myorg/ -run 'IdP'` fails.
- [ ] **Step 3: Implement.** Domain links write `options.domain_aliases`
  through `MyOrgUpdateConnection`. Read-modify-write the connection's
  options, so other options are kept.
- [ ] **Step 4: Run** until the tests pass.
- [ ] **Step 5: Commit** `feat(myorg): identity provider updates and domain links`.

### Task 5: Provisioning and SCIM tokens

**Files:**
- Create: `internal/myorg/provisioning.go`, `internal/myorg/provisioning_test.go`.
- Modify: `internal/logscrub` (add a test that a `token` response member
  is scrubbed, extending it if needed).

**Interfaces:**
- Consumes: `store.Directory` (`GetSCIMConfig`, tokens) and the
  `MyOrg*SCIM*` wrappers.
- Produces: `func provisioningView(conn *store.Connection, cfg *store.SCIMConfig) map[string]any`,
  which returns `identity_provider_id, identity_provider_name, strategy, method: "scim", attributes, user_id_attribute`.

- [ ] **Step 1: Failing tests.**
  - `TestProvisioning`:
    - `GET` before create → `404`;
    - create → `201` `method: scim`;
    - `update-attributes` → `200`, unchanged;
    - delete → `204` and the tokens are gone;
    - a strategy the profile does not provision → `400`.
  - `TestSCIMTokens`:
    - create → `201` with `token`, `token_id`, `scopes` and `valid_until`
      from `token_lifetime: 3600`;
    - `token_lifetime: 900` → `400`;
    - scopes outside the profile → `400`;
    - `null` when the profile sets a maximum → `400`;
    - a third active token → `400`;
    - list and get never show `token`;
    - delete → `204`, after which the token no longer authenticates at
      `/scim/v2`.
  - `TestSCIMTokenOnce`: the token value never appears in the captured
    server log.
- [ ] **Step 2: Run.** `go test ./internal/myorg/ ./internal/logscrub/ -run 'Provisioning|SCIM'` fails.
- [ ] **Step 3: Implement** through the Management SCIM handlers, so the
  Plan 37c limits and hashing apply.
- [ ] **Step 4: Run** until the tests pass.
- [ ] **Step 5: Commit** `feat(myorg): identity provider provisioning and SCIM tokens`.

### Task 6: Console, seed, E2E, docs, final verification

**Files:**
- Console: `console/src/pages/applications/MyOrgSection.vue`. Add a
  `connection_profile_id` select listing Plan 37c connection profiles
  (the field is stored by `myorgrules` but has no form control yet), with
  the hint "Controls the identity providers organization administrators
  may create".
- Seed: `internal/seed` (the new scopes come with
  `my_organization_api`; nothing else).
- E2E: extend `tests/e2e/run-m42b-my-org.sh`, `m42b-my-org.mjs` and
  `m42b-my-org.spec.mjs`. Use a fixture DNS server on loopback, as the
  custom-domain harness does (`tests/e2e/domains/harness/main.go`,
  `BoundedResolver{Server: "127.0.0.1:8073"}`), and the mock OIDC provider
  of `tests/e2e/run-m36-enterprise-oidc.sh`.
- Docs: `docs/my-organization-api.md` (Phase B sections),
  `docs/organizations.md`, `docs/compatibility.md`,
  `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap and README status, the
  record.

- [ ] **Step 1: E2E.** An admin signs in through spa-js, then:
  1. claims `acme.e2e.test`;
  2. the fixture DNS serves the TXT, and verify → `verified`;
  3. creates an `oidc` provider pointing at the mock OIDC provider;
  4. links the domain;
  5. a user `@acme.e2e.test` logs in through home realm discovery into the
     organization;
  6. creates provisioning and a token, and SCIM-creates a user with it;
  7. revokes the token, after which SCIM answers `401`;
  8. another organization's admin gets `404` on the provider.

  The log audit covers the token and client secret.
- [ ] **Step 2: Run** `make e2e-my-org` until it passes.
- [ ] **Step 3: Docs and console.** Run the console tests, typecheck and
  lint, and `make console` in a clean clone.
- [ ] **Step 4: Verify.** Fast tier,
  `make e2e-my-org e2e-organizations-ii e2e-scim e2e-enterprise-oidc`, `gofmt -l .` repo-wide.
  Fill in the record's verification table.
- [ ] **Step 5: Review and push.** Final review, then push
  `plan-42b-phase-b`, open the PR (security-sensitive packages: `myorg`,
  `mgmt`, `store`, `server`) and report CI. Merging needs maintainer
  approval.
