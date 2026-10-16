# zeroauthy Plan 9: Consent, Third-Party Applications, API Access Policies (Milestone 10, part 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** zeroauthy decides who may get tokens for which API, and when the user must approve, the way Auth0 does in 2026:
- third-party applications in `strict` and `permissive` modes;
- `redirection_policy`;
- API access policies (`subject_type_authorization`), with client grants for user and client flows;
- a consent page with remembered user grants;
- the login confirmation prompt for non-verifiable callbacks.

**Architecture:**
- **`internal/access`** holds one pure function, `Decide(Input) Decision`. It is given the client, the API, the client grant, the user grant, the requested scopes, the redirect URI, the prompts and the flow. It returns the scopes to issue, whether consent or confirmation is needed, or an error.
- **Callers:**
  - `/authorize` and its login hand-off (`internal/authz`);
  - the new `/u/consent` page (`internal/login` plus `internal/ui`);
  - the password, refresh and client-credentials grants (`internal/oauth`).
- **Values the docs leave open** sit in one file, `internal/access/observed.go`. Task 1 settles them on the maintainer's own Auth0 tenant before any code is written.
- **Storage:** new fields on `Tenant`, `Client`, `ResourceServer`, `ClientGrant` and `Connection`, and a new `UserGrants` repository. These go through every driver: memory, SQL migration 0003, and gRPC plugins.

**Tech Stack:**
- Go 1.26+; no new Go dependencies.
- E2E adds pinned npm packages from Auth0's most-starred repositories: `express-openid-connect@3.4.0`, `express-jwt@8.5.1` and `jwks-rsa@4.1.0`. node-jsonwebtoken comes in through express-jwt.

**Spec:** `docs/superpowers/specs/2026-10-16-zeroauthy-consent-design.md` (approved 2026-10-16). Also core spec §6.2 and §13.

**Auth0 sources** (public docs; read them, never copy them):
- https://auth0.com/docs/get-started/applications/third-party-applications/user-consent-and-third-party-applications
- https://auth0.com/docs/get-started/applications/third-party-applications/security-controls
- https://auth0.com/docs/get-started/applications/third-party-applications/permissive-mode
- https://auth0.com/docs/get-started/applications/third-party-applications/troubleshooting
- https://auth0.com/docs/troubleshoot/product-lifecycle/deprecations-and-migrations/migrate-to-enhanced-security-third-party-applications
- https://auth0.com/docs/get-started/apis/api-access-policies-for-applications
- https://auth0.com/docs/get-started/applications/application-access-to-apis-client-grants
- https://auth0.com/docs/troubleshoot/product-lifecycle/deprecations-and-migrations/migrate-to-non-verifiable-callback-uri-end-user-confirmation
- https://auth0.com/docs/secure/security-guidance/measures-against-app-impersonation
- https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements (consent screen text keys)
- OIDC Core 1.0 §3.1.2.6 (error codes)

## Global Constraints

- **Earlier constraints still apply:**
  - Drivers return copies; every atomic operation is one store method.
  - `go test -race ./...`, `go vet ./...` and `gofmt -l .` stay clean; `go generate ./...` produces no diff.
  - `CGO_ENABLED=0 go build ./...` works.
- **Wire names are Auth0's.** Seed YAML uses Auth0 Management API property names exactly:
  - `is_first_party`, `third_party_security_mode` (`strict`|`permissive`), `redirection_policy` (`open_redirect_protection`|`allow_always`)
  - `skip_non_verifiable_callback_uri_confirmation_prompt` (on the client and the tenant), `use_scope_descriptions_for_consent`
  - `skip_consent_for_verifiable_first_party_clients`
  - `subject_type_authorization: {user: {policy: …}, client: {policy: …}}` with `allow_all`|`require_client_grant`|`deny_all`
  - `subject_type` (`user`|`client`) on client grants
  - `is_domain_connection`
- **Clean room:**
  - The consent and confirmation page copy, layout and styles are original.
  - The custom-text key names under the `consent` prompt are Auth0's public contract and are taken from the text-elements doc.
  - Task 1 records facts only: redirect URLs reduced to parameter names and error codes, screen types, JSON property names and values. No hosted-page text, no screenshots, no tenant domain or IDs. Follow `CLEAN_ROOM.md` "Behavior testing against the maintainer's own tenant".
- **Defaults:**
  - Clients are first-party unless the seed says otherwise.
  - APIs allow all user flows, and client credentials require a `client` grant.
  - Existing client grants become `subject_type: client`.
  - `skip_consent_for_verifiable_first_party_clients` defaults to **`false`** in the seed, as on Auth0 (D-0026). Rows migrated to schema 3 keep `true` until the next seed apply. Every test seed and fixture in this plan that expects no consent for first-party apps sets it to `true` explicitly.
- **Fail closed when a stored value is unknown:** a third-party client with an empty or unknown `ThirdPartySecurityMode` is treated as `strict`.
- **Non-verifiable callback:** any scheme other than `http`/`https`, or a host of `localhost`, `127.0.0.1` or `::1` (any scheme, any port).

## Observation-dependent values

Task 1 fills the **Observed** column and edits `internal/access/observed.go` and the seed defaults to match. Tasks 2–11 are written against the **Default** column. If Task 1 changes a value, the implementer of each later task uses the observed value; the tests are written against the constants, so most will follow automatically.

Task 1 ran on 2026-10-16 (`docs/compat/observations/consent.md`, D-0025–D-0027). **The code blocks in Tasks 5–10 already use the observed values**; the table records where they came from.

| # | Question | Constant / place | Observed (used by this plan) |
|---|---|---|---|
| O1a | Default `skip_consent_for_verifiable_first_party_clients` on a new API | seed default | **`false`** (maintainer chose parity; migrated rows keep `true`) |
| O1b | Default `subject_type_authorization` | seed default | user `allow_all`, client `require_client_grant` |
| O1c | Default `third_party_security_mode` | seed default | `strict` |
| O1d | Default `redirection_policy` | seed default | third-party `open_redirect_protection`; first-party unset (zeroauthy stores `allow_always`) |
| O1e | `subject_type` of a grant created without one | seed default | `client` |
| O1f | Third-party client in a connection's `enabled_clients` | seed validation | **refused** (third-party apps use domain connections only) |
| O2 | Consent with no `audience` (permissive) | `consentWithoutAudience` | not observable (no permissive clients); `true`, grant audience `https://{domain}/userinfo` |
| O2b | Strict client with no audience | `codeStrictNoAudience` | **`invalid_request`** |
| O3 | Subset covered; scopes merged | `mergeGrantScopes` | subset covered; merged (`true`) |
| O4 | First-party, API skips consent, non-verifiable callback | `Input.ScreenShown` rule | **confirmation only when no other screen (login, signup, consent) was shown in the transaction**: none right after a login, shown on session reuse |
| O5 | `prompt=none` codes | `codeConsentRequired`, `codeConfirmationRequired` | `consent_required` for both |
| O6 | Errors `open_redirect_protection` shows as a page | `ShowErrorPage(client)` | **every** /authorize error after client and redirect URI validation; HTTP 400 |
| O7 | User flow refused by the access policy | `codeAuthorizeDenied`, `codeTokenDenied` | **`invalid_request`** at /authorize; **HTTP 400 `invalid_request`** at /oauth/token; client credentials HTTP 403 `access_denied` (unchanged) |
| O8 | Permissive client, `allow_all`, no grant | `permissiveFollowsPolicy` | not observable; `true` per the permissive-mode page |

## Review Focus

1. **A seed or Go caller that builds a `store.Client` or `store.ResourceServer` literal without the new fields**, such as a plugin author's test. Go zero values would make every client third-party, or every API ask first-party apps for consent. The protections:
   - the seed always sets the fields;
   - the SQL defaults are `TRUE`;
   - a gRPC message missing the optional fields decodes as `true` (pinned in Task 4, `TestCodecDefaultsForOldPlugins`).
   No Go code outside the seed and the drivers may construct these structs for production use.
2. **An old storage plugin, built before proto fields 15–18**, answers `ClientGrantsFind` without honouring `subject_type`. The host must never treat a `client` grant as a `user` grant. Pinned in Task 4 (`TestFindIgnoresWrongSubjectType`).
3. **`prompt=consent` combined with a login.** The login hand-off used to delete the whole `prompt` parameter, which would silently drop `consent`. Only `login` may be removed. Pinned in Task 7 (`TestPromptConsentSurvivesLogin`).
4. **A consent page opened after the session ended, or by another browser.** It must fail closed with the session-expired page and never issue a code. Pinned in Task 8 (`TestConsentWithoutSessionFails`, `TestConsentWrongCookie`).
5. **Third-party clients and connections.** Third-party apps may use only domain connections, at the login page, at the `connection` parameter, and on session reuse. A first-party session on a non-domain connection must not be reused for a third-party app. Pinned in Task 7 (`TestThirdPartySessionOnNonDomainConnectionLogsInAgain`).

---

## Out of Scope

Task 11 adds these to `docs/superpowers/plan-1-followups.md` under "Plan 9 follow-ups":
- Organizations: `third_party_client_access`, consent per organization.
- `default_for: third_party_clients` default permissions, which arrive with dynamic client registration.
- `allow_all_scopes` and `authorization_details_types` on client grants.
- RBAC and its intersection with granted scopes.
- `/api/v2/grants` and `/api/v2/client-grants`, and revoking refresh tokens when a grant is deleted (sub-project 3).
- The `tpc_` client ID prefix for generated strict client IDs (sub-project 3).
- Device flow (`/activate`, which will reuse the consent page) and PAR, which strict clients reject (Plans 10 and 11).
- Auth0 stored a user grant for a first-party client after a login that showed no screen (observation check 1). zeroauthy stores grants only on accepted consent (D-0026); revisit once the grants Management API exists.
- Re-checking the Management API defaults (O1) with a machine (client-credentials) login of auth0-cli; Task 1 used a user login.

## File Structure

| File | Responsibility |
|---|---|
| `docs/compat/observations/consent.md` (new) | Task 1 facts |
| `docs/compat/decisions.md` | D-0025 third-party modes and access policies; D-0026 consent and user grants; D-0027 confirmation prompt, `prompt=none`, redirection policy |
| `internal/store/types.go`, `store.go` | New fields and constants; `UserGrant`; `UserGrants`; `ClientGrants.Find` takes the subject type |
| `internal/store/memory/user_grants.go` (new), `client_grants.go`, `clone.go`, `memory.go`, `tx.go` | Memory driver |
| `pkg/storetest/user_grants.go` (new), and the `clients.go`, `tenants.go`, `resource_servers.go`, `client_grants.go`, `connections.go` suites | Conformance |
| `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0003_consent.sql` (new) | Schema |
| `internal/store/sqlstore/user_grants.go` (new), `tenants.go`, `clients.go`, `resource_servers.go`, `client_grants.go`, `connections.go` | SQL driver |
| `proto/store/v1/store.proto` (+ generated), `internal/store/grpcstore/{codec,client_repos,server_repos,client}.go` | Plugin protocol |
| `pkg/store/store.go` | Public aliases |
| `internal/seed/{seed,validate,apply}.go` | Seed |
| `internal/access/access.go`, `observed.go`, `access_test.go` (new) | Decision rules |
| `internal/authz/{request,validate,handlers,errors}.go` | /authorize integration |
| `internal/ui/templates/consent.html` (new), `internal/ui/ui.go` | Consent page |
| `internal/i18n/locales/en.json`, `internal/i18n/keys.go` | Text |
| `internal/login/consent.go` (new), `login.go` | Consent handlers; domain connections |
| `internal/server/server.go` | Routes |
| `internal/oauth/{grant_password,grant_refresh_token,grant_client_credentials,access}.go` | Token-endpoint checks |
| `tests/e2e/…` | m10 E2E |
| `docs/consent.md` (new), `docs/compat/{matrix,blackbox-clients}.md`, `docs/superpowers/plan-1-followups.md`, core spec §6.2 | Docs |

---

### Task 1: Observe the open points on the maintainer's Auth0 tenant

**Status: done 2026-10-16** (inline, with the maintainer). Results: `docs/compat/observations/consent.md` and D-0025–D-0027. The extra checks run beyond the steps below (token endpoint, `allow_always` re-runs, connection and grant-type refusals) are recorded there. The steps are kept as the procedure for repeating the observation.

This task needs the maintainer. Claude runs the Management API calls with auth0-cli. The maintainer opens the browser URLs and reports back only the final address-bar URL, or which kind of screen appeared. No code changes in this task.

**Files:**
- Create: `docs/compat/observations/consent.md`
- Modify: `docs/compat/decisions.md` (append D-0025, D-0026, D-0027)
- Modify: this plan's "Observation-dependent values" table (fill the Observed column)
- Modify (only if an observation differs from its default): none yet. Tasks 2–6 create the constants; the Observed column tells their implementers what to use.

**Interfaces:**
- Produces: observed values for O1–O8, used by Tasks 5 and 6.

- [x] **Step 1: Check the tools and tenant**

Run: `auth0 --version && auth0 tenants list`
Expected: a version, and the maintainer's tenant marked active. If it isn't logged in, ask the maintainer to run `! auth0 login`. Never print tokens.

Run: `auth0 api get tenants/settings | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k: d.get(k) for k in ["skip_non_verifiable_callback_uri_confirmation_prompt","use_scope_descriptions_for_consent"]})'`
Record both values. If the tenant has `skip_non_verifiable_callback_uri_confirmation_prompt: true`, the O4 and O5 confirmation checks need it to be false at the client level, which Step 2 does.

- [x] **Step 2: Create the test objects (O1)**

All names start with `za-obs-` so teardown can find them. Use `https://example.com/cb` as the callback: the browser ends there with a visible URL and the page content does not matter.

```bash
auth0 api post resource-servers --data '{"name":"za-obs-api","identifier":"https://za-obs.example/api","scopes":[{"value":"read:things","description":"Read things"},{"value":"write:things","description":"Write things"}]}' > /tmp/claude-1000/za-obs-api.json
python3 -c 'import json; d=json.load(open("/tmp/claude-1000/za-obs-api.json")); print({k: d.get(k) for k in ["id","skip_consent_for_verifiable_first_party_clients","subject_type_authorization"]})'

auth0 api post clients --data '{"name":"za-obs-3p","app_type":"regular_web","is_first_party":false,"callbacks":["https://example.com/cb","http://localhost:51089/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}' > /tmp/claude-1000/za-obs-3p.json
python3 -c 'import json; d=json.load(open("/tmp/claude-1000/za-obs-3p.json")); print({k: d.get(k) for k in ["client_id","is_first_party","third_party_security_mode","redirection_policy"]})'

auth0 api post clients --data '{"name":"za-obs-1p","app_type":"regular_web","callbacks":["https://example.com/cb","http://localhost:51089/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post","skip_non_verifiable_callback_uri_confirmation_prompt":false}' > /tmp/claude-1000/za-obs-1p.json
python3 -c 'import json; d=json.load(open("/tmp/claude-1000/za-obs-1p.json")); print({k: d.get(k) for k in ["client_id","is_first_party","redirection_policy","skip_non_verifiable_callback_uri_confirmation_prompt"]})'

auth0 api post client-grants --data '{"client_id":"<3p client_id>","audience":"https://za-obs.example/api","scope":["read:things"]}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k: d.get(k) for k in ["id","subject_type","scope"]})'
```

Record O1a–O1e. Do not record the IDs in the repository; keep them in the scratchpad (`/tmp/claude-1000/…`) for teardown. Also note whether creating the client with `"third_party_security_mode":"permissive"` succeeds (O8 eligibility):

```bash
auth0 api post clients --data '{"name":"za-obs-3p-permissive","app_type":"regular_web","is_first_party":false,"third_party_security_mode":"permissive","callbacks":["https://example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("client_id"), d.get("third_party_security_mode"), d.get("errorCode") or d.get("error"))'
```

Create a test user on a database connection, and promote that connection to domain level only if it is not already. Record the connection's original `is_domain_connection` value so teardown can restore it:

```bash
auth0 users create --connection-name Username-Password-Authentication --email za-obs-user@example.com --password '<random 20 chars>' --name za-obs --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["user_id"])'
```

- [x] **Step 3: Browser checks (O2–O7)**

For each check, Claude prints one `/authorize` URL (with `response_type=code`, `state=s1`, the client, `redirect_uri=https://example.com/cb` unless stated, and a PKCE `code_challenge` for the strict client). The maintainer opens it in a private window, logs in as `za-obs-user` where asked, and replies with **one** of:
- `REDIRECT <the query parameters' names and the values of error only>`
- `CONSENT` (a screen asking to allow access), `CONFIRM` (a screen asking to confirm continuing to the app), or `ERRORPAGE` (an error shown by Auth0).
They do not paste screen text.

| Check | Request | Record |
|---|---|---|
| O4 | 1p client, `audience=https://za-obs.example/api`, `redirect_uri=http://localhost:51089/cb`, skip flag on (the default per O1a) | the first screen after login: CONSENT, CONFIRM or REDIRECT |
| O5a | 1p client, same URL plus `prompt=none`, same browser session | REDIRECT error code |
| O2 | 3p client, no `audience`, `scope=openid profile` | CONSENT or REDIRECT. If CONSENT, accept, then read the grant: `auth0 api get "grants?user_id=<id>"` → audience and scope |
| O2b | 3p strict client, no audience, `scope=read:things` | REDIRECT error, CONSENT or ERRORPAGE |
| O3a | 3p, `audience=…/api`, `scope=read:things`; accept | `auth0 api get "grants?user_id=<id>"` → scope |
| O3b | 3p, same, `scope=read:things` again | CONSENT or REDIRECT (subset covered?) |
| O3c | 3p, `scope=read:things write:things` | CONSENT or REDIRECT; if CONSENT, accept, then read the grant's scope again (merged?) |
| O5b | 3p, `scope=read:things write:things`, `prompt=none`, after deleting the grant (`auth0 api delete grants/<id>`) | REDIRECT error code |
| O6 | 3p (open_redirect_protection), `prompt=none` in a fresh private window (no session) | REDIRECT error code or ERRORPAGE |
| O6b | 3p, accept nothing: decline on the consent screen | REDIRECT or ERRORPAGE |
| O7a | Set the API's user policy to deny: `auth0 api patch resource-servers/<id> --data '{"subject_type_authorization":{"user":{"policy":"deny_all"}}}'`. 1p client with the API audience | REDIRECT error code, or ERRORPAGE |
| O7b | Same policy; password grant through curl with a first-party client that has `password` enabled, if one exists on the tenant; otherwise skip and note it | HTTP status and `error` |
| O7c | `client_credentials` for a client with no grant: create `za-obs-m2m` (non_interactive) without a grant and call `/oauth/token` | HTTP status and `error` |
| O8 | If a permissive client could be created: `allow_all` user policy restored, no grant for it, request the API audience | CONSENT (allowed) or REDIRECT error |

- [x] **Step 4: Tear down**

Delete every `za-obs-*` client, the API, the grants and the test user. Restore `is_domain_connection` if Step 2 changed it. Run `auth0 apps list` and `auth0 apis list` and confirm nothing `za-obs` remains. Delete the scratch JSON files.

- [x] **Step 5: Write the observation note**

Create `docs/compat/observations/consent.md` using the README layout. Record only facts:

```markdown
# Consent, third-party applications and access policies

- **Observed:** 2026-10-XX
- **Docs:** (the source list from this plan)
- **Method:** Management API through auth0-cli; /authorize in a private browser window, recording only the final redirect's parameter names and `error` value, or the kind of screen reached. No page text or images were captured.

## Defaults (O1)
- New resource server: `skip_consent_for_verifiable_first_party_clients` = …; `subject_type_authorization` = …
- New third-party client: `third_party_security_mode` = …; `redirection_policy` = …
- New first-party client: `redirection_policy` = …
- Client grant created without `subject_type`: `subject_type` = …

## /authorize
- O2 …
(one bullet per check, in the table's order)
```

- [x] **Step 6: Record decisions D-0025, D-0026 and D-0027**

Append three entries to `docs/compat/decisions.md` in the existing format (Context, Sources, Decision, Rationale). Each cites the docs and `observations/consent.md`:
- **D-0025 Third-party modes and API access policies:** strict versus permissive (the grant types, PKCE and `/authorize` parameters strict refuses, OIDC scopes dropped); policy evaluation per subject type; O2b, O7 and O8; error codes at /authorize and /oauth/token; client credentials keep `access_denied`; an unknown mode is treated as strict.
- **D-0026 Consent and user grants:** when consent is shown (first and third party, O4); grant key (client, user, audience); the no-audience grant audience (O2); subset and superset handling (O3); `prompt=consent`; decline.
- **D-0027 Confirmation prompt, `prompt=none` and redirection policy:** the definition of non-verifiable; the tenant/client precedence; no confirmation after a consent screen in the same transaction; O5 codes; O6 scope of `open_redirect_protection`.

- [x] **Step 7: Fill the Observed column of this plan**

Edit the table above. Where an observation differs from its default, write the observed value in bold and add "→ change" so later implementers see it.

- [x] **Step 8: Commit**

```bash
git add docs/compat/observations/consent.md docs/compat/decisions.md docs/superpowers/plans/2026-10-16-zeroauthy-plan-9-consent.md
git commit -m "docs: consent observations on the maintainer's tenant; D-0025, D-0026, D-0027"
```

---

### Task 2: Store types, the memory driver and conformance

**Files:**
- Modify: `internal/store/types.go`, `internal/store/store.go`
- Create: `internal/store/memory/user_grants.go`
- Modify: `internal/store/memory/{client_grants,clone,memory,tx}.go`
- Create: `pkg/storetest/user_grants.go`
- Modify: `pkg/storetest/{storetest,clients,tenants,resource_servers,client_grants,connections}.go`
- Modify: `pkg/store/store.go`; every caller of `ClientGrants().Find` (`internal/seed/apply.go`, `internal/oauth/grant_client_credentials.go`, `internal/store/grpcstore/server_repos.go`, `internal/store/grpcstore/client_repos.go`, `internal/store/sqlstore/client_grants.go`). Callers pass `store.SubjectTypeClient` for now; the SQL and gRPC drivers get their real changes in Tasks 3 and 4, but must compile now.

**Interfaces:**
- Produces (used by every later task):

```go
// types.go additions
const (
	SecurityModeStrict     = "strict"
	SecurityModePermissive = "permissive"

	RedirectionPolicyOpenRedirectProtection = "open_redirect_protection"
	RedirectionPolicyAllowAlways            = "allow_always"

	PolicyAllowAll           = "allow_all"
	PolicyRequireClientGrant = "require_client_grant"
	PolicyDenyAll            = "deny_all"

	SubjectTypeUser   = "user"
	SubjectTypeClient = "client"
)

// SubjectTypeAuthorization is an API's access policy for user flows and
// for client credentials (Auth0's subject_type_authorization). An empty
// policy means the default: allow_all for User, require_client_grant for
// Client.
type SubjectTypeAuthorization struct {
	User   string
	Client string
}

// UserGrant records the scopes a user consented to for a client and an
// audience (Auth0's user grants).
type UserGrant struct {
	TenantID  string
	ID        string
	ClientID  string
	UserID    string
	Audience  string // an API identifier, or https://{domain}/userinfo
	Scopes    []string
	CreatedAt time.Time
	UpdatedAt time.Time
}
```

Field additions:
- **`Tenant`:** `SkipNonVerifiableCallbackURIConfirmationPrompt bool`; `UseScopeDescriptionsForConsent bool`.
- **`Client`:**
  - `IsFirstParty bool` (true for first-party apps; the seed and SQL default it to true);
  - `ThirdPartySecurityMode string` (empty for first-party);
  - `RedirectionPolicy string` (empty means the default for the client's party);
  - `SkipNonVerifiableCallbackURIConfirmationPrompt *bool` (nil means the tenant's value applies).
- **`ResourceServer`:** `SkipConsentForVerifiableFirstPartyClients bool`; `SubjectTypeAuthorization SubjectTypeAuthorization`.
- **`ClientGrant`:** `SubjectType string`.
- **`Connection`:** `IsDomainConnection bool`.

```go
// store.go
type Store interface {
	// ... existing ...
	UserGrants() UserGrants
	// ...
}

// ClientGrants stores API authorizations of clients, keyed by
// (TenantID, ID). (ClientID, Audience, SubjectType) is unique within a
// tenant.
type ClientGrants interface {
	// Create returns ErrConflict if the ID or (ClientID, Audience, SubjectType) exists.
	Create(ctx context.Context, g *ClientGrant) error
	Find(ctx context.Context, tenantID, clientID, audience, subjectType string) (*ClientGrant, error)
	// Update replaces the grant with the same ID. ClientID, Audience and
	// SubjectType must not change; drivers return ErrConflict if they do.
	Update(ctx context.Context, g *ClientGrant) error
	Delete(ctx context.Context, tenantID, id string) error
}

// UserGrants stores consent, keyed by (TenantID, ID). (ClientID, UserID,
// Audience) is unique within a tenant.
type UserGrants interface {
	// Find returns ErrNotFound when the user has no grant for the client
	// and audience.
	Find(ctx context.Context, tenantID, clientID, userID, audience string) (*UserGrant, error)
	// Upsert stores g under its (ClientID, UserID, Audience). If a grant
	// exists, its ID and CreatedAt are kept and Scopes and UpdatedAt are
	// replaced; otherwise g is created as given. It returns the stored grant.
	// Concurrent upserts of one key leave exactly one grant.
	Upsert(ctx context.Context, g *UserGrant) (*UserGrant, error)
	// ListByUser returns the user's grants ordered by ClientID, then Audience.
	ListByUser(ctx context.Context, tenantID, userID string) ([]*UserGrant, error)
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
	// DeleteByUser removes all of the user's grants and returns how many.
	DeleteByUser(ctx context.Context, tenantID, userID string) (int, error)
}
```

- [ ] **Step 1: Write the failing conformance tests**

Create `pkg/storetest/user_grants.go`:

```go
package storetest

import (
	"context"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newUserGrant(tenantID, id, clientID, userID, audience string, scopes ...string) *store.UserGrant {
	return &store.UserGrant{
		TenantID: tenantID, ID: id, ClientID: clientID, UserID: userID, Audience: audience,
		Scopes: scopes, CreatedAt: ts(0), UpdatedAt: ts(0),
	}
}

func testUserGrants(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("UpsertFindDelete", func(t *testing.T) {
		s := open(t, newStore)
		in := newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read:things")
		got, err := s.UserGrants().Upsert(ctx, in)
		mustNoErr(t, err)
		mustEqual(t, got, in)
		found, err := s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, found, in)

		// Same key, new ID and scopes: the first ID and CreatedAt are kept.
		again := newUserGrant("ten_a", "ug2", "c1", "auth0|u1", "https://api.test", "read:things", "write:things")
		again.CreatedAt, again.UpdatedAt = ts(5), ts(5)
		got, err = s.UserGrants().Upsert(ctx, again)
		mustNoErr(t, err)
		want := newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read:things", "write:things")
		want.UpdatedAt = ts(5)
		mustEqual(t, got, want)
		found, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, found, want)

		mustNoErr(t, s.UserGrants().Delete(ctx, "ten_a", "ug1"))
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.UserGrants().Delete(ctx, "ten_a", "ug1"), store.ErrNotFound)
	})

	t.Run("ListAndDeleteByUser", func(t *testing.T) {
		s := open(t, newStore)
		for _, g := range []*store.UserGrant{
			newUserGrant("ten_a", "ug3", "c2", "auth0|u1", "https://api.test", "a"),
			newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://z.test", "b"),
			newUserGrant("ten_a", "ug2", "c1", "auth0|u1", "https://a.test", "c"),
			newUserGrant("ten_a", "ug4", "c1", "auth0|u2", "https://api.test", "d"),
			newUserGrant("ten_b", "ug5", "c1", "auth0|u1", "https://api.test", "e"),
		} {
			_, err := s.UserGrants().Upsert(ctx, g)
			mustNoErr(t, err)
		}
		list, err := s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		var ids []string
		for _, g := range list {
			ids = append(ids, g.ID)
		}
		mustEqual(t, ids, []string{"ug2", "ug1", "ug3"})

		n, err := s.UserGrants().DeleteByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, 3)
		list, err = s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, len(list), 0)
		_, err = s.UserGrants().Find(ctx, "ten_b", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err) // other tenant untouched
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u2", "https://api.test")
		mustNoErr(t, err) // other user untouched
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read:things")
		got, err := s.UserGrants().Upsert(ctx, in)
		mustNoErr(t, err)
		in.Scopes[0], got.Scopes[0] = "mutated", "mutated"
		found, err := s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, found.Scopes, []string{"read:things"})
		found.Scopes[0] = "mutated"
		list, err := s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, list[0].Scopes, []string{"read:things"})
	})

	t.Run("ConcurrentUpsert", func(t *testing.T) {
		s := open(t, newStore)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.UserGrants().Upsert(ctx, newUserGrant("ten_a", "ug"+string(rune('a'+i)), "c1", "auth0|u1", "https://api.test", "read:things"))
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			mustNoErr(t, err)
		}
		list, err := s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, len(list), 1)
	})

	t.Run("RollsBackWithTx", func(t *testing.T) {
		s := open(t, newStore)
		err := s.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.UserGrants().Upsert(ctx, newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "a")); err != nil {
				return err
			}
			return store.ErrConflict // any error aborts
		})
		mustErrIs(t, err, store.ErrConflict)
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
```

Register it in `pkg/storetest/storetest.go`: add `"UserGrants": testUserGrants,` to `Suites`, and `"UserGrants"` to `suiteOrder` after `"ClientGrants"`.

Extend the existing suites with round trips of the new fields. Add these subtests next to the existing `CRUD` subtests:

```go
// pkg/storetest/client_grants.go: newClientGrant gains the subject type.
func newClientGrant(tenantID, id, clientID, audience string) *store.ClientGrant {
	return &store.ClientGrant{
		TenantID: tenantID, ID: id, ClientID: clientID, Audience: audience,
		Scopes: []string{"read:things"}, SubjectType: store.SubjectTypeClient, CreatedAt: ts(0),
	}
}
```

Change every `Find(ctx, t, c, a)` call in that file to `Find(ctx, t, c, a, store.SubjectTypeClient)`. Add:

```go
	t.Run("SubjectTypes", func(t *testing.T) {
		s := open(t, newStore)
		cg := newClientGrant("ten_a", "cg1", "c1", "https://api.test")
		ug := newClientGrant("ten_a", "cg2", "c1", "https://api.test")
		ug.SubjectType, ug.Scopes = store.SubjectTypeUser, []string{"write:things"}
		mustNoErr(t, s.ClientGrants().Create(ctx, cg))
		mustNoErr(t, s.ClientGrants().Create(ctx, ug)) // same client and API, other subject type
		got, err := s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeUser)
		mustNoErr(t, err)
		mustEqual(t, got, ug)
		got, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		mustEqual(t, got, cg)
		dup := newClientGrant("ten_a", "cg3", "c1", "https://api.test")
		dup.SubjectType = store.SubjectTypeUser
		mustErrIs(t, s.ClientGrants().Create(ctx, dup), store.ErrConflict)
		moved := *ug
		moved.SubjectType = store.SubjectTypeClient
		mustErrIs(t, s.ClientGrants().Update(ctx, &moved), store.ErrConflict)
	})
```

In `pkg/storetest/clients.go`, add:

```go
	t.Run("ThirdPartyFields", func(t *testing.T) {
		s := open(t, newStore)
		yes, no := true, false
		for i, skip := range []*bool{nil, &yes, &no} {
			c := newClient("ten_a", "tp"+string(rune('0'+i)))
			c.IsFirstParty = false
			c.ThirdPartySecurityMode = store.SecurityModePermissive
			c.RedirectionPolicy = store.RedirectionPolicyAllowAlways
			c.SkipNonVerifiableCallbackURIConfirmationPrompt = skip
			mustNoErr(t, s.Clients().Create(ctx, c))
			got, err := s.Clients().Get(ctx, "ten_a", c.ClientID)
			mustNoErr(t, err)
			mustEqual(t, got, c)
		}
		got, err := s.Clients().Get(ctx, "ten_a", "tp1")
		mustNoErr(t, err)
		*got.SkipNonVerifiableCallbackURIConfirmationPrompt = false // must not reach the store
		again, err := s.Clients().Get(ctx, "ten_a", "tp1")
		mustNoErr(t, err)
		mustEqual(t, *again.SkipNonVerifiableCallbackURIConfirmationPrompt, true)
	})
```

and set `IsFirstParty: true` in `newClient` so the existing cases describe today's clients. In `pkg/storetest/tenants.go`, add a subtest that sets both tenant booleans to `true`, then runs `Create`, `Get`, `Update` (back to `false`) and `Get` with `mustEqual`. In `resource_servers.go`, `newResourceServer` sets `SkipConsentForVerifiableFirstPartyClients: true`. Add a subtest that stores `false` with `SubjectTypeAuthorization{User: store.PolicyRequireClientGrant, Client: store.PolicyDenyAll}`, reads it back, updates it to `{User: store.PolicyDenyAll}` and reads it again. In `connections.go`, add a subtest that round-trips `IsDomainConnection: true` through `Create`, `Get`, `GetByName` and `List`.

- [ ] **Step 2: Run them and watch them fail**

Run: `go test ./internal/store/memory/ 2>&1 | head -20`
Expected: compile errors (`UserGrants` undefined, too many arguments to `Find`).

- [ ] **Step 3: Implement the types and the memory driver**

Add the types, fields and interfaces above to `internal/store/types.go` and `store.go`, with the doc comments as given. In the memory driver:

`internal/store/memory/memory.go`: add `userGrants map[key]*store.UserGrant // by (tenant, ID)`; initialize it in `New`; add `func (s *Store) UserGrants() store.UserGrants { return userGrants{s} }`. In `tx.go`, `snapshot` adds `userGrants: cloneMap(s.userGrants, cloneUserGrant)`, and `restore` assigns `s.userGrants = snap.userGrants`.

`internal/store/memory/clone.go`:

```go
func cloneUserGrant(g *store.UserGrant) *store.UserGrant {
	out := *g
	out.Scopes = slices.Clone(g.Scopes)
	return &out
}
```

`cloneClient` adds a deep copy of the pointer:

```go
	if c.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
		v := *c.SkipNonVerifiableCallbackURIConfirmationPrompt
		out.SkipNonVerifiableCallbackURIConfirmationPrompt = &v
	}
```

`internal/store/memory/client_grants.go`: `find(tenantID, clientID, audience, subjectType)` also compares `g.SubjectType`. `Create` checks `find(g.TenantID, g.ClientID, g.Audience, g.SubjectType)`. `Update` returns `ErrConflict` when `old.SubjectType != g.SubjectType`. `Find` takes and passes `subjectType`.

Create `internal/store/memory/user_grants.go`:

```go
package memory

import (
	"cmp"
	"context"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type userGrants struct{ s *Store }

// find is called with the lock held.
func (r userGrants) find(tenantID, clientID, userID, audience string) (*store.UserGrant, bool) {
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && g.ClientID == clientID && g.UserID == userID && g.Audience == audience {
			return g, true
		}
	}
	return nil, false
}

func (r userGrants) Find(_ context.Context, tenantID, clientID, userID, audience string) (*store.UserGrant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	g, ok := r.find(tenantID, clientID, userID, audience)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUserGrant(g), nil
}

func (r userGrants) Upsert(_ context.Context, g *store.UserGrant) (*store.UserGrant, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if old, ok := r.find(g.TenantID, g.ClientID, g.UserID, g.Audience); ok {
		old.Scopes = slices.Clone(g.Scopes)
		old.UpdatedAt = g.UpdatedAt
		return cloneUserGrant(old), nil
	}
	k := key{g.TenantID, g.ID}
	if _, ok := r.s.userGrants[k]; ok {
		return nil, store.ErrConflict
	}
	r.s.userGrants[k] = cloneUserGrant(g)
	return cloneUserGrant(g), nil
}

func (r userGrants) ListByUser(_ context.Context, tenantID, userID string) ([]*store.UserGrant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.UserGrant
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && g.UserID == userID {
			out = append(out, cloneUserGrant(g))
		}
	}
	slices.SortFunc(out, func(a, b *store.UserGrant) int {
		return cmp.Or(cmp.Compare(a.ClientID, b.ClientID), cmp.Compare(a.Audience, b.Audience))
	})
	return out, nil
}

func (r userGrants) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.userGrants[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.userGrants, k)
	return nil
}

func (r userGrants) DeleteByUser(_ context.Context, tenantID, userID string) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && g.UserID == userID {
			delete(r.s.userGrants, k)
			n++
		}
	}
	return n, nil
}
```

`ConcurrentUpsert` uses distinct IDs for one key. The first writer creates the grant and the rest update it, so no `ErrConflict` reaches callers.

`pkg/store/store.go`: add the aliases `UserGrant`, `UserGrants` and `SubjectTypeAuthorization`, and the constants `SecurityModeStrict`, `SecurityModePermissive`, `RedirectionPolicyOpenRedirectProtection`, `RedirectionPolicyAllowAlways`, `PolicyAllowAll`, `PolicyRequireClientGrant`, `PolicyDenyAll`, `SubjectTypeUser` and `SubjectTypeClient`, in the same style as the existing ones.

To keep the tree compiling:
- Update every listed caller of `ClientGrants().Find` to pass `store.SubjectTypeClient`; the seed's `applyClientGrant` passes the seed grant's subject type once Task 5 adds it.
- The SQL and gRPC drivers get a temporary `UserGrants()` that **panics with "not implemented"**, and their `Find` gains the parameter.
- `internal/store/sqlstore/conformance_test.go` and `internal/store/grpcstore/conformance_test.go` call `storetest.Run`, which now includes `UserGrants`. Until Tasks 3 and 4 land, run only the memory driver in Step 4. Tasks 3 and 4 remove the panics.

- [ ] **Step 4: Run the memory conformance suite**

Run: `go test -race ./internal/store/memory/ ./pkg/storetest/`
Expected: PASS.

Run: `go build ./... && go vet ./...`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add internal/store pkg/store pkg/storetest internal/seed/apply.go internal/oauth/grant_client_credentials.go
git commit -m "feat(store): user grants, client grant subject types, third-party and consent fields"
```

---

### Task 3: SQL migration 0003 and the SQL driver

**Files:**
- Create: `internal/store/sqlstore/migrations/sqlite/0003_consent.sql`, `postgres/0003_consent.sql`, `mysql/0003_consent.sql`
- Create: `internal/store/sqlstore/user_grants.go`
- Modify: `internal/store/sqlstore/{tenants,clients,resource_servers,client_grants,connections}.go`, `migrate_test.go`

**Interfaces:**
- Consumes: Task 2's types and interfaces.
- Produces: `(*sqlstore.Store).UserGrants()`; schema version 3.

- [ ] **Step 1: Write the failing migration test**

In `internal/store/sqlstore/migrate_test.go`, rename `TestLatestVersionIsTwo` to `TestLatestVersionIsThree`, expecting `3`. Add a test proving that existing rows get today's behaviour:

```go
func TestMigration0003Defaults(t *testing.T) {
	ctx := context.Background()
	for _, d := range testDialects(t) { // the helper TestMigrate uses to open each available dialect
		t.Run(d.name, func(t *testing.T) {
			s := openAtVersion(t, d, 2) // migrate to version 2 only
			mustExec(t, s, `INSERT INTO clients (tenant_id, client_id, name, app_type, secrets, token_endpoint_auth_method,
 grant_types, callbacks, allowed_logout_urls, web_origins, allowed_origins, id_token_lifetime,
 refresh_rotating, refresh_leeway, refresh_expiring, refresh_token_lifetime, refresh_idle_token_lifetime, created_at)
 VALUES ('t','c','n','spa','null','none','null','null','null','null','null',0,false,0,false,0,0,0)`)
			mustExec(t, s, `INSERT INTO resource_servers (tenant_id, id, identifier, name, scopes, signing_alg, token_lifetime, allow_offline_access, created_at)
 VALUES ('t','rs','https://api','n','null','RS256',0,false,0)`)
			mustExec(t, s, `INSERT INTO client_grants (tenant_id, id, client_id, audience, scopes, created_at) VALUES ('t','g','c','https://api','null',0)`)
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			c, err := s.Clients().Get(ctx, "t", "c")
			if err != nil || !c.IsFirstParty || c.ThirdPartySecurityMode != "" || c.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
				t.Fatalf("client after migration: %+v %v", c, err)
			}
			rs, err := s.ResourceServers().Get(ctx, "t", "rs")
			if err != nil || !rs.SkipConsentForVerifiableFirstPartyClients || rs.SubjectTypeAuthorization != (store.SubjectTypeAuthorization{}) {
				t.Fatalf("resource server after migration: %+v %v", rs, err)
			}
			g, err := s.ClientGrants().Find(ctx, "t", "c", "https://api", store.SubjectTypeClient)
			if err != nil || g.SubjectType != store.SubjectTypeClient {
				t.Fatalf("grant after migration: %+v %v", g, err)
			}
		})
	}
}
```

The column lists above must match each dialect's `0001_init.sql`; adjust them to the actual column names when writing the test. If `migrate_test.go` has no `openAtVersion` or `mustExec` helpers, add them next to the existing helpers: `openAtVersion` opens a fresh database and applies only the migrations up to the given version, through the same code path `Migrate` uses (factor a `migrateTo(ctx, version)` out of `Migrate` if needed).

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/sqlstore/ -run 'TestLatestVersionIsThree|TestMigration0003Defaults'`
Expected: FAIL (version 2; unknown columns).

- [ ] **Step 3: Write the migrations**

`internal/store/sqlstore/migrations/sqlite/0003_consent.sql`:

```sql
-- Consent, third-party applications and API access policies (Plan 9).
-- Defaults keep existing rows' behaviour: first-party clients, APIs that
-- skip consent for them and allow all user flows, client-credentials grants.
ALTER TABLE tenants ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN use_scope_descriptions_for_consent BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN is_first_party BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE clients ADD COLUMN third_party_security_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN redirection_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NULL;
ALTER TABLE resource_servers ADD COLUMN skip_consent_for_verifiable_first_party_clients BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE resource_servers ADD COLUMN user_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE resource_servers ADD COLUMN client_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE connections ADD COLUMN is_domain_connection BOOLEAN NOT NULL DEFAULT FALSE;
-- SQLite cannot change a UNIQUE constraint in place: rebuild client_grants.
CREATE TABLE client_grants_new (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  subject_type TEXT NOT NULL DEFAULT 'client',
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, client_id, audience, subject_type)
);
INSERT INTO client_grants_new (tenant_id, id, client_id, audience, scopes, created_at, subject_type)
  SELECT tenant_id, id, client_id, audience, scopes, created_at, 'client' FROM client_grants;
DROP TABLE client_grants;
ALTER TABLE client_grants_new RENAME TO client_grants;
CREATE TABLE user_grants (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, client_id, user_id, audience)
);
CREATE INDEX user_grants_user ON user_grants (tenant_id, user_id);
```

`postgres/0003_consent.sql`: the same `ALTER TABLE … ADD COLUMN` lines, with `TEXT` for strings. For client grants:

```sql
ALTER TABLE client_grants ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'client';
ALTER TABLE client_grants DROP CONSTRAINT client_grants_tenant_id_client_id_audience_key;
ALTER TABLE client_grants ADD CONSTRAINT client_grants_client_audience_subject UNIQUE (tenant_id, client_id, audience, subject_type);
CREATE TABLE user_grants ( -- columns as in SQLite
  tenant_id TEXT NOT NULL, id TEXT NOT NULL, client_id TEXT NOT NULL, user_id TEXT NOT NULL,
  audience TEXT NOT NULL, scopes TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, client_id, user_id, audience)
);
CREATE INDEX user_grants_user ON user_grants (tenant_id, user_id);
```

The constraint name `client_grants_tenant_id_client_id_audience_key` is PostgreSQL's default for 0001's unnamed `UNIQUE (tenant_id, client_id, audience)`. Confirm it with `./scripts/test-sql.sh` (Step 5); if the name differs, use the name `\d client_grants` reports.

`mysql/0003_consent.sql`. Strings are `VARCHAR`, and the user-grant key is a hash, because four `VARCHAR(255)` utf8mb4 columns exceed InnoDB's 3072-byte index limit:

```sql
ALTER TABLE tenants
  ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN use_scope_descriptions_for_consent BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients
  ADD COLUMN is_first_party BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN third_party_security_mode VARCHAR(16) NOT NULL DEFAULT '',
  ADD COLUMN redirection_policy VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NULL;
ALTER TABLE resource_servers
  ADD COLUMN skip_consent_for_verifiable_first_party_clients BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN user_policy VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN client_policy VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE connections ADD COLUMN is_domain_connection BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE client_grants
  ADD COLUMN subject_type VARCHAR(16) NOT NULL DEFAULT 'client',
  DROP INDEX client_grants_client_audience,
  ADD UNIQUE KEY client_grants_client_audience_subject (tenant_id, client_id, audience, subject_type);
CREATE TABLE user_grants (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  audience VARCHAR(255) NOT NULL,
  scopes LONGTEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  grant_key BINARY(32) AS (UNHEX(SHA2(CONCAT_WS(CHAR(10), client_id, user_id, audience), 256))) STORED,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY user_grants_key (tenant_id, grant_key),
  KEY user_grants_user (tenant_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
```

- [ ] **Step 4: Update the repositories**

Follow the `connections.go` change from migration 0002 (commit 6349287): extend the column constant, the INSERT placeholders, the UPDATE column list, the scan and the args, in that order.

| File | New columns, in this order at the end of the column list |
|---|---|
| `tenants.go` | `skip_non_verifiable_callback_uri_confirmation_prompt, use_scope_descriptions_for_consent` |
| `clients.go` | `is_first_party, third_party_security_mode, redirection_policy, skip_non_verifiable_callback_uri_confirmation_prompt` (scan the last into `sql.NullBool`; write `nil` for a nil pointer) |
| `resource_servers.go` | `skip_consent_for_verifiable_first_party_clients, user_policy, client_policy` (`user_policy` ↔ `SubjectTypeAuthorization.User`) |
| `connections.go` | `is_domain_connection` |
| `client_grants.go` | `subject_type` in `Create` and in `Find`'s SELECT and WHERE (`AND subject_type = ?`). `Update` also selects `subject_type` and returns `ErrConflict` if it changed |

Nullable-bool helpers, in `codec.go`:

```go
func nullBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func fromNullBool(v sql.NullBool) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Bool
	return &b
}
```

Create `internal/store/sqlstore/user_grants.go`:

```go
package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type userGrants struct{ s *Store }

func (s *Store) UserGrants() store.UserGrants { return userGrants{s} }

const userGrantCols = `tenant_id, id, client_id, user_id, audience, scopes, created_at, updated_at`

func scanUserGrant(row scanner) (*store.UserGrant, error) {
	var g store.UserGrant
	var scopes string
	var created, updated int64
	if err := row.Scan(&g.TenantID, &g.ID, &g.ClientID, &g.UserID, &g.Audience, &scopes, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &g.Scopes); err != nil {
		return nil, err
	}
	g.CreatedAt, g.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &g, nil
}

func (r userGrants) Find(ctx context.Context, tenantID, clientID, userID, audience string) (*store.UserGrant, error) {
	g, err := scanUserGrant(r.s.queryRow(ctx, `SELECT `+userGrantCols+` FROM user_grants
 WHERE tenant_id = ? AND client_id = ? AND user_id = ? AND audience = ?`, tenantID, clientID, userID, audience))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return g, err
}

// Upsert is SELECT ... FOR UPDATE then UPDATE or INSERT in one transaction.
// A concurrent first insert of the same key loses on the unique key; the
// loser retries once and then finds the row to update.
func (r userGrants) Upsert(ctx context.Context, g *store.UserGrant) (*store.UserGrant, error) {
	scopes, err := toJSON(g.Scopes)
	if err != nil {
		return nil, err
	}
	var out *store.UserGrant
	attempt := func() error {
		return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
			old, err := scanUserGrant(tx.queryRow(ctx, `SELECT `+userGrantCols+` FROM user_grants
 WHERE tenant_id = ? AND client_id = ? AND user_id = ? AND audience = ?`+tx.d.forUpdate, g.TenantID, g.ClientID, g.UserID, g.Audience))
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if _, err := tx.exec(ctx, `INSERT INTO user_grants (`+userGrantCols+`) VALUES (?,?,?,?,?,?,?,?)`,
					g.TenantID, g.ID, g.ClientID, g.UserID, g.Audience, scopes, micros(g.CreatedAt), micros(g.UpdatedAt)); err != nil {
					return tx.conflict(err)
				}
				out = &store.UserGrant{TenantID: g.TenantID, ID: g.ID, ClientID: g.ClientID, UserID: g.UserID,
					Audience: g.Audience, Scopes: append([]string(nil), g.Scopes...), CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
				return nil
			case err != nil:
				return err
			}
			if _, err := tx.exec(ctx, `UPDATE user_grants SET scopes = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`,
				scopes, micros(g.UpdatedAt), old.TenantID, old.ID); err != nil {
				return err
			}
			old.Scopes, old.UpdatedAt = append([]string(nil), g.Scopes...), fromMicros(micros(g.UpdatedAt))
			out = old
			return nil
		})
	}
	err = attempt()
	if errors.Is(err, store.ErrConflict) {
		err = attempt()
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r userGrants) ListByUser(ctx context.Context, tenantID, userID string) ([]*store.UserGrant, error) {
	rows, err := r.s.query(ctx, `SELECT `+userGrantCols+` FROM user_grants WHERE tenant_id = ? AND user_id = ? ORDER BY client_id, audience`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.UserGrant
	for rows.Next() {
		g, err := scanUserGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r userGrants) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM user_grants WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r userGrants) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	res, err := r.s.write(ctx, nil, `DELETE FROM user_grants WHERE tenant_id = ? AND user_id = ?`, tenantID, userID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
```

If `scanner`, `forUpdate` or the `ORDER BY` collation differ from what this assumes, follow the existing repositories. `clients.go` orders by `client_id`, and the MySQL tables use the binary collation, so byte order matches the memory driver's `cmp.Compare`. Remove the temporary panic from Task 2.

- [ ] **Step 5: Run the SQL conformance suites**

Run: `go test -race ./internal/store/sqlstore/`
Expected: PASS (SQLite, including the full storetest).

Run: `./scripts/test-sql.sh ./internal/store/sqlstore/`
Expected: PASS on PostgreSQL and MySQL (podman). If podman is not running, ask the maintainer to start it; do not skip.

- [ ] **Step 6: Commit**

```bash
git add internal/store/sqlstore
git commit -m "feat(sqlstore): migration 0003; user grants; consent and third-party columns"
```

---

### Task 4: The gRPC plugin protocol

**Files:**
- Modify: `proto/store/v1/store.proto` (regenerate with `go generate ./proto/...`)
- Modify: `internal/store/grpcstore/{codec,codec_test,client,client_repos,server_repos}.go`

**Interfaces:**
- Consumes: Task 2.
- Produces: the plugin wire format for every new field and the `UserGrants` RPCs.

- [ ] **Step 1: Write the failing codec tests**

In `internal/store/grpcstore/codec_test.go`, add the new fields to the existing round-trip fixtures: a third-party client with a `*bool` set; a tenant with both booleans true; a resource server with skip `false` and both policies; a `user` client grant; a domain connection; and a `UserGrant`. Then add:

```go
// A plugin built before the consent fields leaves them absent. Absence must
// keep today's behaviour: a first-party client, an API that skips consent
// for it, and a client-credentials grant.
func TestCodecDefaultsForOldPlugins(t *testing.T) {
	c, err := clientFromPB(&storev1.Client{TenantId: "t", ClientId: "c", CreatedAt: tsToPB(time.Unix(0, 0))})
	if err != nil || !c.IsFirstParty || c.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
		t.Fatalf("client: %+v %v", c, err)
	}
	rs, err := resourceServerFromPB(&storev1.ResourceServer{TenantId: "t", Id: "r", CreatedAt: tsToPB(time.Unix(0, 0))})
	if err != nil || !rs.SkipConsentForVerifiableFirstPartyClients {
		t.Fatalf("resource server: %+v %v", rs, err)
	}
	g, err := clientGrantFromPB(&storev1.ClientGrant{TenantId: "t", Id: "g", CreatedAt: tsToPB(time.Unix(0, 0))})
	if err != nil || g.SubjectType != store.SubjectTypeClient {
		t.Fatalf("grant: %+v %v", g, err)
	}
}
```

In `client_test.go`, add a test using a fake server whose `ClientGrantsFind` ignores the subject type and always returns a `client` grant. Follow the file's existing fake-server pattern:

```go
func TestFindIgnoresWrongSubjectType(t *testing.T) {
	// An old plugin ignores subject_type and returns the client grant.
	c := newFakeClient(t, fakeServer{clientGrantsFind: func(*storev1.ClientGrantsFindRequest) *storev1.ClientGrantResult {
		return &storev1.ClientGrantResult{Value: &storev1.ClientGrant{TenantId: "t", Id: "g", ClientId: "c", Audience: "a",
			SubjectType: "client", CreatedAt: tsToPB(time.Unix(0, 0))}}
	}})
	_, err := c.ClientGrants().Find(context.Background(), "t", "c", "a", store.SubjectTypeUser)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
```

If `client_test.go` has no fake-server helper, write the test against `grpcstore.NewServer` over a store wrapper whose `ClientGrants().Find` ignores the subject type, served through the same bufconn setup `conformance_test.go` uses.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/grpcstore/ -run 'Codec|SubjectType'`
Expected: compile errors (unknown fields).

- [ ] **Step 3: Extend the protocol**

`proto/store/v1/store.proto`. Append the fields; never renumber:

```proto
message Tenant {
  // ... fields 1-13 ...
  bool skip_non_verifiable_callback_uri_confirmation_prompt = 14;
  bool use_scope_descriptions_for_consent = 15;
}
message Client {
  // ... fields 1-14 ...
  optional bool is_first_party = 15;                                       // absent = true
  string third_party_security_mode = 16;
  string redirection_policy = 17;
  optional bool skip_non_verifiable_callback_uri_confirmation_prompt = 18; // absent = nil
}
message ResourceServer {
  // ... fields 1-9 ...
  optional bool skip_consent_for_verifiable_first_party_clients = 10;      // absent = true
  string user_policy = 11;
  string client_policy = 12;
}
message ClientGrant {
  // ... fields 1-6 ...
  string subject_type = 7; // empty = "client" (plugins older than Plan 9)
}
message Connection {
  // ... fields 1-14 ...
  bool is_domain_connection = 15;
}
message ClientGrantsFindRequest { string tx_id = 1; string tenant_id = 2; string client_id = 3; string audience = 4; string subject_type = 5; }

message UserGrant {
  string tenant_id = 1; string id = 2; string client_id = 3; string user_id = 4; string audience = 5;
  StringList scopes = 6; google.protobuf.Timestamp created_at = 7; google.protobuf.Timestamp updated_at = 8;
}
message UserGrantWrite { string tx_id = 1; UserGrant value = 2; }
message UserGrantsFindRequest { string tx_id = 1; string tenant_id = 2; string client_id = 3; string user_id = 4; string audience = 5; }
message UserGrantResult { Error error = 1; UserGrant value = 2; }
message UserGrantList { Error error = 1; repeated UserGrant values = 2; }
```

Add these RPCs after the `ClientGrants*` RPCs:

```proto
  rpc UserGrantsFind(UserGrantsFindRequest) returns (UserGrantResult);
  rpc UserGrantsUpsert(UserGrantWrite) returns (UserGrantResult);
  rpc UserGrantsListByUser(ScopedKey) returns (UserGrantList);   // key = user_id
  rpc UserGrantsDelete(ScopedKey) returns (Result);
  rpc UserGrantsDeleteByUser(ScopedKey) returns (CountResult);   // key = user_id
```

Update the header comment's field notes for the new "absent =" rules. Run `go generate ./proto/...`.

`codec.go`:
- `clientToPB` always sets `IsFirstParty: proto.Bool(c.IsFirstParty)`. `clientFromPB` uses `pb.IsFirstParty == nil || *pb.IsFirstParty`.
- The skip pointer is copied both ways.
- Resource servers use the same pattern for the skip-consent flag, and map `user_policy`/`client_policy` to `SubjectTypeAuthorization`.
- `clientGrantFromPB` maps `""` to `store.SubjectTypeClient`.
- Add `userGrantToPB`/`userGrantFromPB` in the style of `clientGrantToPB`, using `stringsToPB`, `tsToPB`, `checkTS` and `tsFromPB`.

`client_repos.go`:
- `Find` sends `SubjectType` and, after decoding, returns `store.ErrNotFound` if `got.SubjectType != subjectType`. This is the old-plugin guard.
- Add `clientUserGrants` with `Find` (via `decOne`), `Upsert` (the `UserGrantResult` decoded with `decOne`), `ListByUser` (`decList`), `Delete` (`do`) and `DeleteByUser` (`counted`).
- `client.go` gets `func (c *Client) UserGrants() store.UserGrants { return clientUserGrants{c} }`; remove Task 2's panic.

`server_repos.go`: `ClientGrantsFind` passes `r.SubjectType`, mapping `""` to `client` for hosts older than Plan 9. Add the five `UserGrants*` handlers with the `one`, `many`, `exec` and `count` helpers:

```go
func (s *Server) UserGrantsUpsert(ctx context.Context, r *storev1.UserGrantWrite) (*storev1.UserGrantResult, error) {
	g, err := userGrantFromPB(r.Value)
	if err != nil {
		return &storev1.UserGrantResult{Error: errToPB(err)}, nil
	}
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.UserGrant, error) {
		return st.UserGrants().Upsert(ctx, g)
	}, userGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserGrantResult{Error: e, Value: v}, nil
}
```

`userGrantToPB(nil)` must return `nil, nil`, as `clientGrantToPB` does.

- [ ] **Step 4: Run the plugin tests and full conformance through a plugin**

Run: `go test -race ./internal/store/grpcstore/ ./cmd/zeroauthy-store-memory/... ./pkg/storeplugin/...`
Expected: PASS, including `storetest` over gRPC.

Run: `go generate ./... && git diff --exit-code -- proto internal/gen`
Expected: no diff after the generated files are committed.

- [ ] **Step 5: Commit**

```bash
git add proto internal/store/grpcstore
git commit -m "feat(grpcstore): consent fields and user grants in the plugin protocol"
```

---

### Task 5: The seed

**Files:**
- Modify: `internal/seed/{seed,validate,apply}.go`, `internal/seed/seed_test.go`

**Interfaces:**
- Consumes: Task 2's store fields.
- Produces: the seed YAML schema below, used by Tasks 7–10 fixtures and the E2E seed.

```yaml
tenants:
  - name: acme
    skip_non_verifiable_callback_uri_confirmation_prompt: false   # default false
    use_scope_descriptions_for_consent: false                      # default false
    resource_servers:
      - identifier: https://api
        skip_consent_for_verifiable_first_party_clients: true      # default false (O1a, as on Auth0)
        subject_type_authorization:
          user: {policy: allow_all}                                # default per O1b
          client: {policy: require_client_grant}
    clients:
      - client_id: partner
        is_first_party: false                                      # default true
        third_party_security_mode: strict                          # third-party only; default per O1c
        redirection_policy: open_redirect_protection               # default per O1d
        skip_non_verifiable_callback_uri_confirmation_prompt: true # optional; unset = tenant value
    client_grants:
      - {client_id: partner, audience: https://api, subject_type: user, scopes: [read:things]}  # subject_type default per O1e
    connections:
      - {name: Username-Password-Authentication, is_domain_connection: true}  # default false
```

- [ ] **Step 1: Write the failing tests**

Add to `internal/seed/seed_test.go`. The existing error-table test takes `name: {yaml, wantErrSubstring}`; add rows:

```go
		"first-party with mode":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, third_party_security_mode: strict}]}]`, `third_party_security_mode is only for third-party`},
		"bad mode":                  {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, third_party_security_mode: loose}]}]`, `third_party_security_mode "loose"`},
		"bad redirection policy":    {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, redirection_policy: sometimes}]}]`, `redirection_policy "sometimes"`},
		"third-party password":      {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, is_first_party: false, third_party_security_mode: permissive, grant_types: [password]}]}]`, `grant type "password" is not available to third-party applications`},
		"strict implicit-free list": {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, grant_types: [authorization_code, "urn:ietf:params:oauth:grant-type:device_code"]}]}]`, `not available to strict third-party applications`},
		"strict non-expiring":       {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, is_first_party: false, grant_types: [authorization_code, refresh_token], refresh_token: {rotation_type: non-rotating, expiration_type: non-expiring}}]}]`, `strict third-party applications require expiring refresh tokens`},
		"strict public m2m":         {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, grant_types: [client_credentials]}]}]`, `client_credentials requires a confidential client`},
		"bad user policy":           {`tenants: [{name: a, resource_servers: [{identifier: "https://x", subject_type_authorization: {user: {policy: maybe}}}]}]`, `subject_type_authorization.user.policy "maybe"`},
		"client allow_all":          {`tenants: [{name: a, resource_servers: [{identifier: "https://x", subject_type_authorization: {client: {policy: allow_all}}}]}]`, `subject_type_authorization.client.policy "allow_all"`},
		"bad subject type":          {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", subject_type: robot}]}]`, `subject_type "robot"`},
		"third-party enabled":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, callbacks: ["https://c.test/cb"]}], connections: [{name: db, enabled_clients: [c]}]}]`, `third-party application "c" cannot be enabled on a connection; use is_domain_connection`},
		"dup grant same subject":    {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", subject_type: user}, {client_id: c, audience: "https://x", subject_type: user}]}]`, `duplicate client grant`},
```

Add an apply test:

```go
func TestApplyConsentFields(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`
tenants:
  - name: a
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    use_scope_descriptions_for_consent: true
    resource_servers:
      - identifier: https://x
        skip_consent_for_verifiable_first_party_clients: false
        subject_type_authorization: {user: {policy: require_client_grant}}
        scopes: [{value: read}]
    clients:
      - {client_id: first, app_type: spa, callbacks: ["https://f.test/cb"]}
      - {client_id: third, app_type: spa, is_first_party: false, callbacks: ["https://t.test/cb"], skip_non_verifiable_callback_uri_confirmation_prompt: false}
      - {client_id: m2m, app_type: non_interactive, client_secret: s}
    client_grants:
      - {client_id: third, audience: https://x, subject_type: user, scopes: [read]}
      - {client_id: m2m, audience: https://x, scopes: [read]}
    connections:
      - {name: db, is_domain_connection: true, enabled_clients: [first]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, nil, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "a")
	if !tn.SkipNonVerifiableCallbackURIConfirmationPrompt || !tn.UseScopeDescriptionsForConsent {
		t.Errorf("tenant flags: %+v", tn)
	}
	first, _ := st.Clients().Get(ctx, tn.ID, "first")
	if !first.IsFirstParty || first.ThirdPartySecurityMode != "" || first.RedirectionPolicy != store.RedirectionPolicyAllowAlways || first.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
		t.Errorf("first: %+v", first)
	}
	third, _ := st.Clients().Get(ctx, tn.ID, "third")
	if third.IsFirstParty || third.ThirdPartySecurityMode != store.SecurityModeStrict ||
		third.RedirectionPolicy != store.RedirectionPolicyOpenRedirectProtection ||
		third.SkipNonVerifiableCallbackURIConfirmationPrompt == nil || *third.SkipNonVerifiableCallbackURIConfirmationPrompt {
		t.Errorf("third: %+v", third)
	}
	rs, _ := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://x")
	if rs.SkipConsentForVerifiableFirstPartyClients || rs.SubjectTypeAuthorization != (store.SubjectTypeAuthorization{User: store.PolicyRequireClientGrant, Client: store.PolicyRequireClientGrant}) {
		t.Errorf("rs: %+v", rs)
	}
	if _, err := st.ClientGrants().Find(ctx, tn.ID, "third", "https://x", store.SubjectTypeUser); err != nil {
		t.Errorf("user grant: %v", err)
	}
	if _, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://x", store.SubjectTypeClient); err != nil {
		t.Errorf("client grant (default subject type): %v", err)
	}
	conn, _ := st.Connections().GetByName(ctx, tn.ID, "db")
	if !conn.IsDomainConnection {
		t.Errorf("connection: %+v", conn)
	}
}

func TestApplyRefusesPartyChange(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	first, _ := Parse([]byte(`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://c.test/cb"]}]}]`))
	if err := Apply(ctx, st, first, nil, nil); err != nil {
		t.Fatal(err)
	}
	third, _ := Parse([]byte(`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, callbacks: ["https://c.test/cb"]}]}]`))
	err := Apply(ctx, st, third, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot change after creation") {
		t.Fatalf("err = %v", err)
	}
}
```

Existing expectations: `TestApply…` cases that compare whole `store.Client` or `store.ResourceServer` values gain `IsFirstParty: true`, `RedirectionPolicy: allow_always`, `SkipConsentForVerifiableFirstPartyClients: false` (the new default) and the two default policies.

**Seeds that must keep today's behaviour.** Every test seed and fixture whose first-party flows must not hit consent gets `skip_consent_for_verifiable_first_party_clients: true` on each resource server. Find them with `grep -rln 'resource_servers' --include='*.go' --include='*.yaml' internal cmd tests`. That covers `internal/authz/fixture_test.go`, `internal/oauth/fixture_test.go`, `internal/login/login_test.go`, `internal/server/*_test.go`, `internal/dbconn/*_test.go`, `cmd/zeroauthy/*_test.go` and `tests/e2e/seed.yaml`. Add it in this task, so later tasks start from green seeds. Add a seed test that an omitted flag applies as `false`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/seed/`
Expected: FAIL (unknown YAML fields).

- [ ] **Step 3: Implement**

`seed.go`:

```go
// Tenant gains:
	SkipNonVerifiableCallbackURIConfirmationPrompt bool `yaml:"skip_non_verifiable_callback_uri_confirmation_prompt"`
	UseScopeDescriptionsForConsent                 bool `yaml:"use_scope_descriptions_for_consent"`

// ResourceServer gains:
	SkipConsentForVerifiableFirstPartyClients *bool                    `yaml:"skip_consent_for_verifiable_first_party_clients"`
	SubjectTypeAuthorization                  SubjectTypeAuthorization `yaml:"subject_type_authorization"`

// SubjectTypeAuthorization is Auth0's API access policy object.
type SubjectTypeAuthorization struct {
	User   AccessPolicy `yaml:"user"`
	Client AccessPolicy `yaml:"client"`
}

type AccessPolicy struct {
	Policy string `yaml:"policy"`
}

// Client gains:
	IsFirstParty                                   *bool  `yaml:"is_first_party"`
	ThirdPartySecurityMode                         string `yaml:"third_party_security_mode"`
	RedirectionPolicy                              string `yaml:"redirection_policy"`
	SkipNonVerifiableCallbackURIConfirmationPrompt *bool  `yaml:"skip_non_verifiable_callback_uri_confirmation_prompt"`

// ClientGrant gains:
	SubjectType string `yaml:"subject_type"`

// Connection gains:
	IsDomainConnection bool `yaml:"is_domain_connection"`
```

`validate.go`. In the client loop, after the auth method is settled and before the refresh-token defaults:

```go
		firstParty := c.IsFirstParty == nil || *c.IsFirstParty
		c.IsFirstParty = &firstParty
		thirdParty[c.ClientID] = !firstParty
		switch {
		case firstParty && c.ThirdPartySecurityMode != "":
			fail("client %q: third_party_security_mode is only for third-party applications", c.ClientID)
		case !firstParty && c.ThirdPartySecurityMode == "":
			c.ThirdPartySecurityMode = store.SecurityModeStrict // O1c
		}
		if !firstParty && c.ThirdPartySecurityMode != store.SecurityModeStrict && c.ThirdPartySecurityMode != store.SecurityModePermissive {
			fail("client %q: third_party_security_mode %q must be strict or permissive", c.ClientID, c.ThirdPartySecurityMode)
		}
		if c.RedirectionPolicy == "" {
			c.RedirectionPolicy = store.RedirectionPolicyAllowAlways // O1d
			if !firstParty {
				c.RedirectionPolicy = store.RedirectionPolicyOpenRedirectProtection
			}
		}
		if c.RedirectionPolicy != store.RedirectionPolicyAllowAlways && c.RedirectionPolicy != store.RedirectionPolicyOpenRedirectProtection {
			fail("client %q: redirection_policy %q must be %s or %s", c.ClientID, c.RedirectionPolicy,
				store.RedirectionPolicyOpenRedirectProtection, store.RedirectionPolicyAllowAlways)
		}
		strict := !firstParty && c.ThirdPartySecurityMode == store.SecurityModeStrict
		for _, gt := range c.GrantTypes {
			switch {
			case !firstParty && (gt == "password" || gt == "http://auth0.com/oauth/grant-type/password-realm"):
				fail("client %q: grant type %q is not available to third-party applications", c.ClientID, gt)
			case strict && !slices.Contains(strictGrantTypes, gt):
				fail("client %q: grant type %q is not available to strict third-party applications", c.ClientID, gt)
			}
		}
		if strict && slices.Contains(c.GrantTypes, "client_credentials") && c.TokenEndpointAuthMethod == store.AuthMethodNone {
			fail("client %q: client_credentials requires a confidential client", c.ClientID)
		}
		if strict && store.AppType(c.AppType) == store.AppTypeNative && c.RefreshToken.RotationType == "" {
			c.RefreshToken.RotationType = "rotating" // strict default for native apps
		}
```

with `var strictGrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}` next to `appTypes`. After the existing refresh-token switch, add:

```go
		if strict && rt.ExpirationType != "expiring" {
			fail("client %q: strict third-party applications require expiring refresh tokens", c.ClientID)
		}
```

In the resource-server loop:

```go
		if rs.SkipConsentForVerifiableFirstPartyClients == nil {
			skip := false // O1a: Auth0's default for new APIs (D-0026)
			rs.SkipConsentForVerifiableFirstPartyClients = &skip
		}
		sta := &rs.SubjectTypeAuthorization
		if sta.User.Policy == "" {
			sta.User.Policy = store.PolicyAllowAll
		}
		if sta.Client.Policy == "" {
			sta.Client.Policy = store.PolicyRequireClientGrant
		}
		if !slices.Contains([]string{store.PolicyAllowAll, store.PolicyRequireClientGrant, store.PolicyDenyAll}, sta.User.Policy) {
			fail("resource server %q: subject_type_authorization.user.policy %q must be allow_all, require_client_grant or deny_all", rs.Identifier, sta.User.Policy)
		}
		if !slices.Contains([]string{store.PolicyRequireClientGrant, store.PolicyDenyAll}, sta.Client.Policy) {
			fail("resource server %q: subject_type_authorization.client.policy %q must be require_client_grant or deny_all", rs.Identifier, sta.Client.Policy)
		}
```

The client-grant loop takes a pointer to each grant so the default sticks:

```go
	seenGrants := map[[3]string]bool{}
	for i := range t.ClientGrants {
		g := &t.ClientGrants[i]
		if g.SubjectType == "" {
			g.SubjectType = store.SubjectTypeClient // O1e
		}
		if g.SubjectType != store.SubjectTypeClient && g.SubjectType != store.SubjectTypeUser {
			fail("client grant %q → %q: subject_type %q must be client or user", g.ClientID, g.Audience, g.SubjectType)
		}
		// ... existing unknown-client / unknown-audience checks ...
		k := [3]string{g.ClientID, g.Audience, g.SubjectType}
		if seenGrants[k] {
			fail("duplicate client grant %q → %q (%s)", g.ClientID, g.Audience, g.SubjectType)
		}
		seenGrants[k] = true
		// ... existing scope checks ...
	}
```

Declare `thirdParty := map[string]bool{}` next to `clients := map[string]bool{}` in `(*Tenant).validate`. In the connection loop, the `enabled_clients` check becomes:

```go
		for _, id := range c.EnabledClients {
			switch {
			case !clients[id]:
				fail("connection %q: unknown client %q", c.Name, id)
			case thirdParty[id]:
				// Auth0 refuses this (observations/consent.md): third-party
				// applications reach connections only at the domain level.
				fail("connection %q: third-party application %q cannot be enabled on a connection; use is_domain_connection", c.Name, id)
			}
		}
```

`apply.go`:
- **Tenant** create and update set the two flags.
- **`applyResourceServer`** sets `rs.SkipConsentForVerifiableFirstPartyClients = *in.SkipConsentForVerifiableFirstPartyClients` and `rs.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: in.SubjectTypeAuthorization.User.Policy, Client: in.SubjectTypeAuthorization.Client.Policy}`.
- **`applyClient`**, before assigning, when not creating:

```go
	if !create && (c.IsFirstParty != *in.IsFirstParty || c.ThirdPartySecurityMode != in.ThirdPartySecurityMode) {
		return errors.New("is_first_party and third_party_security_mode cannot change after creation; use a new client_id")
	}
	c.IsFirstParty, c.ThirdPartySecurityMode = *in.IsFirstParty, in.ThirdPartySecurityMode
	c.RedirectionPolicy = in.RedirectionPolicy
	c.SkipNonVerifiableCallbackURIConfirmationPrompt = nil
	if p := in.SkipNonVerifiableCallbackURIConfirmationPrompt; p != nil {
		v := *p
		c.SkipNonVerifiableCallbackURIConfirmationPrompt = &v
	}
```

- **`applyClientGrant`** finds and creates with `in.SubjectType`.
- **`applyConnection`** sets `c.IsDomainConnection = in.IsDomainConnection`.

Seeds run `validate` before `apply` (`Parse` calls `validate`), so the pointers are never nil in `apply`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/seed/ ./internal/... 2>&1 | tail -30`
Expected: seed tests PASS. Other packages may fail only where a test compares a whole seeded client or resource server; update those expectations to the new defaults.

- [ ] **Step 5: Commit**

```bash
git add internal/seed
git commit -m "feat(seed): third-party clients, access policies, consent and domain-connection settings"
```

---

### Task 6: The access decision

**Files:**
- Create: `internal/access/access.go`, `internal/access/observed.go`, `internal/access/access_test.go`

**Interfaces:**
- Consumes: Task 2's store types.
- Produces (used by Tasks 7, 8 and 10):

```go
package access

type Flow int

const (
	Interactive       Flow = iota // /authorize
	Password                      // password and password-realm grants
	Refresh                       // refresh_token grant
	ClientCredentials             // client_credentials grant
)

type Input struct {
	Flow   Flow
	Client *store.Client
	// API is the audience's resource server; nil when there is no audience.
	API *store.ResourceServer
	// ClientGrant is the client's grant for API with SubjectType(Flow), or nil.
	ClientGrant *store.ClientGrant
	// UserGrant is the user's consent for Client and the audience, or nil.
	UserGrant   *store.UserGrant
	Scopes      []string // requested (Interactive, Password) or held (Refresh)
	Prompts     []string
	RedirectURI string
	// TenantSkipConfirmation is the tenant's
	// skip_non_verifiable_callback_uri_confirmation_prompt.
	TenantSkipConfirmation bool
	// ScreenShown means the user already saw a login, signup or consent
	// screen in this transaction, so no confirmation is needed (D-0027).
	ScreenShown bool
}

type Decision struct {
	Scopes       []string // to issue; nil for ClientCredentials (the grant decides)
	Consent      bool     // show the consent screen
	Confirmation bool     // show the confirmation screen
	Err          *Error
}

type Error struct{ Code, Description string }

func Decide(in Input) Decision
func SubjectType(f Flow) string                       // "client" for ClientCredentials, else "user"
func NonVerifiable(redirectURI string) bool
func ConnectionUsable(c *store.Client, conn *store.Connection) bool
func ShowErrorPage(c *store.Client) bool             // redirection_policy: every /authorize error becomes a page
func GrantScopes(existing, accepted []string) []string // O3
func Strict(c *store.Client) bool
```

- [ ] **Step 1: Write the failing table tests**

Create `internal/access/access_test.go`:

```go
package access

import (
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func firstParty() *store.Client { return &store.Client{ClientID: "fp", IsFirstParty: true} }
func strict() *store.Client {
	return &store.Client{ClientID: "tp", ThirdPartySecurityMode: store.SecurityModeStrict, RedirectionPolicy: store.RedirectionPolicyOpenRedirectProtection}
}
func permissive() *store.Client {
	return &store.Client{ClientID: "pp", ThirdPartySecurityMode: store.SecurityModePermissive}
}
func api(mod ...func(*store.ResourceServer)) *store.ResourceServer {
	rs := &store.ResourceServer{Identifier: "https://api", SkipConsentForVerifiableFirstPartyClients: true,
		Scopes: []store.Scope{{Value: "read"}, {Value: "write"}}}
	for _, m := range mod {
		m(rs)
	}
	return rs
}
func userPolicy(p string) func(*store.ResourceServer) {
	return func(rs *store.ResourceServer) { rs.SubjectTypeAuthorization.User = p }
}
func noSkip(rs *store.ResourceServer) { rs.SkipConsentForVerifiableFirstPartyClients = false }
func grant(scopes ...string) *store.ClientGrant {
	return &store.ClientGrant{Audience: "https://api", SubjectType: store.SubjectTypeUser, Scopes: scopes}
}
func ugrant(scopes ...string) *store.UserGrant { return &store.UserGrant{Audience: "https://api", Scopes: scopes} }

const web = "https://app.example/cb"

func TestDecide(t *testing.T) {
	yes := true
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		{"first-party skips consent", Input{Flow: Interactive, Client: firstParty(), API: api(), Scopes: []string{"openid", "read", "nope"}, RedirectURI: web},
			Decision{Scopes: []string{"openid", "read"}}},
		{"first-party consent when API does not skip", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"first-party consent covered by grant", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), UserGrant: ugrant("read", "write"), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Scopes: []string{"read"}}},
		{"prompt=consent forces consent", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), UserGrant: ugrant("read"), Scopes: []string{"read"}, Prompts: []string{"consent"}, RedirectURI: web},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"first-party no audience: no consent", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid", "profile"}, RedirectURI: web},
			Decision{Scopes: []string{"openid", "profile"}}},
		{"first-party localhost: confirmation", Input{Flow: Interactive, Client: firstParty(), API: api(), Scopes: []string{"read"}, RedirectURI: "http://localhost:3000/cb"},
			Decision{Scopes: []string{"read"}, Confirmation: !firstPartyNonVerifiableConsent, Consent: firstPartyNonVerifiableConsent}},
		{"custom scheme: confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, RedirectURI: "com.example.app:/cb"},
			Decision{Scopes: []string{"openid"}, Confirmation: true}},
		{"tenant skips confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, RedirectURI: "http://127.0.0.1:9/cb", TenantSkipConfirmation: true},
			Decision{Scopes: []string{"openid"}}},
		{"client setting beats tenant", Input{Flow: Interactive, Client: &store.Client{IsFirstParty: true, SkipNonVerifiableCallbackURIConfirmationPrompt: &yes}, Scopes: []string{"openid"}, RedirectURI: "http://[::1]:9/cb"},
			Decision{Scopes: []string{"openid"}}},
		{"prompt=none needs confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, Prompts: []string{"none"}, RedirectURI: "http://localhost/cb"},
			Decision{Err: &Error{Code: codeConfirmationRequired}}},
		{"strict needs a grant under allow_all", Input{Flow: Interactive, Client: strict(), API: api(), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeAuthorizeDenied}}},
		{"strict: grant caps scopes, OIDC dropped, consent", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"openid", "profile", "read", "write", "offline_access"}, RedirectURI: web},
			Decision{Scopes: []string{"read", "offline_access"}, Consent: true}},
		{"strict: consent covered", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), UserGrant: ugrant("read", "offline_access"), Scopes: []string{"read", "offline_access"}, RedirectURI: web},
			Decision{Scopes: []string{"read", "offline_access"}}},
		{"strict: consent shown, so no confirmation", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"read"}, RedirectURI: "http://localhost/cb"},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"strict: prompt=none needs consent", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"read"}, Prompts: []string{"none"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeConsentRequired}}},
		{"strict: no audience", Input{Flow: Interactive, Client: strict(), Scopes: []string{"openid"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeStrictNoAudience}}},
		{"localhost right after login: no confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, RedirectURI: "http://localhost/cb", ScreenShown: true},
			Decision{Scopes: []string{"openid"}}},
		{"API without skip: consent even right after login", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}, RedirectURI: "http://localhost/cb", ScreenShown: true},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"permissive follows allow_all", Input{Flow: Interactive, Client: permissive(), API: api(), Scopes: []string{"openid", "read"}, RedirectURI: web},
			permissiveAllowAll()},
		{"permissive no audience asks consent", Input{Flow: Interactive, Client: permissive(), Scopes: []string{"openid", "profile"}, RedirectURI: web},
			Decision{Scopes: []string{"openid", "profile"}, Consent: consentWithoutAudience}},
		{"deny_all at authorize", Input{Flow: Interactive, Client: firstParty(), API: api(userPolicy(store.PolicyDenyAll)), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeAuthorizeDenied}}},
		{"require_client_grant without grant", Input{Flow: Interactive, Client: firstParty(), API: api(userPolicy(store.PolicyRequireClientGrant)), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeAuthorizeDenied}}},
		{"require_client_grant caps scopes", Input{Flow: Interactive, Client: firstParty(), API: api(userPolicy(store.PolicyRequireClientGrant)), ClientGrant: grant("write"), Scopes: []string{"read", "write"}, RedirectURI: web},
			Decision{Scopes: []string{"write"}}},
		{"password: third-party refused", Input{Flow: Password, Client: permissive(), API: api(), Scopes: []string{"read"}},
			Decision{Err: &Error{Code: "unauthorized_client"}}},
		{"password: deny_all", Input{Flow: Password, Client: firstParty(), API: api(userPolicy(store.PolicyDenyAll)), Scopes: []string{"read"}},
			Decision{Err: &Error{Code: codeTokenDenied}}},
		{"password: no consent or confirmation", Input{Flow: Password, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}, RedirectURI: "http://localhost/cb"},
			Decision{Scopes: []string{"read"}}},
		{"refresh: grant withdrawn", Input{Flow: Refresh, Client: strict(), API: api(), Scopes: []string{"read"}},
			Decision{Err: &Error{Code: codeTokenDenied}}},
		{"refresh: grant narrowed", Input{Flow: Refresh, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"read", "write"}},
			Decision{Scopes: []string{"read"}}},
		{"client credentials: deny_all", Input{Flow: ClientCredentials, Client: firstParty(), API: api(func(rs *store.ResourceServer) { rs.SubjectTypeAuthorization.Client = store.PolicyDenyAll }), ClientGrant: &store.ClientGrant{SubjectType: store.SubjectTypeClient}},
			Decision{Err: &Error{Code: "access_denied"}}},
		{"client credentials: no grant", Input{Flow: ClientCredentials, Client: firstParty(), API: api()},
			Decision{Err: &Error{Code: "access_denied", Description: "client is not authorized for this audience"}}},
		{"client credentials: allowed", Input{Flow: ClientCredentials, Client: strict(), API: api(), ClientGrant: &store.ClientGrant{SubjectType: store.SubjectTypeClient}},
			Decision{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.in)
			if tt.want.Err != nil {
				if got.Err == nil || got.Err.Code != tt.want.Err.Code {
					t.Fatalf("Err = %+v, want code %q", got.Err, tt.want.Err.Code)
				}
				if tt.want.Err.Description != "" && got.Err.Description != tt.want.Err.Description {
					t.Fatalf("Description = %q, want %q", got.Err.Description, tt.want.Err.Description)
				}
				return
			}
			if got.Err != nil {
				t.Fatalf("unexpected error %+v", got.Err)
			}
			if !slices.Equal(got.Scopes, tt.want.Scopes) || got.Consent != tt.want.Consent || got.Confirmation != tt.want.Confirmation {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// permissiveAllowAll is the expected decision for a permissive client under
// allow_all with no grant (O8).
func permissiveAllowAll() Decision {
	if !permissiveFollowsPolicy {
		return Decision{Err: &Error{Code: codeAuthorizeDenied}}
	}
	return Decision{Scopes: []string{"openid", "read"}, Consent: true}
}

func TestNonVerifiable(t *testing.T) {
	for uri, want := range map[string]bool{
		"https://app.example/cb": false, "http://app.example/cb": false,
		"http://localhost:3000/": true, "https://localhost/cb": true, "http://LOCALHOST/cb": true,
		"http://127.0.0.1:8/cb": true, "http://[::1]:8/cb": true,
		"com.example.app:/oauth2redirect": true, "myapp://cb": true, "::bad": true,
	} {
		if got := NonVerifiable(uri); got != want {
			t.Errorf("NonVerifiable(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestConnectionUsable(t *testing.T) {
	conn := &store.Connection{EnabledClients: []string{"fp"}}
	domain := &store.Connection{IsDomainConnection: true}
	if !ConnectionUsable(firstParty(), conn) || ConnectionUsable(firstParty(), domain) {
		t.Error("first-party clients use enabled connections only")
	}
	if ConnectionUsable(strict(), conn) || !ConnectionUsable(strict(), domain) {
		t.Error("third-party clients use domain connections only")
	}
}

func TestShowErrorPage(t *testing.T) {
	if !ShowErrorPage(strict()) || !ShowErrorPage(permissive()) || ShowErrorPage(firstParty()) {
		t.Error("open_redirect_protection (and an unset third-party policy) shows errors as a page; first-party unset redirects")
	}
	open := strict()
	open.RedirectionPolicy = store.RedirectionPolicyAllowAlways
	if ShowErrorPage(open) {
		t.Error("allow_always redirects")
	}
}

func TestGrantScopes(t *testing.T) {
	got := GrantScopes([]string{"read"}, []string{"write", "read"})
	want := []string{"write", "read"}
	if mergeGrantScopes {
		want = []string{"read", "write"}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("GrantScopes = %v, want %v", got, want)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/access/`
Expected: FAIL (package does not exist).

- [ ] **Step 3: Implement**

`internal/access/observed.go`:

```go
package access

// Values Auth0's documentation leaves open, settled by observation on the
// maintainer's tenant (docs/compat/observations/consent.md, D-0025–D-0027).
// Change them only together with those records.
const (
	// O5: prompt=none when consent or the confirmation would be needed.
	codeConsentRequired      = "consent_required"
	codeConfirmationRequired = "consent_required"
	// O7: a user flow refused by the API's access policy (HTTP 400 at the
	// token endpoint).
	codeAuthorizeDenied = "invalid_request"
	codeTokenDenied     = "invalid_request"
	// O2b: a strict client that names no audience.
	codeStrictNoAudience = "invalid_request"
	// O8 (not observable; permissive-mode page): a permissive third-party
	// client may use an allow_all API without a client grant.
	permissiveFollowsPolicy = true
	// O4: a first-party client of an API that skips consent gets the
	// confirmation, not consent, for a non-verifiable callback.
	firstPartyNonVerifiableConsent = false
	// O2 (not observable; permissive only): a third-party request with no
	// audience asks consent.
	consentWithoutAudience = true
	// O3: accepting consent adds to a grant's scopes.
	mergeGrantScopes = true
)
```

`internal/access/access.go`:

```go
// Package access decides whether an application may get tokens for an API
// and whether the user must consent or confirm first. Decide is pure:
// callers load the records it needs. Auth0 sources and the observed values
// are listed in D-0025, D-0026 and D-0027.
package access

import (
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// (Flow, Input, Decision and Error as in the Interfaces block.)

var oidcScopes = []string{"openid", "profile", "email"}

// SubjectType is the client grant subject type a flow needs.
func SubjectType(f Flow) string {
	if f == ClientCredentials {
		return store.SubjectTypeClient
	}
	return store.SubjectTypeUser
}

// Strict reports whether c is a third-party client in strict mode. An
// unknown mode counts as strict (fail closed).
func Strict(c *store.Client) bool {
	return !c.IsFirstParty && c.ThirdPartySecurityMode != store.SecurityModePermissive
}

func Decide(in Input) Decision {
	if !in.Client.IsFirstParty && in.Flow == Password {
		return fail("unauthorized_client", "the password grant is not available to third-party applications")
	}
	if e := checkPolicy(in); e != nil {
		return Decision{Err: e}
	}
	if in.Flow == ClientCredentials {
		return Decision{}
	}
	d := Decision{Scopes: issuedScopes(in)}
	if in.Flow != Interactive {
		return d
	}
	d.Consent = needsConsent(in, d.Scopes)
	d.Confirmation = !d.Consent && !in.ScreenShown && NonVerifiable(in.RedirectURI) && !skipConfirmation(in)
	if slices.Contains(in.Prompts, "none") {
		switch {
		case d.Consent:
			return fail(codeConsentRequired, "the user must consent to this application")
		case d.Confirmation:
			return fail(codeConfirmationRequired, "the user must confirm this login")
		}
	}
	return d
}

func fail(code, desc string) Decision { return Decision{Err: &Error{Code: code, Description: desc}} }

func checkPolicy(in Input) *Error {
	code := codeTokenDenied
	switch in.Flow {
	case Interactive:
		code = codeAuthorizeDenied
	case ClientCredentials:
		code = "access_denied"
	}
	if in.API == nil {
		if Strict(in.Client) && in.Flow != ClientCredentials {
			return &Error{codeStrictNoAudience, "this application must request an API audience"}
		}
		return nil
	}
	policy := in.API.SubjectTypeAuthorization.User
	if in.Flow == ClientCredentials {
		policy = in.API.SubjectTypeAuthorization.Client
		if policy == "" {
			policy = store.PolicyRequireClientGrant
		}
	} else if policy == "" {
		policy = store.PolicyAllowAll
	}
	switch policy {
	case store.PolicyDenyAll:
		return &Error{code, "the API does not allow this application to access it"}
	case store.PolicyAllowAll:
		if in.ClientGrant == nil && !in.Client.IsFirstParty && (Strict(in.Client) || !permissiveFollowsPolicy) {
			return &Error{code, "the application is not authorized to access this API"}
		}
		return nil
	default: // require_client_grant and unknown values (fail closed)
		if in.ClientGrant == nil {
			if in.Flow == ClientCredentials {
				return &Error{code, "client is not authorized for this audience"}
			}
			return &Error{code, "the application is not authorized to access this API"}
		}
		return nil
	}
}

// issuedScopes keeps requested OIDC scopes (not for strict clients),
// offline_access, and scopes the API defines that the client grant, when
// there is one, allows. Order follows the request; duplicates are dropped.
func issuedScopes(in Input) []string {
	strict := Strict(in.Client)
	var out []string
	for _, s := range in.Scopes {
		if slices.Contains(out, s) {
			continue
		}
		switch {
		case slices.Contains(oidcScopes, s):
			if strict {
				continue
			}
		case s == "offline_access":
		default:
			if in.API == nil || !slices.ContainsFunc(in.API.Scopes, func(d store.Scope) bool { return d.Value == s }) {
				continue
			}
			if in.ClientGrant != nil && !slices.Contains(in.ClientGrant.Scopes, s) {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

func needsConsent(in Input, scopes []string) bool {
	if in.Client.IsFirstParty {
		if in.API == nil {
			return false
		}
		if in.API.SkipConsentForVerifiableFirstPartyClients &&
			!(firstPartyNonVerifiableConsent && NonVerifiable(in.RedirectURI)) {
			return false
		}
	} else if in.API == nil && !consentWithoutAudience {
		return false
	}
	if slices.Contains(in.Prompts, "consent") || in.UserGrant == nil {
		return true
	}
	for _, s := range scopes {
		if !slices.Contains(in.UserGrant.Scopes, s) {
			return true
		}
	}
	return false
}

func skipConfirmation(in Input) bool {
	if p := in.Client.SkipNonVerifiableCallbackURIConfirmationPrompt; p != nil {
		return *p
	}
	return in.TenantSkipConfirmation
}

// NonVerifiable reports whether the authorization server cannot verify
// which application receives redirectURI: custom schemes and loopback hosts.
func NonVerifiable(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return true
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// ConnectionUsable reports whether c may log users in through conn:
// third-party clients use domain connections, first-party clients the
// connections enabled for them.
func ConnectionUsable(c *store.Client, conn *store.Connection) bool {
	if !c.IsFirstParty {
		return conn.IsDomainConnection
	}
	return slices.Contains(conn.EnabledClients, c.ClientID)
}

// ShowErrorPage reports whether c's /authorize errors must be shown on an
// error page instead of redirected: under open_redirect_protection every
// error is (observed, D-0027).
func ShowErrorPage(c *store.Client) bool {
	policy := c.RedirectionPolicy
	if policy == "" && !c.IsFirstParty {
		policy = store.RedirectionPolicyOpenRedirectProtection
	}
	return policy == store.RedirectionPolicyOpenRedirectProtection
}

// GrantScopes is the scope list a user grant holds after the user accepts
// accepted on top of existing.
func GrantScopes(existing, accepted []string) []string {
	if !mergeGrantScopes {
		return slices.Clone(accepted)
	}
	out := slices.Clone(existing)
	for _, s := range accepted {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/access/ && go vet ./internal/access/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/access
git commit -m "feat(access): consent, third-party and API access policy decisions"
```

---

### Task 7: /authorize: strict checks, domain connections, decision and consent hand-off

**Files:**
- Modify: `internal/authz/{request,validate,handlers,errors}.go`
- Modify: `internal/authz/fixture_test.go`, `handlers_test.go`, `validate_test.go`
- Modify: `internal/login/login.go` (only `connection`: third-party clients use domain connections)

**Interfaces:**
- Consumes: `access.Decide`, `access.ConnectionUsable`, `access.ShowErrorPage`, `access.Strict`, `access.SubjectType`; `store.UserGrants`.
- Produces (used by Task 8):

```go
// ConsentView describes the consent page of a transaction.
type ConsentView struct {
	Confirmation   bool     // the confirmation variant; otherwise consent
	ThirdParty     bool     // show the external-application notice
	CallbackDomain string   // host of redirect_uri, or its scheme for custom schemes
	APIName        string   // the API's name (identifier when unnamed); empty without an audience
	Scopes         []string // labels: scope names, or descriptions per use_scope_descriptions_for_consent
	RedirectURI    string
}

func (h *Handlers) ConsentView(ctx context.Context, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (*ConsentView, error)
func (h *Handlers) Consent(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession, accepted bool)
// ActiveSession returns the browser's session for res, or nil when there is
// none or its user is missing or blocked.
func (h *Handlers) ActiveSession(ctx context.Context, r *http.Request, res tenant.Resolved) (*store.LoginSession, error)
```

- [ ] **Step 1: Write the failing tests**

Extend `fixtureSeed` in `internal/authz/fixture_test.go`:
- Give the existing `spa` client `skip_non_verifiable_callback_uri_confirmation_prompt: true`, so the existing tests that use its localhost and custom-scheme callbacks keep today's behaviour.
- Mark `Username-Password-Authentication` as `is_domain_connection: true`.
- Add:

```yaml
      - client_id: partner
        app_type: regular_web
        client_secret: partner-secret
        is_first_party: false
        grant_types: [authorization_code]
        callbacks: ["https://partner.example/cb", "http://localhost:4000/cb"]
      - client_id: partner-open
        app_type: regular_web
        client_secret: partner-open-secret
        is_first_party: false
        third_party_security_mode: permissive
        redirection_policy: allow_always
        grant_types: [authorization_code]
        callbacks: ["https://open.example/cb"]
      - client_id: local
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["http://localhost:5000/cb"]
```

Also add a second API (`{identifier: "https://locked.acme.test", name: Locked, subject_type_authorization: {user: {policy: deny_all}}, scopes: [{value: "read:things"}]}`), a user grant `client_grants: [{client_id: partner, audience: "https://api.acme.test", subject_type: user, scopes: ["read:things"]}]`, and `local` in `Username-Password-Authentication.enabled_clients`.

Add `UserGrants` lookups to the test env as needed. New tests in `handlers_test.go`:

```go
func partnerQuery() url.Values {
	q := url.Values{
		"client_id": {"partner"}, "redirect_uri": {"https://partner.example/cb"}, "response_type": {"code"},
		"scope": {"read:things"}, "audience": {"https://api.acme.test"}, "state": {"st"},
		"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
	}
	return q
}

func TestThirdPartyGoesToConsent(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, partnerQuery(), e.login(t, fixedNow()))
	loc := location(t, rec)
	if loc.Path != "/u/consent" || loc.Query().Get("state") == "" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestThirdPartyConsentCoveredIssuesCode(t *testing.T) {
	e := newEnv(t)
	e.grantConsent(t, "partner", "https://api.acme.test", "read:things")
	loc := location(t, e.get(t, partnerQuery(), e.login(t, fixedNow())))
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestPromptNoneConsentRequired(t *testing.T) {
	e := newEnv(t)
	// partner-open redirects errors (allow_always); partner would show a page.
	q := url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"},
		"audience": {"https://api.acme.test"}, "scope": {"read:things"}, "state": {"st"}, "prompt": {"none"}}
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if got := loc.Query().Get("error"); got != "consent_required" { // O5
		t.Fatalf("error = %q (%s)", got, loc)
	}
}

func TestProtectedClientErrorsArePages(t *testing.T) {
	e := newEnv(t)
	for name, q := range map[string]url.Values{
		"prompt=none, consent needed": func() url.Values { q := partnerQuery(); q.Set("prompt", "none"); return q }(),
		"no audience (strict)":        func() url.Values { q := partnerQuery(); q.Del("audience"); return q }(),
	} {
		rec := e.get(t, q, e.login(t, fixedNow()))
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: status %d Location %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	q := partnerQuery()
	q.Set("prompt", "none")
	if rec := e.get(t, q); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" { // no session: login_required as a page
		t.Errorf("no session: status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestStrictRejectsParameters(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"request_uri", "request", "id_token_hint", "claims", "login_ticket", "screen_hint"} {
		q := partnerQuery()
		q.Set(p, "x")
		loc := location(t, e.get(t, q))
		if loc.Query().Get("error") != "invalid_request" {
			t.Errorf("%s: Location = %s", p, loc)
		}
	}
}

func TestStrictRequiresPKCE(t *testing.T) {
	e := newEnv(t)
	q := partnerQuery()
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	loc := location(t, e.get(t, q))
	if loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestDenyAllUnderProtectionShowsErrorPage(t *testing.T) {
	e := newEnv(t)
	q := partnerQuery()
	q.Set("audience", "https://locked.acme.test")
	rec := e.get(t, q, e.login(t, fixedNow()))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDenyAllAllowAlwaysRedirects(t *testing.T) {
	e := newEnv(t)
	q := url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"},
		"audience": {"https://locked.acme.test"}, "state": {"st"}}
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Host != "open.example" || loc.Query().Get("error") != "invalid_request" { // O7
		t.Fatalf("Location = %s", loc)
	}
}

func TestLocalhostConfirmation(t *testing.T) {
	e := newEnv(t)
	q := url.Values{"client_id": {"local"}, "redirect_uri": {"http://localhost:5000/cb"}, "response_type": {"code"},
		"state": {"st"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}}
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Path != "/u/consent" {
		t.Fatalf("Location = %s", loc)
	}
	q.Set("prompt", "none")
	loc = location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Query().Get("error") != "consent_required" { // O5
		t.Fatalf("Location = %s", loc)
	}
}

func TestPromptConsentSurvivesLogin(t *testing.T) {
	e := newEnv(t)
	q := goodQuery()
	q.Set("prompt", "login consent")
	loc := location(t, e.get(t, q))
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params["prompt"] != "consent" {
		t.Fatalf("prompt kept in transaction = %q, want consent", txn.Params["prompt"])
	}
}

func TestThirdPartySessionOnNonDomainConnectionLogsInAgain(t *testing.T) {
	e := newEnv(t)
	e.grantConsent(t, "partner", "https://api.acme.test", "read:things")
	cookie := e.loginOn(t, "Other-DB", fixedNow()) // a session through a non-domain connection
	loc := location(t, e.get(t, partnerQuery(), cookie))
	if loc.Path != "/u/login" {
		t.Fatalf("Location = %s", loc)
	}
}
```

Helpers for `handlers_test.go`:
- `grantConsent` upserts a `store.UserGrant` for alice.
- `loginOn` is `login` with a connection argument; it needs alice to have an identity on `Other-DB`, so add `{connection: Other-DB, email: alice@acme.test, password: "alice password 1"}` to the fixture users if the seed allows the same email on two connections (it does: uniqueness is per connection). Otherwise start the session with the existing user ID and the `Other-DB` connection name directly through `Sessions.Start`, which does not check identities.

Also update `TestNoSessionStartsLogin` or whichever test asserts `prompt` is removed, to the new rule that only `login` is removed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/authz/`
Expected: FAIL (consent, prompt, strict checks missing).

- [ ] **Step 3: Implement**

`errors.go`: add `func errUserDeclined() *Error { return &Error{"access_denied", "the user did not authorize the request"} }`.

`request.go`:

```go
// strictUnsupported are /authorize parameters that strict third-party
// applications may not send (D-0025). Organization and invitation are
// refused for every client until Organizations exist.
var strictUnsupported = []string{"claims", "id_token_hint", "login_ticket", "request", "request_uri", "screen_hint"}
```

`Request` gains `Present []string // which strictUnsupported parameters the request carried`; `ParseRequest` fills it with `for _, n := range strictUnsupported { if q.Has(n) { r.Present = append(r.Present, n) } }`. `Present` is not part of `Params()`: a request that carries any of these never reaches a transaction for a strict client, and is irrelevant for the others.

`validate.go`, after the PKCE switch:

```go
	if access.Strict(client) {
		if len(req.Present) > 0 {
			return client, errInvalidRequest(req.Present[0] + " is not supported for this application"), true
		}
		if req.CodeChallenge == "" {
			return client, errInvalidRequest("this application must use PKCE (code_challenge)"), true
		}
	}
```

The connection check becomes:

```go
		if errors.Is(err, store.ErrNotFound) || (err == nil && !access.ConnectionUsable(client, conn)) {
```

`handlers.go`:

1. Extract the session-user check in `Authorize` into `ActiveSession` (same logic; returns `nil, nil` for a missing or blocked user).
2. `connectionDisabled` returns `!access.ConnectionUsable(client, conn)`.
3. Replace the final `h.issueCode(...)` in `Authorize` with `h.finish(w, r, res, client, req, sess, false, false)`, and the one in `Resume` with `h.finish(w, r, res, client, req, sess, false, true)`: the login or signup page was just shown, so the confirmation is skipped (D-0027).
4. Route **every** error `Authorize` and `Resume` deliver to the client through `h.deny(w, r, res, client, req, e)`: redirectable validation errors, `login_required`, and the `server_error` responses after the client is known. Under `open_redirect_protection` all of them become error pages (D-0027).
5. `startLogin` keeps every prompt but `login`:

```go
	params := req.Params()
	var kept []string
	for _, p := range req.Prompts() {
		if p != "login" { // satisfied by this login
			kept = append(kept, p)
		}
	}
	if len(kept) > 0 {
		params["prompt"] = strings.Join(kept, " ")
	} else {
		delete(params, "prompt")
	}
```

Then factor the transaction creation out of `startLogin` into `startTxn(w, r, res, client, req Request, params map[string]string, page string)`. `startLogin` calls it with `/u/login` or `/u/signup`; `startConsent` calls it with `req.Params()` and `/u/consent`.

New code:

```go
// deny delivers an authorization error, or shows it on an error page when
// the client's redirection_policy protects it (D-0027).
func (h *Handlers) deny(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, e *Error) {
	if access.ShowErrorPage(client) {
		view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, req.UILocales))
		ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrAccessDenied), e.Description)
		return
	}
	writeResponse(w, r, req, errorParams(e, req.State))
}

// accessInput loads what access.Decide needs for an interactive request.
// audienceKey is the audience a user grant is stored under.
func (h *Handlers) accessInput(ctx context.Context, res tenant.Resolved, client *store.Client, req Request, userID string) (access.Input, string, error) {
	in := access.Input{
		Flow: access.Interactive, Client: client, Scopes: req.Scopes(), Prompts: req.Prompts(),
		RedirectURI: req.RedirectURI, TenantSkipConfirmation: res.Tenant.SkipNonVerifiableCallbackURIConfirmationPrompt,
	}
	audienceKey := res.Issuer() + "userinfo" // O2
	if req.Audience != "" {
		rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, res.Tenant.ID, req.Audience)
		if err != nil {
			return in, "", err
		}
		in.API, audienceKey = rs, rs.Identifier
		g, err := h.Store.ClientGrants().Find(ctx, res.Tenant.ID, client.ClientID, rs.Identifier, store.SubjectTypeUser)
		switch {
		case err == nil:
			in.ClientGrant = g
		case !errors.Is(err, store.ErrNotFound):
			return in, "", err
		}
	}
	ug, err := h.Store.UserGrants().Find(ctx, res.Tenant.ID, client.ClientID, userID, audienceKey)
	switch {
	case err == nil:
		in.UserGrant = ug
	case !errors.Is(err, store.ErrNotFound):
		return in, "", err
	}
	return in, audienceKey, nil
}

// finish runs the access decision for an authenticated request: it issues
// the code, sends the browser to the consent page, or delivers an error.
// accepted means the user just accepted the consent page for this request;
// screenShown means a login or signup page was shown in this transaction.
func (h *Handlers) finish(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession, accepted, screenShown bool) {
	ctx := r.Context()
	in, audienceKey, err := h.accessInput(ctx, res, client, req, sess.UserID)
	if err != nil {
		h.log().ErrorContext(ctx, "load access decision input", "tenant", res.Tenant.ID, "err", err)
		writeResponse(w, r, req, errorParams(errServer(), req.State))
		return
	}
	in.ScreenShown = screenShown || accepted
	d := access.Decide(in)
	switch {
	case d.Err != nil:
		h.deny(w, r, res, client, req, &Error{d.Err.Code, d.Err.Description})
		return
	case (d.Consent || d.Confirmation) && !accepted:
		h.startConsent(w, r, res, client, req)
		return
	case d.Consent: // accepted
		now := h.now()
		existing := []string(nil)
		if in.UserGrant != nil {
			existing = in.UserGrant.Scopes
		}
		if _, err := h.Store.UserGrants().Upsert(ctx, &store.UserGrant{
			TenantID: res.Tenant.ID, ID: "ugr_" + secrets.RandomString(24), ClientID: client.ClientID, UserID: sess.UserID,
			Audience: audienceKey, Scopes: access.GrantScopes(existing, d.Scopes), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			h.log().ErrorContext(ctx, "store user grant", "tenant", res.Tenant.ID, "err", err)
			writeResponse(w, r, req, errorParams(errServer(), req.State))
			return
		}
	}
	h.issueCode(w, r, res, client, req, sess, d.Scopes)
}
```

`issueCode` and `createCode` take `scopes []string` and store them as `AuthCode.Scopes` instead of `req.Scopes()`.

```go
// Consent finishes a consent-page transaction. Declining is access_denied.
func (h *Handlers) Consent(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession, accepted bool) {
	ctx := r.Context()
	if err := h.Store.AuthTransactions().Delete(ctx, res.Tenant.ID, txn.ID); err != nil {
		h.log().WarnContext(ctx, "delete consent transaction", "tenant", res.Tenant.ID, "err", err)
	}
	http.SetCookie(w, &http.Cookie{Name: TxnCookiePrefix + txn.ID, Value: "", Path: "/u", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	req := RequestFromParams(txn.Params)
	client, verr, redirectable := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		if !redirectable {
			view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]))
			ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), verr.Description)
			return
		}
		h.deny(w, r, res, client, req, verr)
		return
	}
	if !accepted {
		h.deny(w, r, res, client, req, errUserDeclined())
		return
	}
	h.finish(w, r, res, client, req, sess, true, true)
}

// ConsentView describes the page for txn. It returns an error when the
// request is no longer valid; the caller shows the generic error page.
func (h *Handlers) ConsentView(ctx context.Context, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (*ConsentView, error) {
	req := RequestFromParams(txn.Params)
	client, verr, _ := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		return nil, errors.New(verr.Description)
	}
	in, _, err := h.accessInput(ctx, res, client, req, sess.UserID)
	if err != nil {
		return nil, err
	}
	d := access.Decide(in)
	if d.Err != nil {
		return nil, errors.New(d.Err.Description)
	}
	v := &ConsentView{Confirmation: !d.Consent, ThirdParty: !client.IsFirstParty, RedirectURI: req.RedirectURI}
	if u, err := url.Parse(req.RedirectURI); err == nil {
		v.CallbackDomain = u.Hostname()
		if v.CallbackDomain == "" {
			v.CallbackDomain = u.Scheme + ":"
		}
	}
	if in.API != nil {
		v.APIName = in.API.Name
		if v.APIName == "" {
			v.APIName = in.API.Identifier
		}
	}
	for _, s := range d.Scopes {
		label := s
		if res.Tenant.UseScopeDescriptionsForConsent && in.API != nil {
			if i := slices.IndexFunc(in.API.Scopes, func(d store.Scope) bool { return d.Value == s }); i >= 0 && in.API.Scopes[i].Description != "" {
				label = in.API.Scopes[i].Description
			}
		}
		v.Scopes = append(v.Scopes, label)
	}
	return v, nil
}
```

In `internal/login/login.go`, `connection()` loads the client and uses `access.ConnectionUsable(client, c)` in place of `slices.Contains(c.EnabledClients, txn.ClientID)`. A missing client yields `errNoConnection`.

Add `KeyErrAccessDenied = "zeroauthy.error.access-denied"` to `internal/i18n/keys.go`, and to `en.json` under `zeroauthy.error`: `"access-denied": "The application was not given access to your account."` (Task 8 adds the remaining keys).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/authz/ ./internal/login/ ./internal/i18n/ ./internal/server/`
Expected: PASS. `internal/server` flow tests using seeded first-party clients with `https` callbacks are unaffected. Any test that uses a localhost callback without the skip flag now reaches `/u/consent`: set the flag in that test's seed rather than changing the assertion.

- [ ] **Step 5: Commit**

```bash
git add internal/authz internal/login/login.go internal/i18n
git commit -m "feat(authz): access policies, strict third-party checks, consent hand-off, redirection policy"
```

---

### Task 8: The consent page

**Files:**
- Create: `internal/ui/templates/consent.html`, `internal/login/consent.go`, `internal/login/consent_test.go`
- Modify: `internal/ui/ui.go`, `internal/ui/ui_test.go`, `internal/i18n/locales/en.json`, `internal/i18n/keys.go`, `internal/login/login.go`, `internal/server/server.go`, `internal/server/flow_test.go`

**Interfaces:**
- Consumes: `authz.Handlers.ConsentView`, `Consent`, `ActiveSession` (Task 7).
- Produces: `GET`/`POST /u/consent`; `ui.RenderConsent`; `ui.ConsentData`.

```go
type ConsentData struct {
	State, CSRF    string
	Confirmation   bool
	ThirdParty     bool
	CallbackDomain string
	APIName        string
	Scopes         []string
	RedirectURI    string // its origin is allowed as form-action
}

func RenderConsent(w http.ResponseWriter, status int, t Tenant, d ConsentData)
```

- [ ] **Step 1: Write the failing tests**

`internal/ui/ui_test.go`:

```go
func TestRenderConsent(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderConsent(rec, http.StatusOK, Tenant{Name: "Acme"}, ConsentData{
		State: "st", CSRF: "tok", ThirdParty: true, CallbackDomain: "partner.example", APIName: "Things API",
		Scopes: []string{"read:things", "<script>"}, RedirectURI: "https://partner.example/cb",
	})
	body := rec.Body.String()
	for _, want := range []string{`name="state" value="st"`, `name="csrf" value="tok"`, `value="accept"`, `value="decline"`,
		"read:things", "&lt;script&gt;", "partner.example", "Things API"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://partner.example") {
		t.Errorf("CSP = %q", csp)
	}
}

func TestRenderConsentConfirmation(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderConsent(rec, http.StatusOK, Tenant{Name: "Acme"}, ConsentData{State: "st", CSRF: "tok", Confirmation: true, CallbackDomain: "localhost"})
	body := rec.Body.String()
	if strings.Contains(body, "<ul") || !strings.Contains(body, "localhost") {
		t.Errorf("confirmation page: %s", body)
	}
}
```

`internal/login/consent_test.go`: build on the login package's existing test env (`login_test.go`), using a seed with a third-party client like Task 7's `partner`. Add:
- `TestConsentAcceptIssuesCodeAndRemembers`: GET `/authorize` (via the authz handler wired in the env) → `/u/consent`; GET the page (200, contains `read:things`); POST `action=accept` with state and CSRF → 302 to `partner.example/cb?code=…`; `UserGrants().Find` returns `[read:things]`. A second `/authorize` goes straight to the callback.
- `TestConsentDeclineProtected`: POST `action=decline` → 400 error page, no `Location`, and no grant stored.
- `TestConsentDeclineAllowAlways`: with `partner-open` → 302 with `error=access_denied` and `state=st`.
- `TestConsentWrongCSRF`: → 400 session-expired page.
- `TestConsentWithoutSessionFails`: drop the session cookie before the POST → 400 session-expired page, no code.
- `TestConsentWrongCookie`: replace the `za_txn_` cookie value → 400.
- `TestNoConfirmationRightAfterLogin`: `local` client, no session: `/authorize` → `/u/login` → POST valid credentials → 302 straight to `http://localhost:5000/cb?code=…`, not to `/u/consent` (D-0027: the login page counts as the transaction's screen).
- `TestConfirmationAcceptStoresNoGrant`: `local` client on localhost → page without a scope list → accept → code; `UserGrants().Find` → `ErrNotFound`.

`internal/server/flow_test.go`: one end-to-end flow through `server.New`: login page → consent → token exchange for the `partner` client. Assert the access token's `scope` is `read:things` and there is no `id_token` (strict drops `openid`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/ui/ ./internal/login/ ./internal/server/`
Expected: FAIL (undefined `RenderConsent`, 404 on `/u/consent`).

- [ ] **Step 3: Implement**

`internal/ui/templates/consent.html` (original markup in the style of `logout_confirm.html`):

```html
{{define "doctitle"}}{{t .Tenant.L "consent.consent.pageTitle"}}{{end}}
{{define "title"}}{{if .Data.Confirmation}}{{t .Tenant.L "zeroauthy.consent.confirmTitle"}}{{else}}{{t .Tenant.L "consent.consent.title"}}{{end}}{{end}}
{{define "content"}}
{{if .Data.Confirmation}}
<p>{{t .Tenant.L "zeroauthy.consent.confirmDescription" "callbackDomain" .Data.CallbackDomain}}</p>
{{else}}
<p>{{t .Tenant.L "zeroauthy.consent.description"}}</p>
{{if .Data.APIName}}<p><strong>{{.Data.APIName}}</strong></p>{{end}}
<ul class="scopes">
{{range .Data.Scopes}}<li>{{.}}</li>
{{end}}</ul>
{{if .Data.ThirdParty}}<p role="note">{{t .Tenant.L "zeroauthy.consent.externalApp" "callbackDomain" .Data.CallbackDomain}}</p>{{end}}
{{end}}
<form method="post" action="/u/consent">
<input type="hidden" name="state" value="{{.Data.State}}">
<input type="hidden" name="csrf" value="{{.Data.CSRF}}">
<button type="submit" name="action" value="accept">{{if .Data.Confirmation}}{{t .Tenant.L "zeroauthy.consent.confirmButtonText"}}{{else}}{{t .Tenant.L "consent.consent.acceptButtonText"}}{{end}}</button>
<button type="submit" name="action" value="decline" class="secondary">{{if .Data.Confirmation}}{{t .Tenant.L "zeroauthy.consent.cancelButtonText"}}{{else}}{{t .Tenant.L "consent.consent.declineButtonText"}}{{end}}</button>
</form>
{{end}}
```

If `layout.html` has no `secondary` button style, add one to its stylesheet: same size as the primary button, transparent background, border in the primary colour.

`ui.go`: register `"consent": parsePage("templates/layout.html", "templates/consent.html")`, and add `ConsentData` and:

```go
// RenderConsent shows the consent or confirmation page of a transaction.
func RenderConsent(w http.ResponseWriter, status int, t Tenant, d ConsentData) {
	render(w, status, "consent", t, d, formActionFor(d.RedirectURI))
}
```

`en.json`. Add a `consent` prompt and keys under `zeroauthy`; all text is original:

```json
  "consent": {
    "consent": {
      "pageTitle": "Authorize application",
      "title": "Allow ${clientName}?",
      "acceptButtonText": "Allow",
      "declineButtonText": "Deny"
    }
  },
```

and inside the existing `zeroauthy` object:

```json
    "consent": {
      "description": "${clientName} is asking for permission to:",
      "externalApp": "${clientName} is not operated by ${companyName}. If you allow it, you will be sent to ${callbackDomain}.",
      "confirmTitle": "Continue to ${clientName}?",
      "confirmDescription": "Continue only if you started this sign-in. You will be sent to ${callbackDomain}.",
      "confirmButtonText": "Continue",
      "cancelButtonText": "Cancel"
    },
```

Before committing, open Auth0's text-elements doc (sources list) and check that the consent screen's keys are named `pageTitle`, `title`, `acceptButtonText` and `declineButtonText`. If a name differs, use Auth0's name in both the template and `en.json`. If a key does not exist there, move it under `zeroauthy.consent` instead. Add the constants to `keys.go` only for keys used from Go (none here; the template uses them directly). Make sure the catalog test's "keys used" scan covers templates; if it only scans `keys.go`, add the new keys to the comment list it checks, following the existing exemption pattern.

`internal/login/login.go`: split `load` into `loadTxn(r, state) (*flow, error)` (everything but the connection) and `load`, which calls `loadTxn` and then sets `f.conn`. Split `postedFlow` into `postedTxn` (form parse, `loadTxn`, CSRF) and `postedFlow`, which calls `postedTxn` and then loads the connection, preserving today's error behaviour.

`internal/login/consent.go`:

```go
package login

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// ConsentPage renders the consent or confirmation screen of a transaction
// started by /authorize after login.
func (h *Handlers) ConsentPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.loadTxn(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	sess, err := h.Authz.ActiveSession(r.Context(), r, f.res)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if sess == nil {
		h.fail(w, r, errTxn, f)
		return
	}
	v, err := h.Authz.ConsentView(r.Context(), f.res, f.txn, sess)
	if err != nil {
		h.log().WarnContext(r.Context(), "consent page", "tenant", f.res.Tenant.ID, "err", err)
		h.fail(w, r, errTxn, f)
		return
	}
	ui.RenderConsent(w, http.StatusOK, f.view, ui.ConsentData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Confirmation: v.Confirmation, ThirdParty: v.ThirdParty,
		CallbackDomain: v.CallbackDomain, APIName: v.APIName, Scopes: v.Scopes, RedirectURI: v.RedirectURI,
	})
}

func (h *Handlers) ConsentSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedTxn(w, r)
	if !ok {
		return
	}
	sess, err := h.Authz.ActiveSession(r.Context(), r, f.res)
	switch {
	case err != nil:
		h.fail(w, r, err, f)
		return
	case sess == nil:
		h.fail(w, r, errTxn, f)
		return
	}
	switch r.PostForm.Get("action") {
	case "accept":
		h.Authz.Consent(w, r, f.res, f.txn, sess, true)
	case "decline":
		h.Authz.Consent(w, r, f.res, f.txn, sess, false)
	default:
		h.fail(w, r, errors.New("login: consent form without an action"), f)
	}
}
```

The page needs `{{t … "clientName"}}`: `loadTxn` already sets `clientName` on the localizer. It also needs `companyName`; check `ui.TenantView`/`i18n` set it the way the login page does.

`internal/server/server.go`, next to the other `/u` routes:

```go
		tr.Get("/u/consent", lg.ConsentPage)
		tr.Post("/u/consent", lg.ConsentSubmit)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/ui/ ./internal/login/ ./internal/i18n/ ./internal/server/ ./internal/authz/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui internal/login internal/i18n internal/server
git commit -m "feat(login): consent and confirmation page"
```

---

### Task 9: The token endpoint

**Files:**
- Create: `internal/oauth/access.go`
- Modify: `internal/oauth/{grant_password,grant_refresh_token,grant_client_credentials}.go`, `internal/oauth/fixture_test.go`, `grant_password_test.go`, `grant_refresh_token_test.go`, `token_test.go`

**Interfaces:**
- Consumes: `access.Decide`, `access.SubjectType`.
- Produces: no new exported API.

- [ ] **Step 1: Write the failing tests**

Extend the oauth fixture seed with:
- a third-party permissive `regular_web` client `partner` with grant types `[authorization_code, refresh_token]` and a secret;
- an API `https://locked.test` with user policy `deny_all` and client policy `deny_all`;
- an API `https://granted.test` with `subject_type_authorization: {user: {policy: require_client_grant}}`, scopes `a` and `b`, and a user grant for the first-party password client limited to `[a]`;
- a client-credentials grant from the M2M client to `https://locked.test`.

Tests:

```go
func TestPasswordGrantDenyAll(t *testing.T) {
	e := newEnv(t)
	rec := e.token(t, passwordForm("https://locked.test"))
	assertOAuthError(t, rec, http.StatusBadRequest, "invalid_request") // O7
}

func TestPasswordGrantClientGrantCapsScopes(t *testing.T) {
	e := newEnv(t)
	f := passwordForm("https://granted.test")
	f.Set("scope", "a b")
	rec := e.token(t, f)
	if got := tokenScope(t, rec); got != "a" {
		t.Fatalf("scope = %q, want a", got)
	}
}

func TestPasswordGrantRequireClientGrantWithoutGrant(t *testing.T) {
	e := newEnv(t)
	f := passwordFormFor("other-password-client", "https://granted.test") // a first-party client with no user grant
	assertOAuthError(t, e.token(t, f), http.StatusBadRequest, "invalid_request")
}

func TestRefreshGrantRechecksPolicy(t *testing.T) {
	e := newEnv(t)
	rt := e.issueRefreshToken(t, "https://granted.test", "a offline_access") // via the password grant
	e.setUserPolicy(t, "https://granted.test", store.PolicyDenyAll)
	assertOAuthError(t, e.token(t, refreshForm(rt)), http.StatusBadRequest, "invalid_request")
}

func TestClientCredentialsDenyAll(t *testing.T) {
	e := newEnv(t)
	assertOAuthError(t, e.token(t, clientCredentialsForm("https://locked.test")), http.StatusForbidden, "access_denied")
}
```

Use the existing fixture helpers where they exist (the names above are illustrative: match `grant_password_test.go`'s helpers). `setUserPolicy` loads the resource server, sets `SubjectTypeAuthorization.User` and calls `Update`. `other-password-client` is a second first-party client with the password grant enabled. The password grant for a third-party client cannot be seeded (the seed refuses it), so test `access.Decide`'s rule for it through the seed error in Task 5 and the access table in Task 6. Additionally, add a test that updates a first-party password client to third-party in the store after seeding and expects `403 unauthorized_client` *before* the password is checked: its log must show no `login failed` line, and the user throttle must not be charged.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/oauth/`
Expected: FAIL.

- [ ] **Step 3: Implement**

`internal/oauth/access.go`:

```go
package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// decide runs the access decision for a token-endpoint flow. rs is nil when
// there is no audience.
func (h *Handlers) decide(ctx context.Context, tenantID string, flow access.Flow, c *store.Client, rs *store.ResourceServer, scopes []string) (access.Decision, *Error) {
	in := access.Input{Flow: flow, Client: c, API: rs, Scopes: scopes}
	if rs != nil {
		g, err := h.Store.ClientGrants().Find(ctx, tenantID, c.ClientID, rs.Identifier, access.SubjectType(flow))
		switch {
		case err == nil:
			in.ClientGrant = g
		case !errors.Is(err, store.ErrNotFound):
			h.log().ErrorContext(ctx, "load client grant", "tenant", tenantID, "client_id", c.ClientID, "err", err)
			return access.Decision{}, serverError()
		}
	}
	d := access.Decide(in)
	if d.Err != nil {
		status := http.StatusForbidden // unauthorized_client, access_denied
		if d.Err.Code == "invalid_request" {
			status = http.StatusBadRequest // a refused user flow (observed, D-0025)
		}
		return d, &Error{Status: status, Code: d.Err.Code, Description: d.Err.Description}
	}
	return d, nil
}
```

- **Password grant (`grant_password.go`):** at the very start of the grant, after client authentication and before any lookup or throttle, add:

```go
	if !c.IsFirstParty {
		return nil, unauthorizedClient("the password grant is not available to third-party applications")
	}
```

  After `rs, lifetime, oerr := h.audienceFor(...)`:

```go
	d, oerr := h.decide(ctx, tenantID, access.Password, c, rs, userScopes(strings.Fields(form.Get("scope")), rs, offlineAllowed(c, rs)))
	if oerr != nil {
		return nil, oerr
	}
	scopes := d.Scopes
```

  and remove the old `scopes :=` line.
- **Refresh grant (`grant_refresh_token.go`):** after the scopes are settled (narrowing included), run `d, oerr := h.decide(ctx, tenantID, access.Refresh, c, rs, scopes)` and then `scopes = d.Scopes`.
- **Client credentials (`grant_client_credentials.go`):** replace the grant lookup with a `Find(..., store.SubjectTypeClient)` that keeps `grant` and maps `ErrNotFound` to nil; call `access.Decide(access.Input{Flow: access.ClientCredentials, Client: c, API: rs, ClientGrant: grant})`; on `Err`, return `accessDenied(d.Err.Description)`; then `resolveScopes(form.Get("scope"), grant.Scopes, rs.Scopes)` as today. The existing "client is not authorized for this audience" tests keep passing because `checkPolicy` uses that exact description.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/oauth/ ./internal/server/ ./internal/dbconn/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth
git commit -m "feat(oauth): access policies and third-party limits on the token endpoint"
```

---

### Task 10: E2E with Auth0's SDKs (m10)

Clients are chosen from Auth0's most-starred repositories (maintainer request, 2026-10-16):
- express-openid-connect (519★): a third-party permissive web app that goes through consent.
- auth0-spa-js (1015★): the confirmation prompt, and silent authentication refused afterwards.
- express-jwt (4.5k★, on node-jsonwebtoken) with node-jwks-rsa (876★): validates the strict client's token.
- node-auth0 (682★): the password grant on an API that denies user flows.

**Files:**
- Modify: `tests/e2e/package.json` (+ `package-lock.json`), `tests/e2e/seed.yaml`, `tests/e2e/spa/app.js`, `tests/e2e/spa-server.mjs`, `tests/e2e/m3-db-flows.mjs` (or the node-auth0 m3 script that runs password grants)
- Create: `tests/e2e/m10-consent.spec.mjs`, `docs/compat/blackbox-clients.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Add the pinned packages**

Run (in `tests/e2e`): `npm install --save-exact express-openid-connect@3.4.0 express-jwt@8.5.1 jwks-rsa@4.1.0`
Expected: `package.json` and `package-lock.json` updated; nothing else changes.

- [ ] **Step 2: Extend the E2E seed**

In `tests/e2e/seed.yaml`:
- **Tenant:** add `skip_non_verifiable_callback_uri_confirmation_prompt: true`. Every existing E2E app uses a localhost callback; the default prompt would change their flows. Individual clients below opt back in.
- **Connection:** set `is_domain_connection: true` on `Username-Password-Authentication`.
- **API:** add `https://locked.e2e.local` with `subject_type_authorization: {user: {policy: deny_all}}`. Task 5 already added `skip_consent_for_verifiable_first_party_clients: true` to `https://api.e2e.local`; keep it.
- **Clients:**

```yaml
      - client_id: e2e-3p-web
        name: E2E Partner Web
        app_type: regular_web
        is_first_party: false
        third_party_security_mode: permissive
        client_secret: e2e-3p-web-secret-not-for-production
        token_endpoint_auth_method: client_secret_basic # express-openid-connect's default
        grant_types: [authorization_code]
        callbacks: ["http://localhost:3001/callback"]
        allowed_logout_urls: ["http://localhost:3001"]
      - client_id: e2e-3p-strict
        name: E2E Partner Strict
        app_type: spa
        is_first_party: false
        grant_types: [authorization_code]
        callbacks: ["https://localhost:3443/strict/"]
        web_origins: ["https://localhost:3443"]
        allowed_origins: ["https://localhost:3443"]
      - client_id: e2e-confirm
        name: E2E Confirm
        app_type: spa
        grant_types: [authorization_code]
        skip_non_verifiable_callback_uri_confirmation_prompt: false
        callbacks: ["https://localhost:3443/confirm/"]
        web_origins: ["https://localhost:3443"]
        allowed_origins: ["https://localhost:3443"]
```

- **Grants and connections:** add the client grant `{client_id: e2e-3p-strict, audience: https://api.e2e.local, subject_type: user, scopes: ["read:things"]}`, and add `e2e-confirm` to `Username-Password-Authentication.enabled_clients`.

- [ ] **Step 3: Serve the extra SPA paths**

`tests/e2e/spa-server.mjs`: add routes `'/confirm/'` and `'/strict/'` → `['spa/index.html', 'text/html; charset=utf-8']`.

`tests/e2e/spa/app.js`: pick the client from the path. `/strict/` only displays the page; the spec drives that flow by hand.

```js
(async () => {
  const base = ['/confirm/', '/strict/'].find((p) => window.location.pathname.startsWith(p)) || '/';
  if (base === '/strict/') {
    document.body.dataset.ready = 'true';
    return;
  }
  const started = performance.now();
  const client = await auth0.createAuth0Client({
    domain: 'localhost:8443',
    clientId: base === '/confirm/' ? 'e2e-confirm' : 'e2e-spa',
    authorizationParams: {
      redirect_uri: window.location.origin + base,
      audience: 'https://api.e2e.local',
      scope: 'openid profile email read:things',
    },
  });
  const initMs = performance.now() - started;
  const params = new URLSearchParams(window.location.search);
  if (params.has('code') && params.has('state')) {
    await client.handleRedirectCallback();
    window.history.replaceState({}, '', base);
  }
  window.__za = { client, initMs };
  document.getElementById('login').onclick = () => client.loginWithRedirect();
  document.body.dataset.ready = 'true';
})().catch((err) => {
  document.getElementById('out').textContent = String((err && (err.error_description || err.error || err.message)) || err);
  document.body.dataset.ready = 'error';
});
```

- [ ] **Step 4: Write the spec**

`tests/e2e/m10-consent.spec.mjs`:

```js
// Black-box test (CLEAN_ROOM.md): Auth0's SDKs against zeroauthy's consent,
// third-party and confirmation flows. Clients come from Auth0's most-starred
// repositories: express-openid-connect, auth0-spa-js, express-jwt with
// jwks-rsa (on node-jsonwebtoken).
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import express from 'express';
import { auth as oidc, requiresAuth } from 'express-openid-connect';
import { expressjwt } from 'express-jwt';
import jwksRsa from 'jwks-rsa';

const IDP = 'https://localhost:8443';

async function login(page) {
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
}

test('express-openid-connect: a third-party web app gets consent once', async ({ page }) => {
  const app = express();
  app.use(oidc({
    issuerBaseURL: IDP, baseURL: 'http://localhost:3001', clientID: 'e2e-3p-web',
    clientSecret: 'e2e-3p-web-secret-not-for-production', secret: randomBytes(32).toString('hex'),
    authRequired: false, authorizationParams: { response_type: 'code', scope: 'openid profile email' },
  }));
  app.get('/me', requiresAuth(), (req, res) => res.json(req.oidc.user));
  const server = app.listen(3001, '127.0.0.1');
  await once(server, 'listening');
  try {
    await page.goto('http://localhost:3001/me');
    await login(page);
    await page.waitForURL(/localhost:8443\/u\/consent/);
    await expect(page.locator('[role=note]')).toContainText('localhost'); // external-app notice names the callback domain
    await page.click('button[value=accept]');
    await page.waitForURL('http://localhost:3001/me');
    expect(JSON.parse(await page.locator('body').innerText()).email).toBe('alice@e2e.local');

    // express-openid-connect's /logout ends only the app session when the
    // issuer is not an Auth0 domain (idpLogout is off), so the zeroauthy
    // session survives. The next login must not show consent again.
    await page.goto('http://localhost:3001/logout');
    const seen = [];
    page.on('framenavigated', (f) => { if (f === page.mainFrame()) seen.push(f.url()); });
    await page.goto('http://localhost:3001/me');
    await page.waitForURL('http://localhost:3001/me');
    expect(seen.filter((u) => u.includes('/u/'))).toEqual([]);
  } finally {
    server.close();
  }
});

test('strict third-party: consent, decline page, and a token express-jwt accepts', async ({ page }) => {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const authorize = (extra = {}) => `${IDP}/authorize?` + new URLSearchParams({
    client_id: 'e2e-3p-strict', redirect_uri: 'https://localhost:3443/strict/', response_type: 'code',
    audience: 'https://api.e2e.local', scope: 'openid read:things', state: 's1',
    code_challenge: challenge, code_challenge_method: 'S256', ...extra,
  });

  // Decline: open_redirect_protection shows an error page and never redirects.
  await page.goto(authorize());
  await login(page);
  await page.waitForURL(/\/u\/consent/);
  await page.click('button[value=decline]');
  await expect(page).toHaveURL(/localhost:8443\/u\/consent/);
  await expect(page.locator('main')).toBeVisible();

  // Accept.
  await page.goto(authorize());
  await page.waitForURL(/\/u\/consent/);
  await page.click('button[value=accept]');
  await page.waitForURL(/localhost:3443\/strict\/\?code=/);
  const code = new URL(page.url()).searchParams.get('code');
  const r = await fetch(`${IDP}/oauth/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'e2e-3p-strict', code,
      code_verifier: verifier, redirect_uri: 'https://localhost:3443/strict/' }),
  });
  expect(r.status).toBe(200);
  const tok = await r.json();
  expect(tok.id_token).toBeUndefined(); // strict: no OIDC
  expect(tok.scope).toBe('read:things');

  const api = express();
  api.get('/me', expressjwt({
    secret: jwksRsa.expressJwtSecret({ jwksUri: `${IDP}/.well-known/jwks.json`, cache: true }),
    audience: 'https://api.e2e.local', issuer: `${IDP}/`, algorithms: ['RS256'],
  }), (req, res) => res.json(req.auth));
  const server = api.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const me = await fetch(`http://127.0.0.1:${server.address().port}/me`, { headers: { authorization: `Bearer ${tok.access_token}` } });
    expect(me.status).toBe(200);
    expect((await me.json()).azp).toBe('e2e-3p-strict');
  } finally {
    server.close();
  }

  // The grant is remembered: prompt=none now succeeds.
  await page.goto(authorize({ prompt: 'none', state: 's2' }));
  await page.waitForURL(/localhost:3443\/strict\/\?code=.*state=s2/);
});

test('auth0-spa-js: a localhost callback needs confirmation on session reuse', async ({ page }) => {
  await page.goto('https://localhost:3443/confirm/');
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true', { timeout: 20_000 });

  // A fresh login shows the login page, so no confirmation follows (D-0027).
  await page.click('#login');
  await login(page);
  await page.waitForURL('https://localhost:3443/confirm/');
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);

  // Silent authentication cannot show the confirmation: consent_required (O5).
  await page.reload();
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(false);
  const err = await page.evaluate(() => window.__za.client.getTokenSilently().then(() => null, (e) => e.error));
  expect(err).toBe('consent_required');

  // An interactive login that reuses the session shows the confirmation.
  await page.click('#login');
  await page.waitForURL(/\/u\/consent/);
  await expect(page.locator('ul.scopes')).toHaveCount(0); // confirmation, not consent
  await page.click('button[value=accept]');
  await page.waitForURL('https://localhost:3443/confirm/');
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
  expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
});
```

If the pinned express-openid-connect turns out to call `/v2/logout` (ending the zeroauthy session), the second visit will pass through `/u/login`. In that case, log in there and change the assertion to "no URL contains `/u/consent`". The point of the check is that consent is not shown twice.

The node-auth0 check goes in the existing node-auth0 m3 script (`m3-db-flows.mjs` or the one that calls `oauth.passwordGrant`). Add one call with `audience: 'https://locked.e2e.local'` and assert a 400 with `error === 'invalid_request'` (O7).

- [ ] **Step 5: Run the E2E suites**

Run: `./tests/e2e/run-m3.sh && ./tests/e2e/run-browser.sh`
Expected: all specs pass, the existing m4–m9 included (the tenant-level skip keeps them unchanged). If Playwright cannot start on the host, use `E2E_IN_CONTAINER=1 ./tests/e2e/run-browser.sh`.

- [ ] **Step 6: Record client coverage**

Create `docs/compat/blackbox-clients.md`:

```markdown
# Black-box clients

zeroauthy is tested with Auth0's own open-source SDKs and libraries, chosen in
order of GitHub stars (github.com/orgs/auth0/repositories?q=sort:stars), as
the maintainer asked on 2026-10-16. Versions are pinned in tests/e2e/package.json.

| Repository | Stars (2026-10-16) | Used in | Surfaces |
|---|---|---|---|
| node-jsonwebtoken | 18k | m10 (through express-jwt) | access token verification |
| express-jwt | 4.5k | m10 | access token verification with JWKS |
| nextjs-auth0 | 2.3k | m5 | login, session, refresh, logout |
| auth0-spa-js | 1.0k | m4, m6, m10 | PKCE login, silent auth, confirmation |
| auth0-react | 991 | m5 | refresh rotation, logout |
| node-jwks-rsa | 876 | m10 | JWKS |
| node-auth0 | 682 | m3, m6, m9, m10 | password grants, dbconnections, access policy |
| express-openid-connect | 519 | m10 | third-party consent (web app) |
| express-oauth2-jwt-bearer | — | m3, m4 | access token verification |
| auth0-auth-js | — | m6, m9 | password grant, dbconnections |

## Not yet used (in star order), with the milestone that should pick them up

| Repository | Stars | Planned for |
|---|---|---|
| java-jwt | 6.2k | OIDF/JWT interop job (milestone 11) |
| jwt-decode | 3.4k | milestone 11 (decode ID tokens in a browser test) |
| angular2-jwt / auth0-angular | 2.6k / 201 | milestone 11 (Angular SPA) |
| go-jwt-middleware | 1.2k | milestone 11 (Go resource server) |
| lock / auth0.js | 1.1k / 1.1k | not planned: embedded/classic login (deprecated by Auth0 in favour of Universal Login); revisit if requested |
| auth0-python | 578 | milestone 11 (Authentication API client) |
| react-native-auth0, Auth0.swift, Auth0.Android | 551 / 465 / 301 | device flow plan (Plan 11) or later: native redirect handling |
| auth0-PHP, auth0.net, auth0-java, ruby-auth0, laravel-auth0 | 410 … 205 | milestone 11 (one per language as an Authentication API client) |
| auth0-cli, auth0-deploy-cli, terraform-provider-auth0, go-auth0 | 343 / 282 / 222 / 197 | sub-project 3 (Management API) |
| passport-auth0 | 305 | milestone 11 |
```

- [ ] **Step 7: Commit**

```bash
git add tests/e2e docs/compat/blackbox-clients.md
git commit -m "test(e2e): consent, third-party and confirmation with express-openid-connect, auth0-spa-js, express-jwt and node-auth0"
```

---

### Task 11: Documentation and final verification

**Files:**
- Create: `docs/consent.md`
- Modify: `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md`, `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md` (§6.2 consent line, §13 milestone 10 note), `docs/compat/changelog-review.md` (mark the 2025-10-28 backlog row `done`), `docs/compat/decisions.md` (a D-0021 addendum: plugins must be rebuilt to serve `UserGrants`; older plugins fail consent with a server error)

- [ ] **Step 1: Write the operator guide**

`docs/consent.md`, in the style of `docs/custom-db.md`. Sections:
1. **First- and third-party applications:** `is_first_party`; the two modes and what strict refuses; `redirection_policy`.
2. **API access policies:** `subject_type_authorization`; client grants with `subject_type`; how scopes are capped.
3. **Consent:** when it is shown, user grants, `prompt=consent`, `use_scope_descriptions_for_consent`, customizing the text (the `consent` prompt keys and the `zeroauthy.consent.*` keys).
4. **The confirmation prompt:** non-verifiable callbacks; the tenant and client settings; why silent authentication fails for them; local development advice (set the client flag on development clients only).
5. **Domain connections.**
6. **Errors:** a table of `/authorize` and `/oauth/token` error codes, from D-0025–D-0027.
7. **Example seed:** the YAML block from Task 5's Interfaces.

Every statement must match the code; quote the observed values, not the defaults, if Task 1 changed any.

- [ ] **Step 2: Update the matrix, backlog and spec**

- **`docs/compat/matrix.md`:** add rows for:
  - consent and user grants (verified with express-openid-connect 3.4.0 and Chromium in m10);
  - third-party strict and permissive (strict verified by raw HTTP plus express-jwt 8.5.1 and jwks-rsa 4.1.0; permissive by express-openid-connect);
  - API access policies (node-auth0 password grant on `deny_all`; the rest by server tests);
  - the confirmation prompt (auth0-spa-js 2.28.3);
  - `redirection_policy` (decline page in m10; `allow_always` by server tests);
  - domain connections (server tests).
  Note the D-0025–D-0027 decisions.
- **`docs/superpowers/plan-1-followups.md`:** add "Plan 9 follow-ups" with the Out of Scope list of this plan, plus any review findings deferred during execution.
- **Core spec §6.2:** replace the consent line with: "**Consent:** see `docs/superpowers/specs/2026-10-16-zeroauthy-consent-design.md` (Plan 9): first- and third-party applications, API access policies, user grants and the confirmation prompt for non-verifiable callbacks."
- **Changelog review:** set the 2025-10-28 backlog row's status to `done (Plan 9)`.

- [ ] **Step 3: Full verification**

Run each and read the output:
- `gofmt -l . | grep -v '^internal/gen/' ; go vet ./... && go test -race ./...` → no gofmt output, PASS.
- `./scripts/test-sql.sh` → PASS on PostgreSQL and MySQL.
- `go generate ./... && git status --porcelain` → no changes.
- `CGO_ENABLED=0 go build ./... && make build` → success.
- `./scripts/check-sources.sh api/authentication.yaml` → PASS.
- `./tests/e2e/run-m3.sh && ./tests/e2e/run-browser.sh` → PASS.

- [ ] **Step 4: Commit**

```bash
git add docs
git commit -m "docs: consent guide, matrix, follow-ups and spec for Plan 9"
```
