# zeroauthy Plan 10: Pushed Authorization Requests (Milestone 10, part 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A confidential client pushes its authorization parameters to `POST /oauth/par`, receives a one-time `request_uri` valid for 30 seconds, and starts the browser at `/authorize?client_id=…&request_uri=…`. A tenant can allow PAR, and a client can require it, as on Auth0.

**Architecture:**
- **Storage:** a new `PushedAuthRequests` repository (`Create`, atomic `Consume`, `Get`, `DeleteExpired`), modelled on `AuthCodes`. New fields `Tenant.PushedAuthorizationRequestsSupported` and `Client.RequirePushedAuthorizationRequests`. Every driver: memory, SQL migration 0004, gRPC plugins.
- **`internal/authz`** owns the PAR constants and the request model. `validate` becomes the exported `ValidateRequest`, shared by `/authorize` and `/oauth/par`. `Request` gains `Ext` (`ext-*` parameters) and `Pushed`. `/authorize` resolves `request_uri` before validation.
- **`internal/oauth`** gets `POST /oauth/par` (`par.go`), which reuses the token endpoint's client authentication and `authz.ValidateRequest`.
- **Discovery** advertises `pushed_authorization_request_endpoint` when the tenant allows PAR.
- **Values the docs leave open** (P1–P9) are settled by Task 1 on the maintainer's trial tenant before any code is written.

**Tech Stack:** Go 1.26+, no new Go dependencies. E2E uses already-pinned packages: `express-openid-connect@3.4.0`, `@auth0/nextjs-auth0@4.32.0`, `@auth0/auth0-auth-js@1.16.1`, Playwright 1.64.

**Spec:** `docs/superpowers/specs/2026-10-16-zeroauthy-par-design.md` (approved 2026-10-16). Also core spec §6.1, §6.2 and §13.

**Auth0 sources** (public docs; read them, never copy them):
- https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-par
- https://auth0.com/docs/get-started/applications/configure-par
- RFC 9126 (OAuth 2.0 Pushed Authorization Requests), RFC 6749 §2.3 and §5.2, RFC 8414 §2

## Global Constraints

- **Earlier constraints still apply:**
  - Drivers return copies; every atomic operation is one store method.
  - `go test -race ./...`, `go vet ./...` and `gofmt -l .` stay clean; `go generate ./...` produces no diff.
  - `CGO_ENABLED=0 go build ./...` works.
  - SQL tests: `./scripts/test-sql.sh <pkgs>` (podman; `ZA_TEST_POSTGRES_DSN` / `ZA_TEST_MYSQL_DSN`). Never install databases on the host.
- **Wire names are Auth0's:** client field `require_pushed_authorization_requests`; tenant field per P7 (working name `pushed_authorization_requests_supported`); discovery field `pushed_authorization_request_endpoint`; request URI prefix `urn:ietf:params:oauth:request_uri:`.
- **Fixed values (documented):** lifetime 30 seconds, not configurable; body at most 10 KB (10240 bytes); form-encoded only; at most 10 `ext-*` parameters; response `201` with `request_uri` and `expires_in`; `Cache-Control: no-store`.
- **Scope A only:** client-secret authentication (`client_secret_basic`, `client_secret_post`). No `private_key_jwt`, mTLS, JAR (`request`), RAR (`authorization_details`).
- **Secrets at rest:** the opaque part of the `request_uri` (64 characters from `secrets.RandomString`) is stored only as `secrets.HashToken`.
- **Defaults are safe for old data:** both new booleans default to `false` in SQL and decode as `false` from plugins that predate the proto fields.
- **Clean room:** Task 1 records facts only (status codes, `error` values, redirect parameter names, screen types, JSON property names). No messages, screenshots, tenant domains, IDs or secrets. Follow `CLEAN_ROOM.md` "Behavior testing against the maintainer's own tenant". The trial tenant belongs to the maintainer.

## Observation-dependent values

Task 1 ran on 2026-10-16 (`docs/compat/observations/par.md`, D-0028–D-0030). **The code blocks in Tasks 5–8 already use the observed values and rulings**; the table records where they came from. Also observed: the `request_uri` opaque part is 64 characters (applied); Auth0 sends `iss` on authorization responses (RFC 9207; a follow-up).

Originally: Task 1 fills the **Observed** column. Tasks 2–9 are written against the **Default** column. If Task 1 observes something different, the implementer of each later task uses the observed value: the place to change is named in the **Where** column, and the matching test changes with it.

| # | Question | Default (used by the code blocks below) | Where | Observed |
|---|---|---|---|---|
| P1 | `/authorize` with `request_uri` plus other query parameters (`state`, `redirect_uri`, `scope`, an unknown one) | Only pushed parameters count; query parameters other than `client_id` and `request_uri` are ignored | `resolvePushed` (Task 6) | ignored (state, redirect_uri, response_type, scope, unknown) |
| P2a | `/oauth/par` with an unregistered `redirect_uri` | `400 invalid_request` | `par` (Task 7) | `400 invalid_request` |
| P2b | `/oauth/par` with `response_type=token` | `400 unsupported_response_type` | `ValidateRequest` codes (Task 7 maps them) | **`403 unauthorized_client` (no implicit grant); `bogus` → `501 unsupported_response_type`. Ruling: keep the code, use per-code statuses (D-0028) → change: `parStatus` in Task 7** |
| P2c | `/oauth/par` with 11 `ext-*` parameters | `400 invalid_request` | `par` (Task 7) | `400 invalid_request`; 10 → 201 |
| P2d | `/oauth/par` with a body over 10 KB | `400 invalid_request` | `parsePARRequest` (Task 7) | **`413 payload_too_large` → change (applied in Task 7)** |
| P2e | `/oauth/par` with a JSON body | `400 invalid_request` | `parsePARRequest` (Task 7) | `400 invalid_request` |
| P3a | `/oauth/par` with a wrong secret | `401 invalid_client` | unchanged `authenticateClient` | `401 invalid_client` |
| P3b | `/oauth/par` from a public (SPA) client | `400 unauthorized_client` | `par` (Task 7) | **`400 invalid_request` → change (applied in Task 7)** |
| P4a | A `request_uri` used a second time | Error page (HTTP 400), no redirect | `resolvePushed` (Task 6) | error page |
| P4b | A `request_uri` after 30 s | Error page, no redirect | `resolvePushed` (Task 6) | error page |
| P4c | A `request_uri` sent with another client's `client_id` | Error page, no redirect | `resolvePushed` (Task 6) | error page; the attempt uses the request up (matches consume-then-compare) |
| P5 | Client requires PAR, plain `/authorize` | Redirect `error=invalid_request` (subject to `redirection_policy`) | `ValidateRequest` (Task 6) | redirect `invalid_request` + `state`; also with the tenant setting off |
| P6a | `request_uri` inside the PAR body | `400 invalid_request` | `par` (Task 7) | `400 invalid_request` |
| P6b | Tenant setting off: `/oauth/par`; `/authorize` with a `request_uri` | `/oauth/par`: `400 invalid_request`; `/authorize`: error page | `par` (Task 7), `resolvePushed` (Task 6) | `400 invalid_request`; error page |
| P7 | Management API property of the tenant setting | `pushed_authorization_requests_supported` (top level of tenant settings) | yaml tag (Task 5), SQL column (Task 3), proto field (Task 4), docs | `pushed_authorization_requests_supported`, top level |
| P8 | Discovery before and after enabling | `pushed_authorization_request_endpoint` only when enabled; no other PAR fields | `Discovery` (Task 7) | endpoint only when on; **`request_uri_parameter_supported: false` in both states → change (applied in Task 7)** |
| P9 | Strict third-party client calls `/oauth/par` | `400 invalid_request` | `par` (Task 7); seed rule (Task 5) | **`400 invalid_request`; the refusal covers third-party clients generally → change: refuse every third-party client (applied in Tasks 5 and 7)** |

## Review Focus

1. **SDKs send more than `client_id` and `request_uri` to `/authorize` after PAR.** openid-client (inside express-openid-connect) and oauth4webapi build the URL themselves, and some versions add `redirect_uri`, `scope` or `response_type`. Those extras must neither fail the request nor override the pushed values (P1). Pinned in Task 6 (`TestPushedExtrasAreIgnored`) and end to end in Task 8.
2. **A login or consent page between `/authorize` and the code.** `Resume`, `Consent` and `ConsentView` rebuild the request from `AuthTransaction.Params` and validate it again. A client that requires PAR must not be refused there because the rebuilt request lost its "pushed" mark. Pinned in Task 6 (`TestRequiredPARSurvivesLogin`).
3. **An old storage plugin without the `PushedAuthRequests` RPCs.** The sweeper calls `DeleteExpired` every 10 minutes on every deployment, PAR or not. It must not log an error forever, and must not fail the other sweeps. Pinned in Task 4 (`TestOldPluginPushedAuthRequestsSweep`).
4. **Two browsers racing for the same `request_uri`** (a replayed link, a double click). Exactly one gets a login page; the other gets the error page. Pinned in storetest `ConcurrentConsume` (Task 2) and Task 6 (`TestPushedReuseFails`).
5. **`ext-*` parameters through the hosted login round trip.** A pushed `ext-foo` must survive `startLogin` → `/u/login` → `Resume` in the transaction, without being treated as a known parameter or dropping the `za_*` keys. Pinned in Task 6 (`TestExtParamsRoundTrip`).

---

## Out of Scope

Task 9 adds these to `docs/superpowers/plan-1-followups.md` under "Plan 10 follow-ups":
- `private_key_jwt` client authentication, with the 2025-10-10 changelog item (issuer string as the assertion `aud`).
- JAR: signed `request` objects at `/authorize` and in PAR; the client's `signed_request_object` settings.
- RAR: `authorization_details` and the resource server's `authorization_details` types.
- mTLS client authentication and `mtls_endpoint_aliases`.
- PAR for public clients (Auth0 does not support it today).
- Actions access to `ext-*` parameters (sub-project 2).
- A general Authentication API rate limiter covering `/oauth/par` (zeroauthy has per-identity throttles only).
- The `iss` authorization response parameter (RFC 9207), which Auth0 sends (tenant setting `authorization_response_iss_parameter_supported`; observations/par.md).
- Repeated query parameters on `/authorize` get a JSON 400 from the generated wrapper (existing item; it also applies to `request_uri`).

## File Structure

| File | Responsibility |
|---|---|
| `docs/compat/observations/par.md` (new) | Task 1 facts |
| `docs/compat/decisions.md` | D-0028 `/oauth/par` behaviour; D-0029 `request_uri` at `/authorize` and required PAR; D-0030 settings and discovery |
| `internal/store/types.go`, `store.go` | `PushedAuthRequest`, `PushedAuthRequests`, two new fields |
| `pkg/store/store.go` | Public aliases |
| `internal/store/memory/pushed_auth_requests.go` (new), `memory.go`, `tx.go`, `clone.go` | Memory driver |
| `pkg/storetest/pushed_auth_requests.go` (new), `storetest.go`, `sweep.go`, `tenants.go`, `clients.go` | Conformance |
| `internal/app/sweeper.go`, `sweeper_test.go` | Expiry sweep |
| `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0004_par.sql` (new), `pushed_auth_requests.go` (new), `tenants.go`, `clients.go`, `migrate_test.go` | SQL driver |
| `proto/store/v1/store.proto` (+ generated), `internal/store/grpcstore/{codec,client_repos,server_repos,client}.go`, tests | Plugin protocol |
| `internal/seed/{seed,validate,apply}.go`, `seed_test.go` | Seed |
| `internal/authz/{par.go (new),request.go,validate.go,handlers.go}`, tests | Request model, validation, `request_uri` resolution |
| `internal/oauth/par.go` (new), `par_test.go` (new) | `POST /oauth/par` |
| `internal/oidc/handlers.go`, test | Discovery |
| `api/authentication.yaml`, `internal/gen/authapi/*` (generated), `internal/server/server.go` | Contract and routing |
| `tests/e2e/{seed.yaml,m10-par.spec.mjs (new),run-browser.sh,next-app/lib/auth0.js}` | E2E |
| `docs/par.md` (new), `docs/compat/{matrix,blackbox-clients,changelog-review}.md`, `docs/superpowers/plan-1-followups.md`, core spec | Docs |

---

### Task 1: Observe the open points on the maintainer's trial tenant

This task needs the maintainer. Claude runs Management API calls with auth0-cli and back-channel calls with curl. The maintainer opens the browser URLs and reports only the final address-bar URL reduced to parameter names (plus the values of `error` and `state`), or which kind of screen appeared. No code changes in this task.

**Files:**
- Create: `docs/compat/observations/par.md`
- Modify: `docs/compat/decisions.md` (append D-0028, D-0029, D-0030)
- Modify: this plan's "Observation-dependent values" table (fill the Observed column)

**Interfaces:**
- Produces: observed values for P1–P9, used by Tasks 3–8.

**Status: done 2026-10-16** (inline, with the maintainer). Results: `docs/compat/observations/par.md`, D-0028–D-0030. The steps are kept as the procedure for repeating the observation; in practice each `/authorize` URL was created only when the maintainer said "go", because 30 seconds is too short for a chat round trip.

- [x] **Step 1: Point auth0-cli at the trial tenant**

Ask the maintainer to run `! auth0 login` and choose the **new trial tenant**, then:

Run: `auth0 tenants list`
Expected: the trial tenant is marked active. Never print tokens or the tenant domain into the repository. Keep the domain in a shell variable for this session only: `set -x OBS (auth0 tenants list --json | python3 -c 'import json,sys; print([t["name"] for t in json.load(sys.stdin) if t.get("active")][0])')` (fish syntax; the shell here is fish).

- [x] **Step 2: Settings and discovery before enabling PAR (P7, P8)**

```bash
auth0 api get tenants/settings | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k: v for k, v in d.items() if "push" in k.lower() or "par" == k.lower()}); print(sorted(d.get("flags", {}).keys()))' > /tmp/claude-1000/par-settings-before.txt
curl -s "https://$OBS/.well-known/openid-configuration" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sorted(k for k in d if "push" in k or "request" in k))'
```

Record the keys only. Then ask the maintainer to turn on **Dashboard → Settings → Advanced → "Allow Pushed Authorization Requests (PAR)"** and save. Run both commands again and diff. The key that changed is P7 (note whether it is top level or under `flags`); the discovery keys that appeared are P8. Also record the value of `require_pushed_authorization_requests` in discovery if present.

- [x] **Step 3: Create the test objects**

All names start with `za-obs-par-`. Scratch files go in `/tmp/claude-1000/`.

```bash
auth0 api post clients --data '{"name":"za-obs-par-web","app_type":"regular_web","callbacks":["https://example.com/cb","https://example.com/cb2"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}' > /tmp/claude-1000/za-obs-par-web.json
auth0 api post clients --data '{"name":"za-obs-par-other","app_type":"regular_web","callbacks":["https://example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}' > /tmp/claude-1000/za-obs-par-other.json
auth0 api post clients --data '{"name":"za-obs-par-spa","app_type":"spa","callbacks":["https://example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}' > /tmp/claude-1000/za-obs-par-spa.json
auth0 api post clients --data '{"name":"za-obs-par-required","app_type":"regular_web","callbacks":["https://example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post","require_pushed_authorization_requests":true}' > /tmp/claude-1000/za-obs-par-required.json
auth0 api post clients --data '{"name":"za-obs-par-3p","app_type":"regular_web","is_first_party":false,"third_party_security_mode":"strict","callbacks":["https://example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}' > /tmp/claude-1000/za-obs-par-3p.json
python3 -c 'import json; d=json.load(open("/tmp/claude-1000/za-obs-par-required.json")); print(d.get("require_pushed_authorization_requests"), d.get("errorCode") or d.get("error"))'
```

If creating `za-obs-par-required` fails because of ordering, note the error code (it confirms "tenant first"). Enable the database connection for the first-party clients, and create a test user:

```bash
auth0 users create --connection-name Username-Password-Authentication --email za-obs-par@example.com --password '<random 20 chars>' --name za-obs-par --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["user_id"])'
```

Define a helper for the back-channel calls (fish):

```fish
function par --argument-names file
    set -l id (python3 -c "import json; print(json.load(open('$file'))['client_id'])")
    set -l secret (python3 -c "import json; print(json.load(open('$file')).get('client_secret',''))")
    curl -s -o /tmp/claude-1000/par-body.json -w '%{http_code}\n' -X POST "https://$OBS/oauth/par" \
        -H 'content-type: application/x-www-form-urlencoded' \
        --data-urlencode "client_id=$id" --data-urlencode "client_secret=$secret" $argv[2..-1]
    python3 -c 'import json; d=json.load(open("/tmp/claude-1000/par-body.json")); print({k: d.get(k) for k in ["error","expires_in"]}, "request_uri" in d)'
end
```

- [x] **Step 4: Back-channel checks (P2, P3, P6a, P9)**

Each call uses `--data-urlencode response_type=code --data-urlencode redirect_uri=https://example.com/cb --data-urlencode scope=openid --data-urlencode state=s1` unless stated. Record HTTP status and `error` only.

| Check | Variation |
|---|---|
| baseline | `par /tmp/claude-1000/za-obs-par-web.json …` → expect 201, `expires_in`, and the `request_uri` prefix (record the prefix only) |
| P2a | `redirect_uri=https://example.com/nope` |
| P2b | `response_type=token` |
| P2c | add `ext-a1=x` … `ext-a11=x` (11 parameters); then the same with 10 |
| P2d | add `ext-big=` with 11000 characters |
| P2e | the baseline body as JSON (`-H 'content-type: application/json'`) |
| P3a | `client_secret=wrong` |
| P3b | the SPA client, no secret |
| P6a | add `request_uri=urn:ietf:params:oauth:request_uri:abc` |
| P9 | the strict third-party client, with `code_challenge` (43 characters) and `code_challenge_method=S256` |

- [x] **Step 5: Browser checks (P1, P4, P5)**

Before the timed checks, the maintainer logs in once on the trial tenant in a private window (any plain `/authorize` URL for `za-obs-par-web`), so later requests go straight back to `https://example.com/cb`. Claude pushes and immediately prints the `/authorize` URL; the maintainer opens it **within 30 seconds** in the same private window and replies with one of:
- `REDIRECT <parameter names>, error=<value>, state=<value>`
- `LOGIN`, `CONSENT` or `ERRORPAGE`.

| Check | Push | Browser URL |
|---|---|---|
| P1a | baseline (`state=s1`) | `/authorize?client_id=<web>&request_uri=<uri>&state=s2` → which `state` comes back? |
| P1b | baseline (`redirect_uri=…/cb`) | add `&redirect_uri=https://example.com/cb2` → which path does the browser end on? |
| P1c | baseline | add `&response_type=token&scope=openid%20email&foo=bar` → REDIRECT or ERRORPAGE? |
| P4a | baseline | open the same URL a second time |
| P4b | baseline | wait 35 s before opening |
| P4c | baseline for `za-obs-par-web` | `/authorize?client_id=<other>&request_uri=<uri>` |
| P5 | none | plain `/authorize?client_id=<required>&response_type=code&redirect_uri=https://example.com/cb&scope=openid&state=s1` |

- [x] **Step 6: Tenant setting off (P6b)**

Push one baseline request, then ask the maintainer to turn the PAR setting **off**, then:
- run the baseline `par` call again (status, `error`);
- the maintainer opens the `/authorize` URL for the request pushed before the switch (screen or redirect).

- [x] **Step 7: Tear down**

Delete every `za-obs-par-*` client and the test user. Leave the PAR setting as the maintainer prefers. Run `auth0 apps list` and confirm nothing `za-obs-par` remains. Delete the scratch files.

- [x] **Step 8: Write the observation note**

Create `docs/compat/observations/par.md` in the README layout:

```markdown
# Pushed authorization requests

- **Observed:** 2026-10-XX, on a trial tenant owned by the maintainer
- **Docs:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-par, https://auth0.com/docs/get-started/applications/configure-par
- **Method:** Management API through auth0-cli; /oauth/par through curl, recording HTTP status and `error`; /authorize in a private browser window, recording only the final redirect's parameter names and the values of `error` and `state`, or the kind of screen reached. No page text or images were captured.

## Settings and discovery (P7, P8)
- …

## /oauth/par (P2, P3, P6a, P9)
- …

## /authorize with request_uri (P1, P4, P5, P6b)
- …
```

- [x] **Step 9: Record decisions D-0028, D-0029 and D-0030**

Append to `docs/compat/decisions.md` in the existing format (Context, Sources, Decision, Rationale), each citing the two docs pages, RFC 9126 and `observations/par.md`:
- **D-0028 `/oauth/par`:** form only, 10 KB, client-secret authentication, public and strict clients refused (P3b, P9), `request_uri` in the body (P6a), validation codes and statuses (P2), `ext-*` cap, the tenant setting off (P6b), 43-character opaque identifier stored hashed.
- **D-0029 `request_uri` at `/authorize`:** extra query parameters (P1), reuse, expiry and client mismatch (P4), required PAR (P5), and the stored request surviving the login round trip.
- **D-0030 Settings and discovery:** the tenant property name (P7), the client property, seed ordering rule, discovery fields (P8).

- [x] **Step 10: Fill the Observed column of this plan**

Where an observation differs from its default, write the observed value in bold and add "→ change" so later implementers see it. If P7 differs from `pushed_authorization_requests_supported`, replace that name everywhere in Tasks 3–9 of this plan before committing (column, yaml tag, proto field name).

- [x] **Step 11: Commit**

```bash
git add docs/compat/observations/par.md docs/compat/decisions.md docs/superpowers/plans/2026-10-16-zeroauthy-plan-10-par.md
git commit -m "docs: PAR observations on the maintainer's trial tenant; D-0028, D-0029, D-0030"
```

---

### Task 2: Store types, the memory driver and conformance

**Files:**
- Modify: `internal/store/types.go`, `internal/store/store.go`, `pkg/store/store.go`
- Create: `internal/store/memory/pushed_auth_requests.go`
- Modify: `internal/store/memory/memory.go`, `tx.go`, `clone.go`
- Create: `pkg/storetest/pushed_auth_requests.go`
- Modify: `pkg/storetest/storetest.go`, `sweep.go`, `tenants.go`, `clients.go`
- Modify: `internal/app/sweeper.go`, `internal/app/sweeper_test.go`

**Interfaces:**
- Produces:
  - `store.Tenant.PushedAuthorizationRequestsSupported bool`
  - `store.Client.RequirePushedAuthorizationRequests bool`
  - `store.PushedAuthRequest{TenantID, IDHash, ClientID string; Params map[string]string; ExpiresAt, CreatedAt time.Time; UsedAt *time.Time}`
  - `store.PushedAuthRequests` with `Create(ctx, *PushedAuthRequest) error`, `Consume(ctx, tenantID, idHash string, at time.Time) (*PushedAuthRequest, error)`, `Get(ctx, tenantID, idHash string) (*PushedAuthRequest, error)`, `DeleteExpired(ctx, before time.Time) (int, error)`
  - `store.Store.PushedAuthRequests() PushedAuthRequests`
  - storetest suite name `"PushedAuthRequests"`, helper `newPushedAuthRequest(tenantID, hash string) *store.PushedAuthRequest`

- [ ] **Step 1: Write the conformance suite**

Create `pkg/storetest/pushed_auth_requests.go`:

```go
package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newPushedAuthRequest(tenantID, hash string) *store.PushedAuthRequest {
	return &store.PushedAuthRequest{
		TenantID: tenantID, IDHash: hash, ClientID: "web",
		Params: map[string]string{
			"client_id": "web", "redirect_uri": "https://web.test/cb", "response_type": "code",
			"scope": "openid", "state": "s1", "ext-tenant_hint": "blue",
		},
		ExpiresAt: ts(30 * time.Second), CreatedAt: ts(0),
	}
}

func testPushedAuthRequests(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("ConsumeOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		mustErrIs(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")), store.ErrConflict)

		got, err := s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(5*time.Second))
		mustNoErr(t, err)
		want := newPushedAuthRequest("ten_a", "h1")
		used := ts(5 * time.Second)
		want.UsedAt = &used
		mustEqual(t, got, want)

		again, err := s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(10*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(used), true) // the first use time is kept
		mustEqual(t, again.ClientID, "web")
	})

	t.Run("GetReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		got, err := s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got, newPushedAuthRequest("ten_a", "h1"))
		got.Params["state"] = "mutated"
		again, err := s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, again.Params["state"], "s1")
	})

	t.Run("CreateCopiesInput", func(t *testing.T) {
		s := open(t, newStore)
		in := newPushedAuthRequest("ten_a", "h1")
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, in))
		in.Params["state"] = "mutated"
		got, err := s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.Params["state"], "s1")
	})

	t.Run("UnknownAndOtherTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		_, err := s.PushedAuthRequests().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PushedAuthRequests().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PushedAuthRequests().Get(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)
		// The failed cross-tenant attempt must not have consumed it.
		_, err = s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(0))
		mustNoErr(t, err)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		short := newPushedAuthRequest("ten_a", "h1") // expires ts(30s)
		long := newPushedAuthRequest("ten_b", "h2")
		long.ExpiresAt = ts(time.Hour)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, short))
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, long))
		_, err := s.PushedAuthRequests().Consume(ctx, "ten_b", "h2", ts(time.Second)) // used rows are swept by expiry too
		mustNoErr(t, err)
		n, err := s.PushedAuthRequests().DeleteExpired(ctx, ts(30*time.Second))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PushedAuthRequests().Get(ctx, "ten_b", "h2")
		mustNoErr(t, err)
	})

	t.Run("ConcurrentDeleteExpiredAndCreate", func(t *testing.T) {
		testSweepWhileCreating(t, newStore, pushedAuthRequestSweepTarget())
	})

	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(time.Second))
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrAlreadyUsed):
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		mustEqual(t, ok, 1)
	})
}
```

Add to `pkg/storetest/sweep.go`, after `authCodeSweepTarget`:

```go
func pushedAuthRequestSweepTarget() sweepTarget {
	ctx := context.Background()
	return sweepTarget{
		create: func(s store.Store, i int, expired bool) error {
			x := newPushedAuthRequest("ten_a", fmt.Sprintf("h%d", i)) // expires at ts(30s)
			if expired {
				x.ExpiresAt = ts(10 * time.Second)
			}
			return s.PushedAuthRequests().Create(ctx, x)
		},
		exists: func(s store.Store, i int) (bool, error) {
			_, err := s.PushedAuthRequests().Get(ctx, "ten_a", fmt.Sprintf("h%d", i))
			return existsBy(err)
		},
		sweep:  func(s store.Store, c time.Time) (int, error) { return s.PushedAuthRequests().DeleteExpired(ctx, c) },
		cutoff: ts(20 * time.Second),
	}
}
```

In `pkg/storetest/storetest.go`, add `"PushedAuthRequests": testPushedAuthRequests,` to `Suites`, and insert `"PushedAuthRequests"` into `suiteOrder` after `"AuthCodes"`.

Add the field round trips. In `pkg/storetest/tenants.go`, inside `ConsentFlags` rename nothing; add a sibling subtest after it:

```go
	t.Run("PARFlag", func(t *testing.T) {
		s := open(t, newStore)
		want := newTenant("acme")
		want.PushedAuthorizationRequestsSupported = true
		mustNoErr(t, s.Tenants().Create(ctx, want))
		got, err := s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.PushedAuthorizationRequestsSupported = false
		mustNoErr(t, s.Tenants().Update(ctx, want))
		got, err = s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)
	})
```

In `pkg/storetest/clients.go`, after `ThirdPartyFields`:

```go
	t.Run("RequirePAR", func(t *testing.T) {
		s := open(t, newStore)
		c := newClient("ten_a", "par")
		c.RequirePushedAuthorizationRequests = true
		mustNoErr(t, s.Clients().Create(ctx, c))
		got, err := s.Clients().Get(ctx, "ten_a", "par")
		mustNoErr(t, err)
		mustEqual(t, got, c)

		c.RequirePushedAuthorizationRequests = false
		mustNoErr(t, s.Clients().Update(ctx, c))
		got, err = s.Clients().Get(ctx, "ten_a", "par")
		mustNoErr(t, err)
		mustEqual(t, got, c)
	})
```

- [ ] **Step 2: Run the memory conformance to see it fail**

Run: `go test ./internal/store/memory/`
Expected: build failure: `s.PushedAuthRequests undefined`, `unknown field PushedAuthorizationRequestsSupported`.

- [ ] **Step 3: Add the types and the interface**

In `internal/store/types.go`, add to `Tenant` after `UseScopeDescriptionsForConsent`:

```go
	// PushedAuthorizationRequestsSupported allows /oauth/par and request_uri
	// at /authorize (RFC 9126).
	PushedAuthorizationRequestsSupported bool
```

Add to `Client` after `SkipNonVerifiableCallbackURIConfirmationPrompt`:

```go
	// RequirePushedAuthorizationRequests refuses /authorize requests that
	// do not name a pushed request. Only for confidential clients of a
	// tenant that allows PAR.
	RequirePushedAuthorizationRequests bool
```

After `AuthCode`:

```go
// PushedAuthRequest is an authorization request pushed to /oauth/par
// (RFC 9126). The /authorize request that names it uses it once.
type PushedAuthRequest struct {
	TenantID string
	// IDHash is secrets.HashToken of the opaque part of the request_uri.
	IDHash   string
	ClientID string
	// Params is the validated request, including kept ext-* parameters.
	Params    map[string]string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
}
```

In `internal/store/store.go`, add `PushedAuthRequests() PushedAuthRequests` to `Store` after `AuthCodes()`, and after the `AuthCodes` interface:

```go
// PushedAuthRequests stores pushed authorization requests, keyed by
// (TenantID, IDHash).
type PushedAuthRequests interface {
	// Create returns ErrConflict if the IDHash exists in the tenant.
	Create(ctx context.Context, p *PushedAuthRequest) error
	// Consume atomically marks the request used at `at` and returns it. A
	// request that was already used is returned together with
	// ErrAlreadyUsed, and its first UsedAt is kept. Unknown requests return
	// ErrNotFound. Expiry is the caller's check.
	Consume(ctx context.Context, tenantID, idHash string, at time.Time) (*PushedAuthRequest, error)
	// Get returns the request without changing it, or ErrNotFound.
	Get(ctx context.Context, tenantID, idHash string) (*PushedAuthRequest, error)
	// DeleteExpired removes, in every tenant, the requests whose ExpiresAt
	// is not after before, used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
```

In `pkg/store/store.go`, add `PushedAuthRequests = store.PushedAuthRequests` beside `AuthCodes`, and `PushedAuthRequest = store.PushedAuthRequest` beside `AuthCode`.

- [ ] **Step 4: Implement the memory driver**

Create `internal/store/memory/pushed_auth_requests.go`:

```go
package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type pushedAuthRequests struct{ s *Store }

func (r pushedAuthRequests) Create(_ context.Context, p *store.PushedAuthRequest) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{p.TenantID, p.IDHash}
	if _, ok := r.s.pushedAuthRequests[k]; ok {
		return store.ErrConflict
	}
	r.s.pushedAuthRequests[k] = clonePushedAuthRequest(p)
	return nil
}

func (r pushedAuthRequests) Consume(_ context.Context, tenantID, idHash string, at time.Time) (*store.PushedAuthRequest, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	p, ok := r.s.pushedAuthRequests[key{tenantID, idHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if p.UsedAt != nil {
		return clonePushedAuthRequest(p), store.ErrAlreadyUsed
	}
	t := at
	p.UsedAt = &t
	return clonePushedAuthRequest(p), nil
}

func (r pushedAuthRequests) Get(_ context.Context, tenantID, idHash string) (*store.PushedAuthRequest, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	p, ok := r.s.pushedAuthRequests[key{tenantID, idHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clonePushedAuthRequest(p), nil
}

func (r pushedAuthRequests) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, p := range r.s.pushedAuthRequests {
		if !p.ExpiresAt.After(before) {
			delete(r.s.pushedAuthRequests, k)
			n++
		}
	}
	return n, nil
}
```

In `clone.go`, after `cloneAuthCode`:

```go
func clonePushedAuthRequest(p *store.PushedAuthRequest) *store.PushedAuthRequest {
	out := *p
	out.Params = maps.Clone(p.Params)
	if p.UsedAt != nil {
		t := *p.UsedAt
		out.UsedAt = &t
	}
	return &out
}
```

In `memory.go`:
- field `pushedAuthRequests map[key]*store.PushedAuthRequest // by (tenant, IDHash)` after `authCodes`;
- `pushedAuthRequests: map[key]*store.PushedAuthRequest{},` in `New`;
- `func (s *Store) PushedAuthRequests() store.PushedAuthRequests { return pushedAuthRequests{s} }` after `AuthCodes()` (run `gofmt` to realign the block).

In `tx.go`: `pushedAuthRequests: cloneMap(s.pushedAuthRequests, clonePushedAuthRequest),` in `snapshot`, and `s.pushedAuthRequests = snap.pushedAuthRequests` in `restore`.

`Tenant` and `Client` have no reference fields added, so `cloneTenant` and `cloneClient` need no change.

- [ ] **Step 5: Run the memory conformance**

Run: `go test ./internal/store/memory/ ./pkg/storetest/`
Expected: PASS. `go build ./...` fails in `sqlstore` and `grpcstore` (missing `PushedAuthRequests`); Tasks 3 and 4 fix that. Until then run only the packages named in each step.

- [ ] **Step 6: Sweep pushed requests**

In `internal/app/sweeper_test.go`, `TestSweepRemovesExpiredRecords` creates expired and live records of each kind and expects `sweep` to return 5. After the password-reset tickets, add:

```go
	must(st.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{TenantID: "t", IDHash: "old", ExpiresAt: now.Add(-time.Second)}))
	must(st.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{TenantID: "t", IDHash: "new", ExpiresAt: now.Add(30 * time.Second)}))
```

change the expected count from 5 to 6 (comparison and message), and after the existing live-record checks add:

```go
	if _, err := st.PushedAuthRequests().Get(ctx, "t", "new"); err != nil {
		t.Errorf("live pushed request removed: %v", err)
	}
```

Run: `go test ./internal/app/ -run Sweep`
Expected: FAIL (`sweep = 5`).

In `internal/app/sweeper.go`, add to `jobs` after the auth codes line:

```go
		{st.PushedAuthRequests().DeleteExpired, now},
```

Run: `go test ./internal/app/ -run Sweep`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/store pkg/store pkg/storetest internal/app
git commit -m "feat(store): pushed authorization requests; PAR tenant and client fields"
```

---

### Task 3: SQL migration 0004 and the SQL driver

**Files:**
- Create: `internal/store/sqlstore/migrations/sqlite/0004_par.sql`, `postgres/0004_par.sql`, `mysql/0004_par.sql`
- Create: `internal/store/sqlstore/pushed_auth_requests.go`
- Modify: `internal/store/sqlstore/tenants.go`, `clients.go`, `migrate_test.go`

**Interfaces:**
- Consumes: Task 2's types and interface.
- Produces: `(*sqlstore.Store).PushedAuthRequests()`; schema version 4.

- [ ] **Step 1: Bump the expected schema version**

In `migrate_test.go`, rename `TestLatestVersionIsThree` to `TestLatestVersionIsFour` and change `3` to `4` in the comparison and message.

Run: `go test ./internal/store/sqlstore/ -run TestLatestVersion`
Expected: FAIL (`LatestVersion = 3, want 4`) — the package will not build until Step 4; a build failure counts as the failing state.

- [ ] **Step 2: Write the migrations**

`migrations/sqlite/0004_par.sql` and `migrations/postgres/0004_par.sql` (identical):

```sql
-- Pushed authorization requests (Plan 10). Defaults keep existing rows'
-- behaviour: PAR off for every tenant, not required by any client.
ALTER TABLE tenants ADD COLUMN pushed_authorization_requests_supported BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN require_pushed_authorization_requests BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE pushed_auth_requests (
  tenant_id TEXT NOT NULL,
  id_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  PRIMARY KEY (tenant_id, id_hash)
);
CREATE INDEX pushed_auth_requests_expires ON pushed_auth_requests (expires_at);
```

`migrations/mysql/0004_par.sql`:

```sql
-- Pushed authorization requests (Plan 10). Defaults keep existing rows'
-- behaviour: PAR off for every tenant, not required by any client.
ALTER TABLE tenants ADD COLUMN pushed_authorization_requests_supported BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN require_pushed_authorization_requests BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE pushed_auth_requests (
  tenant_id VARCHAR(64) NOT NULL,
  id_hash VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  params LONGTEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  PRIMARY KEY (tenant_id, id_hash),
  KEY pushed_auth_requests_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
```

- [ ] **Step 3: Add the columns to tenants and clients**

`tenants.go`:
- append `, pushed_authorization_requests_supported` to `tenantCols` (after `use_scope_descriptions_for_consent`);
- the `INSERT` gets a 16th `?`;
- the `UPDATE` gets `, pushed_authorization_requests_supported=?` before ` WHERE id=?`;
- `tenantArgs` appends `t.PushedAuthorizationRequestsSupported` after `t.UseScopeDescriptionsForConsent`;
- `scanTenant` scans `&t.PushedAuthorizationRequestsSupported` after `&t.UseScopeDescriptionsForConsent`.

`clients.go`:
- append `, require_pushed_authorization_requests` to `clientCols`;
- the `INSERT` gets a 19th `?`;
- the `UPDATE` gets `, require_pushed_authorization_requests=?` after `skip_non_verifiable_callback_uri_confirmation_prompt=?`, and its comment becomes "then the 17 mutable columns";
- `clientArgs` appends `c.RequirePushedAuthorizationRequests` last;
- `scanClient` scans `&c.RequirePushedAuthorizationRequests` last.

- [ ] **Step 4: Implement the repository**

Create `internal/store/sqlstore/pushed_auth_requests.go`:

```go
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type pushedAuthRequests struct{ s *Store }

func (s *Store) PushedAuthRequests() store.PushedAuthRequests { return pushedAuthRequests{s} }

const pushedAuthRequestCols = `tenant_id, id_hash, client_id, params, expires_at, created_at, used_at`

func (r pushedAuthRequests) Create(ctx context.Context, p *store.PushedAuthRequest) error {
	params, err := toJSON(p.Params)
	if err != nil {
		return err
	}
	// Retried on deadlock: on MySQL an INSERT can be the victim of a cycle
	// with DeleteExpired's range DELETE (gap locks).
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO pushed_auth_requests (`+pushedAuthRequestCols+`) VALUES (?,?,?,?,?,?,?)`,
			p.TenantID, p.IDHash, p.ClientID, params, micros(p.ExpiresAt), micros(p.CreatedAt), nullMicros(p.UsedAt))
		return tx.conflict(err)
	})
}

// Consume claims the request with one conditional UPDATE by primary key, so
// concurrent callers see exactly one success. The read-back runs in the
// same transaction, so the returned record is the state this call saw.
func (r pushedAuthRequests) Consume(ctx context.Context, tenantID, idHash string, at time.Time) (*store.PushedAuthRequest, error) {
	var out *store.PushedAuthRequest
	var used bool
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out, used = nil, false
		res, err := tx.exec(ctx, `UPDATE pushed_auth_requests SET used_at = ? WHERE tenant_id = ? AND id_hash = ? AND used_at IS NULL`,
			micros(at), tenantID, idHash)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		used = n == 0
		p, err := pushedAuthRequests{tx}.Get(ctx, tenantID, idHash)
		if err != nil {
			return err
		}
		if p.UsedAt == nil { // created after our UPDATE looked: absent as far as this call is concerned
			return store.ErrNotFound
		}
		out = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	if used {
		return out, store.ErrAlreadyUsed
	}
	return out, nil
}

func (r pushedAuthRequests) Get(ctx context.Context, tenantID, idHash string) (*store.PushedAuthRequest, error) {
	p, err := scanPushedAuthRequest(r.s.queryRow(ctx, `SELECT `+pushedAuthRequestCols+` FROM pushed_auth_requests WHERE tenant_id = ? AND id_hash = ?`, tenantID, idHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (r pushedAuthRequests) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM pushed_auth_requests WHERE expires_at <= ?`, micros(before)))
		return err
	})
	return n, err
}

func scanPushedAuthRequest(row scanner) (*store.PushedAuthRequest, error) {
	var p store.PushedAuthRequest
	var params string
	var exp, created int64
	var used sql.NullInt64
	if err := row.Scan(&p.TenantID, &p.IDHash, &p.ClientID, &params, &exp, &created, &used); err != nil {
		return nil, err
	}
	if err := fromJSON(params, &p.Params); err != nil {
		return nil, err
	}
	p.ExpiresAt, p.CreatedAt, p.UsedAt = fromMicros(exp), fromMicros(created), fromNullMicros(used)
	return &p, nil
}
```

- [ ] **Step 5: Run the SQL conformance on all three databases**

Run: `go test ./internal/store/sqlstore/` (SQLite only)
Expected: PASS, including `TestConformance/sqlite/PushedAuthRequests` and `TestLatestVersionIsFour`.

Run: `./scripts/test-sql.sh ./internal/store/sqlstore/`
Expected: PASS on sqlite, postgres and mysql. A Postgres or MySQL failure in `ConcurrentDeleteExpiredAndCreate` means the index or the retry is missing; compare with `auth_codes`.

- [ ] **Step 6: Commit**

```bash
git add internal/store/sqlstore
git commit -m "feat(sqlstore): migration 0004; pushed authorization requests; PAR columns"
```

---

### Task 4: The gRPC plugin protocol

**Files:**
- Modify: `proto/store/v1/store.proto` (then `go generate ./proto/...`)
- Modify: `internal/store/grpcstore/codec.go`, `client_repos.go`, `server_repos.go`, `client.go`
- Test: `internal/store/grpcstore/codec_test.go`, `client_test.go`

**Interfaces:**
- Consumes: Task 2's types.
- Produces: RPCs `PushedAuthRequestsCreate`, `PushedAuthRequestsConsume`, `PushedAuthRequestsGet`, `PushedAuthRequestsDeleteExpired`; codec `pushedAuthRequestToPB` / `pushedAuthRequestFromPB`.

- [ ] **Step 1: Write the old-plugin test**

Add to `internal/store/grpcstore/client_test.go` (imports as needed: `net`, `google.golang.org/grpc`, `insecure`, `bufconn`, `storev1`, `time`):

```go
// oldPlugin answers every RPC with Unimplemented, like a plugin built before
// the RPC existed.
type oldPlugin struct{ storev1.UnimplementedStoreServiceServer }

func serveOldPlugin(t *testing.T) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	storev1.RegisterStoreServiceServer(gs, oldPlugin{})
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(conn, func() error { err := conn.Close(); gs.Stop(); return err })
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The sweeper runs on every deployment. A plugin that predates PAR stores no
// pushed requests, so there is nothing to sweep and nothing to report.
func TestOldPluginPushedAuthRequestsSweep(t *testing.T) {
	c := serveOldPlugin(t)
	n, err := c.PushedAuthRequests().DeleteExpired(context.Background(), time.Now())
	if n != 0 || err != nil {
		t.Fatalf("DeleteExpired = %d, %v; want 0, nil", n, err)
	}
	// Other calls still fail: PAR cannot silently work without storage.
	if _, err := c.PushedAuthRequests().Get(context.Background(), "t", "h"); err == nil {
		t.Fatal("Get on an old plugin succeeded")
	}
}
```

Add a codec round trip to `codec_test.go`, following the existing auth-code round-trip test in that file:

```go
func TestPushedAuthRequestCodecRoundTrip(t *testing.T) {
	used := time.Date(2026, 1, 2, 3, 4, 5, 6000, time.UTC)
	for _, in := range []*store.PushedAuthRequest{
		{TenantID: "t", IDHash: "h", ClientID: "c", Params: map[string]string{"state": "s", "ext-a": "b"},
			ExpiresAt: used.Add(30 * time.Second), CreatedAt: used.Add(-time.Second)},
		{TenantID: "t", IDHash: "h", ClientID: "c", Params: map[string]string{},
			ExpiresAt: used, CreatedAt: used, UsedAt: &used},
	} {
		pb, err := pushedAuthRequestToPB(in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pushedAuthRequestFromPB(pb)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(out, in) {
			t.Fatalf("round trip: got %+v, want %+v", out, in)
		}
	}
}

// Plugins built before fields 16 (tenant) and 19 (client) never set them:
// PAR stays off and is never required.
func TestPARFieldsDefaultOffForOldPlugins(t *testing.T) {
	tn, err := tenantFromPB(&storev1.Tenant{Id: "t", Name: "t"})
	if err != nil || tn.PushedAuthorizationRequestsSupported {
		t.Fatalf("tenant = %+v, %v", tn, err)
	}
	c, err := clientFromPB(&storev1.Client{TenantId: "t", ClientId: "c"})
	if err != nil || c.RequirePushedAuthorizationRequests {
		t.Fatalf("client = %+v, %v", c, err)
	}
}
```

If an empty `Params` map decodes as `nil` (check `stringMapFromPB`), make the second case's `Params` nil instead of `map[string]string{}` so the test pins the codec's actual contract; do the same check the auth-transaction round trip already makes. If `tenantFromPB`/`clientFromPB` have different names, use the names in `codec.go`.

Run: `go test ./internal/store/grpcstore/`
Expected: build failure (undefined `PushedAuthRequests`, `pushedAuthRequestToPB`).

- [ ] **Step 2: Extend the proto**

In `proto/store/v1/store.proto`:

`Tenant`, after field 15:
```proto
  bool pushed_authorization_requests_supported = 16; // absent = false
```

`Client`, after field 18:
```proto
  bool require_pushed_authorization_requests = 19;   // absent = false
```

After `message AuthCode`:
```proto
message PushedAuthRequest {
  string tenant_id = 1; string id_hash = 2; string client_id = 3; StringMap params = 4;
  google.protobuf.Timestamp expires_at = 5; google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp used_at = 7; // absent = nil
}
```

After `AuthCodeResult`:
```proto
message PushedAuthRequestWrite { string tx_id = 1; PushedAuthRequest value = 2; }
message PushedAuthRequestResult { Error error = 1; PushedAuthRequest value = 2; } // Consume may set both
```

In `service StoreService`, after the auth-code RPCs:
```proto
  rpc PushedAuthRequestsCreate(PushedAuthRequestWrite) returns (Result);
  rpc PushedAuthRequestsConsume(ConsumeRequest) returns (PushedAuthRequestResult);
  rpc PushedAuthRequestsGet(ScopedKey) returns (PushedAuthRequestResult);
  rpc PushedAuthRequestsDeleteExpired(DeleteExpiredRequest) returns (CountResult);
```

Run: `go generate ./proto/...`
Expected: `store.pb.go` and `store_grpc.pb.go` regenerate.

- [ ] **Step 3: Codec**

In `codec.go`, in the tenant encoder add `PushedAuthorizationRequestsSupported: t.PushedAuthorizationRequestsSupported,` and in the decoder `PushedAuthorizationRequestsSupported: pb.PushedAuthorizationRequestsSupported,`. Likewise for the client with `RequirePushedAuthorizationRequests`.

After the auth-code section:

```go
// ---- pushed auth request ----

func pushedAuthRequestToPB(p *store.PushedAuthRequest) (*storev1.PushedAuthRequest, error) {
	if p == nil {
		return nil, nil
	}
	return &storev1.PushedAuthRequest{
		TenantId: p.TenantID, IdHash: p.IDHash, ClientId: p.ClientID, Params: stringMapToPB(p.Params),
		ExpiresAt: tsToPB(p.ExpiresAt), CreatedAt: tsToPB(p.CreatedAt), UsedAt: optTSToPB(p.UsedAt),
	}, nil
}

func pushedAuthRequestFromPB(pb *storev1.PushedAuthRequest) (*store.PushedAuthRequest, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.ExpiresAt, pb.CreatedAt, pb.UsedAt); err != nil {
		return nil, err
	}
	return &store.PushedAuthRequest{
		TenantID: pb.TenantId, IDHash: pb.IdHash, ClientID: pb.ClientId, Params: stringMapFromPB(pb.Params),
		ExpiresAt: tsFromPB(pb.ExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt), UsedAt: optTSFromPB(pb.UsedAt),
	}, nil
}
```

- [ ] **Step 4: Client and server repositories**

`client.go`, after `AuthCodes()`:
```go
func (c *Client) PushedAuthRequests() store.PushedAuthRequests { return clientPushedAuthRequests{c} }
```

`client_repos.go`, after `clientAuthCodes` (add imports `google.golang.org/grpc/codes` and `google.golang.org/grpc/status` if absent):

```go
type clientPushedAuthRequests struct{ c *Client }

func (a clientPushedAuthRequests) Create(ctx context.Context, v *store.PushedAuthRequest) error {
	return put("PushedAuthRequestsCreate", v, pushedAuthRequestToPB, func(pb *storev1.PushedAuthRequest) (result, error) {
		return a.c.rpc.PushedAuthRequestsCreate(ctx, &storev1.PushedAuthRequestWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientPushedAuthRequests) Consume(ctx context.Context, tenantID, idHash string, at time.Time) (*store.PushedAuthRequest, error) {
	r, err := a.c.rpc.PushedAuthRequestsConsume(ctx, &storev1.ConsumeRequest{TxId: a.c.txID, TenantId: tenantID, Hash: idHash, At: tsToPB(at)})
	return decOne("PushedAuthRequestsConsume", err, r.GetError(), r.GetValue(), pushedAuthRequestFromPB)
}

func (a clientPushedAuthRequests) Get(ctx context.Context, tenantID, idHash string) (*store.PushedAuthRequest, error) {
	r, err := a.c.rpc.PushedAuthRequestsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: idHash})
	return decOne("PushedAuthRequestsGet", err, r.GetError(), r.GetValue(), pushedAuthRequestFromPB)
}

// DeleteExpired treats a plugin that predates the RPC as holding no pushed
// requests: the sweeper calls it on every deployment.
func (a clientPushedAuthRequests) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.PushedAuthRequestsDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	if status.Code(err) == codes.Unimplemented {
		return 0, nil
	}
	return counted("PushedAuthRequestsDeleteExpired", r, err)
}
```

`server_repos.go`, after the auth-code section:

```go
// ---- pushed auth requests ----

func (s *Server) PushedAuthRequestsCreate(ctx context.Context, r *storev1.PushedAuthRequestWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, pushedAuthRequestFromPB, func(st store.Store, p *store.PushedAuthRequest) error {
		return st.PushedAuthRequests().Create(ctx, p)
	}), nil
}

// PushedAuthRequestsConsume returns the request together with ErrAlreadyUsed on reuse.
func (s *Server) PushedAuthRequestsConsume(ctx context.Context, r *storev1.ConsumeRequest) (*storev1.PushedAuthRequestResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.PushedAuthRequest, error) {
		return st.PushedAuthRequests().Consume(ctx, r.TenantId, r.Hash, tsFromPB(r.At))
	}, pushedAuthRequestToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.PushedAuthRequestResult{Error: e, Value: v}, nil
}

func (s *Server) PushedAuthRequestsGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.PushedAuthRequestResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.PushedAuthRequest, error) {
		return st.PushedAuthRequests().Get(ctx, r.TenantId, r.Key)
	}, pushedAuthRequestToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.PushedAuthRequestResult{Error: e, Value: v}, nil
}

func (s *Server) PushedAuthRequestsDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.PushedAuthRequests().DeleteExpired(ctx, tsFromPB(r.Before))
	}), nil
}
```

- [ ] **Step 5: Run everything that builds now**

Run: `go build ./... && go test ./internal/store/... ./pkg/... ./internal/app/`
Expected: PASS, including `TestConformance` (memory and SQLite over gRPC), the reflection test that every RPC is implemented by `*Server`, `TestOldPluginPushedAuthRequestsSweep` and the codec tests.

Run: `go generate ./... && git status --short`
Expected: no changes beyond this task's files.

- [ ] **Step 6: Commit**

```bash
git add proto internal/store/grpcstore
git commit -m "feat(grpcstore): pushed authorization requests and PAR fields in the plugin protocol"
```

---

### Task 5: The seed

**Files:**
- Modify: `internal/seed/seed.go`, `validate.go`, `apply.go`
- Test: `internal/seed/seed_test.go`

**Interfaces:**
- Consumes: Task 2's fields.
- Produces: seed YAML `pushed_authorization_requests_supported` (tenant) and `require_pushed_authorization_requests` (client).

- [ ] **Step 1: Write the failing tests**

Add to the `cases` map in `TestValidation`:

```go
		"par without tenant":   {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, require_pushed_authorization_requests: true}]}]`, `require_pushed_authorization_requests needs the tenant's pushed_authorization_requests_supported`},
		"par on public client": {`tenants: [{name: a, pushed_authorization_requests_supported: true, clients: [{client_id: c, app_type: spa, require_pushed_authorization_requests: true}]}]`, `require_pushed_authorization_requests is only for confidential applications`},
		"par on third party":   {`tenants: [{name: a, pushed_authorization_requests_supported: true, clients: [{client_id: c, app_type: regular_web, client_secret: s, is_first_party: false, third_party_security_mode: permissive, require_pushed_authorization_requests: true}]}]`, `third-party applications cannot use pushed authorization requests`},
```

Add a new test:

```go
func TestApplyPARFields(t *testing.T) {
	const doc = `
tenants:
  - name: acme
    pushed_authorization_requests_supported: true
    clients:
      - {client_id: web, app_type: regular_web, client_secret: s, require_pushed_authorization_requests: true}
      - {client_id: other, app_type: regular_web, client_secret: s}
`
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil || !tn.PushedAuthorizationRequestsSupported {
		t.Fatalf("tenant = %+v, %v", tn, err)
	}
	for id, want := range map[string]bool{"web": true, "other": false} {
		c, err := st.Clients().Get(ctx, tn.ID, id)
		if err != nil || c.RequirePushedAuthorizationRequests != want {
			t.Fatalf("%s: RequirePushedAuthorizationRequests = %v, %v; want %v", id, c.RequirePushedAuthorizationRequests, err, want)
		}
	}

	// Applying again with the settings removed turns them off.
	f, err = Parse([]byte(strings.ReplaceAll(strings.ReplaceAll(doc, "pushed_authorization_requests_supported: true", ""), ", require_pushed_authorization_requests: true", "")))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	c, _ := st.Clients().Get(ctx, tn.ID, "web")
	if tn.PushedAuthorizationRequestsSupported || c.RequirePushedAuthorizationRequests {
		t.Fatalf("settings not cleared: tenant %v client %v", tn.PushedAuthorizationRequestsSupported, c.RequirePushedAuthorizationRequests)
	}
}
```

Run: `go test ./internal/seed/ -run 'TestValidation|TestApplyPARFields'`
Expected: FAIL (`unknown field` errors from the strict YAML decoder).

- [ ] **Step 2: Implement**

`seed.go`: add to `Tenant` after `UseScopeDescriptionsForConsent`:
```go
	PushedAuthorizationRequestsSupported bool `yaml:"pushed_authorization_requests_supported"`
```
and to `Client` after `SkipNonVerifiableCallbackURIConfirmationPrompt`:
```go
	RequirePushedAuthorizationRequests bool `yaml:"require_pushed_authorization_requests"`
```

`validate.go`, in the client loop, after the third-party mode defaulting (where `c.ThirdPartySecurityMode` is final and `public` is known):

```go
		if c.RequirePushedAuthorizationRequests {
			switch {
			case !t.PushedAuthorizationRequestsSupported:
				fail("client %q: require_pushed_authorization_requests needs the tenant's pushed_authorization_requests_supported", c.ClientID)
			case public:
				fail("client %q: require_pushed_authorization_requests is only for confidential applications", c.ClientID)
			case !firstParty:
				fail("client %q: third-party applications cannot use pushed authorization requests", c.ClientID) // P9, D-0028
			}
		}
```

`apply.go`: in both tenant branches (create and update), after `tn.UseScopeDescriptionsForConsent = …`:
```go
		tn.PushedAuthorizationRequestsSupported = in.PushedAuthorizationRequestsSupported
```
In `applyClient`, after the `RedirectionPolicy` line:
```go
	c.RequirePushedAuthorizationRequests = in.RequirePushedAuthorizationRequests
```

- [ ] **Step 3: Run the seed tests**

Run: `go test ./internal/seed/`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/seed
git commit -m "feat(seed): pushed_authorization_requests_supported and require_pushed_authorization_requests"
```

---

### Task 6: /authorize: the request model, shared validation and request_uri

**Files:**
- Create: `internal/authz/par.go`, `internal/authz/par_test.go`
- Modify: `internal/authz/request.go`, `validate.go`, `handlers.go`, `validate_test.go`, `fixture_test.go`
- Modify: `api/authentication.yaml` (the `request_uri` query parameter), then `go generate ./internal/gen/...`

**Interfaces:**
- Consumes: Task 2's store; Task 5's seed fields (in the fixture).
- Produces (used by Task 7):
  - `authz.RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"`
  - `authz.PARLifetime = 30 * time.Second`
  - `authz.MaxExtParams = 10`
  - `authz.ExtPrefix = "ext-"`
  - `authz.Request.Ext map[string]string`, `authz.Request.Pushed bool`
  - `authz.ValidateRequest(ctx, st store.Store, t *store.Tenant, req *Request) (*store.Client, *Error, bool)` (the renamed `validate`)
  - `authz.Error` fields `Code`, `Description` (unchanged)

- [ ] **Step 1: Extend the fixture**

In `internal/authz/fixture_test.go`, add `pushed_authorization_requests_supported: true` to tenant `acme`, and these clients (and add `par-web` and `par-required` to the `Username-Password-Authentication` `enabled_clients`):

```yaml
      - client_id: par-web
        app_type: regular_web
        client_secret: par-web-secret
        grant_types: [authorization_code]
        callbacks: ["https://par.acme.test/cb", "https://par.acme.test/cb2"]
      - client_id: par-required
        app_type: regular_web
        client_secret: par-required-secret
        require_pushed_authorization_requests: true
        grant_types: [authorization_code]
        callbacks: ["https://req.acme.test/cb"]
```

Tenant `globex` keeps PAR off.

- [ ] **Step 2: Write the failing tests**

Create `internal/authz/par_test.go`:

```go
package authz

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// push stores a pushed request the way /oauth/par does and returns its
// request_uri.
func (e *env) push(t *testing.T, tenantID, clientID string, params map[string]string, expiresIn time.Duration) string {
	t.Helper()
	id := secrets.RandomString(43)
	p := map[string]string{"client_id": clientID}
	for k, v := range params {
		p[k] = v
	}
	if err := e.st.PushedAuthRequests().Create(context.Background(), &store.PushedAuthRequest{
		TenantID: tenantID, IDHash: secrets.HashToken(id), ClientID: clientID, Params: p,
		ExpiresAt: fixedNow().Add(expiresIn), CreatedAt: fixedNow(),
	}); err != nil {
		t.Fatal(err)
	}
	return RequestURIPrefix + id
}

func parParams() map[string]string {
	return map[string]string{
		"redirect_uri": "https://par.acme.test/cb", "response_type": "code",
		"scope": "openid", "state": "pushed-state", "za_pushed": "1",
	}
}

func parQuery(clientID, uri string) url.Values {
	return url.Values{"client_id": {clientID}, "request_uri": {uri}}
}

func TestPushedRequestStartsLogin(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	loc := location(t, e.get(t, parQuery("par-web", uri)))
	if loc.Path != "/u/login" {
		t.Fatalf("Location = %s", loc)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params["state"] != "pushed-state" || txn.Params["redirect_uri"] != "https://par.acme.test/cb" {
		t.Fatalf("transaction params = %v", txn.Params)
	}
}

func TestPushedRequestWithSessionIssuesCode(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	loc := location(t, e.get(t, parQuery("par-web", uri), e.login(t, fixedNow())))
	if loc.Host != "par.acme.test" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "pushed-state" {
		t.Fatalf("Location = %s", loc)
	}
}

// P1: SDKs add their own parameters next to request_uri; only the pushed
// ones count.
func TestPushedExtrasAreIgnored(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	q := parQuery("par-web", uri)
	q.Set("state", "query-state")
	q.Set("redirect_uri", "https://par.acme.test/cb2")
	q.Set("response_type", "token")
	q.Set("scope", "openid email")
	q.Set("foo", "bar")
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Path != "/cb" || loc.Query().Get("state") != "pushed-state" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestPushedReuseFails(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	location(t, e.get(t, parQuery("par-web", uri)))
	rec := e.get(t, parQuery("par-web", uri))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("reuse: status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestPushedRequestRefused(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func() url.Values{
		"expired": func() url.Values {
			return parQuery("par-web", e.push(t, e.tenant.ID, "par-web", parParams(), 0))
		},
		"other client": func() url.Values {
			return parQuery("web", e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime))
		},
		"unknown":      func() url.Values { return parQuery("par-web", RequestURIPrefix+"nope") },
		"wrong prefix": func() url.Values { return parQuery("par-web", "urn:example:nope") },
		"no client_id": func() url.Values { return url.Values{"request_uri": {RequestURIPrefix + "x"}} },
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.get(t, q())
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
				t.Fatalf("status %d, Location %q, body %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
		})
	}
}

// P6b: a tenant without PAR refuses request_uri.
func TestPushedRequestOnTenantWithoutPAR(t *testing.T) {
	e := newEnv(t)
	globex, err := e.st.Tenants().GetByName(context.Background(), "globex")
	if err != nil {
		t.Fatal(err)
	}
	uri := e.push(t, globex.ID, "globex-spa", map[string]string{
		"redirect_uri": "https://app.globex.test/cb", "response_type": "code", "za_pushed": "1",
	}, PARLifetime)
	r := httptestRequest("https://globex.example.test/authorize?" + parQuery("globex-spa", uri).Encode())
	rec := e.serve(t, r)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

// P5: a client that requires PAR cannot use a plain request.
func TestRequiredPARRefusesPlainRequest(t *testing.T) {
	e := newEnv(t)
	q := url.Values{
		"client_id": {"par-required"}, "redirect_uri": {"https://req.acme.test/cb"},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"s1"},
	}
	loc := location(t, e.get(t, q))
	if loc.Host != "req.acme.test" || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != "s1" {
		t.Fatalf("Location = %s", loc)
	}
}

// Review focus 2: the pushed mark survives the login transaction, so Resume
// does not refuse a client that requires PAR.
func TestRequiredPARSurvivesLogin(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-required", map[string]string{
		"redirect_uri": "https://req.acme.test/cb", "response_type": "code", "scope": "openid", "za_pushed": "1",
	}, PARLifetime)
	loc := location(t, e.get(t, parQuery("par-required", uri)))
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	req := RequestFromParams(txn.Params)
	if !req.Pushed {
		t.Fatalf("transaction lost the pushed mark: %v", txn.Params)
	}
	if _, verr, _ := ValidateRequest(context.Background(), e.st, e.tenant, &req); verr != nil {
		t.Fatalf("revalidation failed: %+v", verr)
	}
}

// Review focus 5.
func TestExtParamsRoundTrip(t *testing.T) {
	req := ParseRequest(url.Values{"client_id": {"c"}, "ext-tenant_hint": {"blue"}, "foo": {"bar"}})
	req.Pushed = true
	p := req.Params()
	if p["ext-tenant_hint"] != "blue" || p["za_pushed"] != "1" || p["foo"] != "" {
		t.Fatalf("Params = %v", p)
	}
	p["za_stage"] = "consent"
	back := RequestFromParams(p)
	if back.Ext["ext-tenant_hint"] != "blue" || !back.Pushed || len(back.Ext) != 1 {
		t.Fatalf("RequestFromParams = %+v", back)
	}
	// A pushed mark never comes from a browser query.
	if ParseRequest(url.Values{"za_pushed": {"1"}}).Pushed {
		t.Fatal("ParseRequest accepted za_pushed from a query")
	}
	if !strings.HasPrefix(RequestURIPrefix, "urn:ietf:params:oauth:request_uri:") || MaxExtParams != 10 || PARLifetime != 30*time.Second {
		t.Fatal("PAR constants changed")
	}
}
```

`httptestRequest` and `e.serve` do not exist yet. Add them to `handlers_test.go` next to `get`, and make `get` use them:

```go
func httptestRequest(target string) *http.Request { return httptest.NewRequest("GET", target, nil) }

func (e *env) serve(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}
```

Also rename every `validate(` call in `validate_test.go` to `ValidateRequest(`.

Run: `go test ./internal/authz/`
Expected: build failure (undefined `RequestURIPrefix`, `PARLifetime`, `ValidateRequest`, `Pushed`, `Ext`).

- [ ] **Step 3: Constants and the request model**

Create `internal/authz/par.go`:

```go
package authz

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Pushed authorization requests (RFC 9126, D-0028, D-0029).
const (
	RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"
	// PARLifetime is fixed, as on Auth0.
	PARLifetime = 30 * time.Second
	// MaxExtParams is how many ext-* parameters a pushed request may carry.
	MaxExtParams = 10
	ExtPrefix    = "ext-"
)

// pushedKey marks a request that came from /oauth/par in stored Params. Like
// stageKey it is not a request parameter: ParseRequest never reads it.
const pushedKey = "za_pushed"

func errPushedUnusable() *Error {
	return errInvalidRequest("request_uri is invalid, expired or already used")
}

// resolvePushed replaces a request_uri request with the request it names.
// It returns nil, nil for strict third-party clients: ValidateRequest refuses
// their request_uri (D-0025). Every error is shown on the error page; the
// pushed redirect_uri is unknown until the request is found.
func (h *Handlers) resolvePushed(ctx context.Context, t *store.Tenant, q url.Values) (*Request, *Error) {
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, errInvalidRequest("client_id is required")
	}
	client, err := h.Store.Clients().Get(ctx, t.ID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidRequest("unknown client")
	}
	if err != nil {
		return nil, errServer()
	}
	if access.Strict(client) {
		return nil, nil
	}
	if !t.PushedAuthorizationRequestsSupported {
		return nil, errInvalidRequest("pushed authorization requests are not enabled") // P6b
	}
	id, ok := strings.CutPrefix(q.Get("request_uri"), RequestURIPrefix)
	if !ok || id == "" {
		return nil, errPushedUnusable()
	}
	now := h.now()
	p, err := h.Store.PushedAuthRequests().Consume(ctx, t.ID, secrets.HashToken(id), now)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrAlreadyUsed):
		return nil, errPushedUnusable() // P4a
	case err != nil:
		h.log().ErrorContext(ctx, "consume pushed request", "tenant", t.ID, "err", err)
		return nil, errServer()
	}
	if p.ClientID != client.ClientID || !now.Before(p.ExpiresAt) {
		return nil, errPushedUnusable() // P4b, P4c
	}
	// P1: query parameters other than client_id and request_uri are ignored.
	req := RequestFromParams(p.Params)
	req.Pushed = true
	return &req, nil
}
```

In `request.go`, add to `Request` after `UILocales`:

```go
	// Ext holds ext-* parameters, kept for Actions (sub-project 2).
	Ext map[string]string
	// Pushed is true for a request that came from /oauth/par.
	Pushed bool
```

`ParseRequest` collects `ext-*` parameters (never `za_pushed`):

```go
	for k := range q {
		if strings.HasPrefix(k, ExtPrefix) {
			if r.Ext == nil {
				r.Ext = map[string]string{}
			}
			r.Ext[k] = q.Get(k)
		}
	}
```

`Params` adds, before `return out`:

```go
	for k, v := range r.Ext {
		out[k] = v
	}
	if r.Pushed {
		out[pushedKey] = "1"
	}
```

`RequestFromParams` adds, before `return r`:

```go
	for k, v := range p {
		if strings.HasPrefix(k, ExtPrefix) {
			if r.Ext == nil {
				r.Ext = map[string]string{}
			}
			r.Ext[k] = v
		}
	}
	r.Pushed = p[pushedKey] == "1"
```

- [ ] **Step 4: Export validation and enforce required PAR**

In `validate.go`, rename `validate` to `ValidateRequest` and update its comment ("ValidateRequest checks an authorization request in the order of spec §6.2. /oauth/par uses it too."). Update the four callers in `handlers.go`.

After the redirect URI check (the `callbackAllowed` block) and before the response-mode handling, add:

```go
	if client.RequirePushedAuthorizationRequests && !req.Pushed {
		return client, errInvalidRequest("this application must use pushed authorization requests"), true // P5
	}
```

`req.ResponseMode` is still empty there; `writeResponse` must see `query`. Move the line `if req.ResponseMode == "" { req.ResponseMode = "query" }` above the new check (it is idempotent).

- [ ] **Step 5: Resolve request_uri in Authorize**

In `handlers.go`, `Authorize`, replace:

```go
	view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, r.URL.Query().Get("ui_locales")))
	req := ParseRequest(r.URL.Query())
```

with:

```go
	q := r.URL.Query()
	view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, q.Get("ui_locales")))
	req := ParseRequest(q)
	if q.Has("request_uri") {
		pushed, perr := h.resolvePushed(ctx, res.Tenant, q)
		if perr != nil {
			ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), perr.Description)
			return
		}
		if pushed != nil {
			req = *pushed
			view = ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, req.UILocales))
		}
	}
```

- [ ] **Step 6: Document request_uri in the contract**

In `api/authentication.yaml`, `/authorize` parameters, after `ui_locales`:

```yaml
        - {name: request_uri, in: query, schema: {type: string}, description: "A `urn:ietf:params:oauth:request_uri:` value from `/oauth/par`. The pushed request replaces every other parameter except `client_id`, which must match."}
```

Run: `go generate ./internal/gen/... && go build ./...`
Expected: builds (the server ignores `AuthorizeParams`).

- [ ] **Step 7: Run the authz tests**

Run: `go test ./internal/authz/ ./internal/login/`
Expected: PASS, including the existing strict-client test that sends `request_uri` (it still gets the redirect with `invalid_request`).

- [ ] **Step 8: Commit**

```bash
git add internal/authz api internal/gen
git commit -m "feat(authz): request_uri from pushed requests; required PAR; ext parameters"
```

---

### Task 7: POST /oauth/par and discovery

**Files:**
- Create: `internal/oauth/par.go`, `internal/oauth/par_test.go`
- Modify: `internal/oauth/fixture_test.go`
- Modify: `api/authentication.yaml` (path, schemas, discovery field), then `go generate ./internal/gen/...`
- Modify: `internal/server/server.go`
- Modify: `internal/oidc/handlers.go` and its test file

**Interfaces:**
- Consumes: `authz.ParseRequest`, `authz.ValidateRequest`, `authz.Request.Pushed`, `authz.RequestURIPrefix`, `authz.PARLifetime`, `authz.MaxExtParams`, `authz.ExtPrefix`; `store.PushedAuthRequests`; `(*Handlers).authenticateClient`.
- Produces: `(*oauth.Handlers).OauthPar(w, r)`; generated `ServerInterface.OauthPar`; `oidc.Configuration.PushedAuthorizationRequestEndpoint`.

- [ ] **Step 1: Extend the fixture**

In `internal/oauth/fixture_test.go`, add `pushed_authorization_requests_supported: true` to tenant `acme` and these clients:

```yaml
      - {client_id: par-web, app_type: regular_web, client_secret: par-web-secret, grant_types: [authorization_code], callbacks: ["https://par.acme.test/cb"]}
      - {client_id: par-basic, app_type: regular_web, client_secret: par-basic-secret, token_endpoint_auth_method: client_secret_basic, grant_types: [authorization_code], callbacks: ["https://par.acme.test/cb"]}
      - {client_id: par-strict, app_type: regular_web, client_secret: par-strict-secret, is_first_party: false, grant_types: [authorization_code], callbacks: ["https://partner.acme.test/cb"]}
```

and to tenant `globex`:

```yaml
      - {client_id: globex-web, app_type: regular_web, client_secret: globex-web-secret, grant_types: [authorization_code], callbacks: ["https://web.globex.test/cb"]}
```

(`code-spa` is the public client used for P3b.)

- [ ] **Step 2: Write the failing tests**

Create `internal/oauth/par_test.go`:

```go
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func (f *fixture) par(t *testing.T, host, contentType, body string, basic ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthPar)))
	req := httptest.NewRequest("POST", "https://"+host+"/oauth/par", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

const formType = "application/x-www-form-urlencoded"

func parForm(extra ...string) url.Values {
	v := url.Values{
		"client_id": {"par-web"}, "client_secret": {"par-web-secret"},
		"response_type": {"code"}, "redirect_uri": {"https://par.acme.test/cb"},
		"scope": {"openid"}, "state": {"s1"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestPARStoresRequest(t *testing.T) {
	f := newFixture(t)
	rec, body := f.par(t, "acme.example.test", formType, parForm("ext-tenant_hint", "blue", "foo", "bar").Encode())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %v", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || body["expires_in"] != float64(30) {
		t.Fatalf("headers %v body %v", rec.Header(), body)
	}
	uri, _ := body["request_uri"].(string)
	id, ok := strings.CutPrefix(uri, authz.RequestURIPrefix)
	if !ok || len(id) != 64 {
		t.Fatalf("request_uri = %q", uri)
	}
	p, err := f.st.PushedAuthRequests().Get(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(id))
	if err != nil {
		t.Fatal(err)
	}
	if p.ClientID != "par-web" || p.Params["state"] != "s1" || p.Params["ext-tenant_hint"] != "blue" ||
		p.Params["foo"] != "" || p.Params["client_secret"] != "" || p.Params["za_pushed"] != "1" {
		t.Fatalf("stored params = %v", p.Params)
	}
	if !p.ExpiresAt.Equal(fixedNow().Add(authz.PARLifetime)) {
		t.Fatalf("ExpiresAt = %v", p.ExpiresAt)
	}
}

func TestPARWithBasicAuth(t *testing.T) {
	f := newFixture(t)
	form := parForm()
	form.Del("client_secret")
	form.Set("client_id", "par-basic")
	rec, body := f.par(t, "acme.example.test", formType, form.Encode(), "par-basic", "par-basic-secret")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %v", rec.Code, body)
	}
}

func TestPARRefusals(t *testing.T) {
	f := newFixture(t)
	elevenExt := parForm()
	for i := range 11 {
		elevenExt.Set(fmt.Sprintf("ext-a%d", i), "x")
	}
	tenExt := parForm()
	for i := range 10 {
		tenExt.Set(fmt.Sprintf("ext-a%d", i), "x")
	}
	public := url.Values{"client_id": {"code-spa"}, "response_type": {"code"}, "redirect_uri": {"https://app.acme.test/cb"}}
	strict := parForm("client_id", "par-strict", "client_secret", "par-strict-secret", "redirect_uri", "https://partner.acme.test/cb",
		"code_challenge", strings.Repeat("a", 43), "code_challenge_method", "S256")
	cases := []struct {
		name, host, ctype, body string
		status                  int
		code                    string
	}{
		{"P2a bad redirect_uri", "acme.example.test", formType, parForm("redirect_uri", "https://evil.test/cb").Encode(), 400, "invalid_request"},
		{"P2b response_type", "acme.example.test", formType, parForm("response_type", "token").Encode(), 501, "unsupported_response_type"},
		{"unknown audience", "acme.example.test", formType, parForm("audience", "https://nope.test").Encode(), 403, "access_denied"},
		{"P2c eleven ext", "acme.example.test", formType, elevenExt.Encode(), 400, "invalid_request"},
		{"P2d oversized", "acme.example.test", formType, parForm("ext-big", strings.Repeat("x", 11000)).Encode(), 413, "payload_too_large"},
		{"P2e json", "acme.example.test", "application/json", `{"client_id":"par-web","client_secret":"par-web-secret","response_type":"code"}`, 400, "invalid_request"},
		{"repeated", "acme.example.test", formType, parForm().Encode() + "&state=s2", 400, "invalid_request"},
		{"P3a wrong secret", "acme.example.test", formType, parForm("client_secret", "nope").Encode(), 401, "invalid_client"},
		{"P3b public", "acme.example.test", formType, public.Encode(), 400, "invalid_request"},
		{"P6a request_uri", "acme.example.test", formType, parForm("request_uri", authz.RequestURIPrefix+"x").Encode(), 400, "invalid_request"},
		{"P6b tenant off", "globex.example.test", formType, url.Values{"client_id": {"globex-web"}, "client_secret": {"globex-web-secret"}, "response_type": {"code"}, "redirect_uri": {"https://web.globex.test/cb"}}.Encode(), 400, "invalid_request"},
		{"P9 strict", "acme.example.test", formType, strict.Encode(), 400, "invalid_request"},
		{"P9 permissive", "acme.example.test", formType, url.Values{"client_id": {"partner"}, "client_secret": {"partner-secret"}, "response_type": {"code"}, "redirect_uri": {"https://partner.acme.test/cb"}}.Encode(), 400, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.par(t, tc.host, tc.ctype, tc.body)
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", rec.Code, body, tc.status, tc.code)
			}
		})
	}
	t.Run("ten ext allowed", func(t *testing.T) {
		if rec, body := f.par(t, "acme.example.test", formType, tenExt.Encode()); rec.Code != http.StatusCreated {
			t.Fatalf("got %d %v", rec.Code, body)
		}
	})
}
```

Run: `go test ./internal/oauth/ -run PAR`
Expected: build failure (`f.h.OauthPar undefined`).

- [ ] **Step 3: Implement the endpoint**

Create `internal/oauth/par.go`:

```go
package oauth

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// maxPARRequestBytes is Auth0's documented limit for a pushed request.
const maxPARRequestBytes = 10 << 10

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// OauthPar implements POST /oauth/par (RFC 9126, D-0028).
func (h *Handlers) OauthPar(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	out, oerr := h.par(w, r, res)
	if oerr != nil {
		writeError(w, oerr)
		return
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handlers) par(w http.ResponseWriter, r *http.Request, res tenant.Resolved) (*parResponse, *Error) {
	ctx := r.Context()
	t := res.Tenant
	if !t.PushedAuthorizationRequestsSupported {
		return nil, invalidRequest("pushed authorization requests are not enabled for this tenant") // P6b
	}
	form, oerr := parsePARRequest(w, r)
	if oerr != nil {
		return nil, oerr
	}
	c, oerr := h.authenticateClient(ctx, r, form, t.ID)
	if oerr != nil {
		return nil, oerr
	}
	if c.TokenEndpointAuthMethod == store.AuthMethodNone {
		return nil, invalidRequest("only confidential applications may push authorization requests") // P3b
	}
	if !c.IsFirstParty {
		return nil, invalidRequest("pushed authorization requests are not available to third-party applications") // P9
	}
	if form.Has("request_uri") {
		return nil, invalidRequest("request_uri is not allowed in a pushed authorization request") // P6a
	}
	ext := 0
	for k := range form {
		if strings.HasPrefix(k, authz.ExtPrefix) {
			ext++
		}
	}
	if ext > authz.MaxExtParams {
		return nil, invalidRequest(fmt.Sprintf("at most %d ext- parameters are allowed", authz.MaxExtParams)) // P2c
	}

	req := authz.ParseRequest(form)
	req.ClientID, req.Pushed = c.ClientID, true
	if _, verr, _ := authz.ValidateRequest(ctx, h.Store, t, &req); verr != nil {
		if verr.Code == "server_error" {
			return nil, serverError()
		}
		return nil, &Error{Status: parStatus(verr.Code), Code: verr.Code, Description: verr.Description} // P2
	}

	id := secrets.RandomString(64)
	now := h.now().UTC()
	if err := h.Store.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{
		TenantID: t.ID, IDHash: secrets.HashToken(id), ClientID: c.ClientID, Params: req.Params(),
		ExpiresAt: now.Add(authz.PARLifetime), CreatedAt: now,
	}); err != nil {
		h.log().ErrorContext(ctx, "store pushed request", "tenant", t.ID, "client_id", c.ClientID, "err", err)
		return nil, serverError()
	}
	return &parResponse{RequestURI: authz.RequestURIPrefix + id, ExpiresIn: int(authz.PARLifetime.Seconds())}, nil
}

// parStatus is the HTTP status Auth0 uses at /oauth/par for each
// /authorize error code (D-0028).
func parStatus(code string) int {
	switch code {
	case "unauthorized_client", "access_denied":
		return http.StatusForbidden
	case "unsupported_response_type":
		return http.StatusNotImplemented
	default:
		return http.StatusBadRequest
	}
}

// parsePARRequest reads a form-encoded body of at most 10 KB with no
// repeated parameters (P2d, P2e). An oversized body is 413
// payload_too_large, as on Auth0.
func parsePARRequest(w http.ResponseWriter, r *http.Request) (url.Values, *Error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPARRequestBytes)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, invalidRequest("Content-Type must be application/x-www-form-urlencoded")
	}
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, &Error{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Description: "the request body exceeds 10 KB"}
		}
		return nil, invalidRequest("malformed form body")
	}
	for k, vs := range r.PostForm {
		if len(vs) > 1 {
			return nil, invalidRequest(fmt.Sprintf("parameter %q is repeated", k))
		}
	}
	return r.PostForm, nil
}
```

`par.go` imports `errors` as well (for `errors.As`), and no longer needs `access`. If `authz` imports anything that imports `oauth`, `go build` reports an import cycle; it does not today (authz imports access, i18n, secrets, session, store, tenant, ui).

- [ ] **Step 4: Contract and routing**

In `api/authentication.yaml`, after `/oauth/revoke`:

```yaml
  /oauth/par:
    post:
      operationId: oauthPar
      tags: [Tokens]
      summary: Push an authorization request
      description: |
        A confidential application sends its authorization parameters over
        the back channel and receives a `request_uri` to use once at
        `/authorize` within 30 seconds. The application authenticates as at
        `/oauth/token` (client secret only). The tenant must allow pushed
        authorization requests. The body is form-encoded, at most 10 KB, with
        at most 10 `ext-` parameters; other unknown parameters are dropped.
      x-source:
        - https://www.rfc-editor.org/rfc/rfc9126
        - https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-par
        - https://auth0.com/docs/get-started/applications/configure-par
      security:
        - clientSecretBasic: []
        - {}
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              $ref: "#/components/schemas/PushedAuthorizationRequest"
      responses:
        "201":
          description: The request was stored.
          headers:
            Cache-Control: {schema: {type: string, const: no-store}}
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/PushedAuthorizationResponse"
        "400":
          $ref: "#/components/responses/OAuthErrorResponse"
        "401":
          $ref: "#/components/responses/OAuthErrorResponse"
        "403":
          $ref: "#/components/responses/OAuthErrorResponse"
        "404":
          $ref: "#/components/responses/UnknownTenant"
        "413":
          $ref: "#/components/responses/OAuthErrorResponse"
        "501":
          $ref: "#/components/responses/OAuthErrorResponse"
        default:
          $ref: "#/components/responses/ServerError"
```

Under `components.schemas`:

```yaml
    PushedAuthorizationRequest:
      type: object
      description: The `/authorize` parameters, plus client authentication (`client_id`, `client_secret`) and up to 10 `ext-` parameters.
      properties:
        client_id: {type: string}
        client_secret: {type: string}
        response_type: {type: string}
        redirect_uri: {type: string}
        scope: {type: string}
        state: {type: string}
        audience: {type: string}
      additionalProperties: {type: string}
    PushedAuthorizationResponse:
      type: object
      required: [request_uri, expires_in]
      properties:
        request_uri: {type: string, description: "`urn:ietf:params:oauth:request_uri:` followed by an opaque value."}
        expires_in: {type: integer, const: 30}
```

In the `OpenIDConfiguration` schema properties, add (not required):

```yaml
        pushed_authorization_request_endpoint: {type: string, description: Present when the tenant allows pushed authorization requests.}
        request_uri_parameter_supported: {type: boolean, description: "Always false: `request_uri` is accepted only from `/oauth/par`."}
```

Run: `go generate ./internal/gen/...`
Expected: `ServerInterface` gains `OauthPar`. `go build ./...` now fails in `internal/server` (`authAPI` does not implement it).

In `internal/server/server.go`, after `OauthRevoke`:

```go
func (a authAPI) OauthPar(w http.ResponseWriter, r *http.Request)     { a.oauth.OauthPar(w, r) }
```

(No CORS entry and no preflight: PAR is back channel only, for confidential clients.)

- [ ] **Step 5: Discovery**

In `internal/oidc/handlers.go`, add to `Configuration` after `RevocationEndpoint`:

```go
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	// RequestURIParameterSupported is always false (D-0030): request_uri is
	// accepted only from /oauth/par. OIDC Discovery defaults it to true.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
```

In `Discovery`, build the value before writing:

```go
	cfg := Configuration{ /* the existing literal */ }
	if res.Tenant.PushedAuthorizationRequestsSupported {
		cfg.PushedAuthorizationRequestEndpoint = base + "/oauth/par" // P8
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
```

Add to `internal/oidc/handlers_test.go` (the `setup` tenant `acme` has PAR off):

```go
func TestDiscoveryAdvertisesPAROnlyWhenEnabled(t *testing.T) {
	h, _ := setup(t)
	var off map[string]any
	if err := json.Unmarshal(get(h, "https://acme.example.test/.well-known/openid-configuration").Body.Bytes(), &off); err != nil {
		t.Fatal(err)
	}
	if _, ok := off["pushed_authorization_request_endpoint"]; ok {
		t.Fatalf("PAR endpoint advertised for a tenant without PAR: %v", off)
	}
	if v, ok := off["request_uri_parameter_supported"]; !ok || v != false {
		t.Fatalf("request_uri_parameter_supported = %v (present %v); want false", v, ok)
	}

	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_par", Name: "par", Domains: []string{"par.example.test"},
		PushedAuthorizationRequestsSupported: true}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", (&Handlers{}).Discovery)
	hp := contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux))
	var on map[string]any
	if err := json.Unmarshal(get(hp, "https://par.example.test/.well-known/openid-configuration").Body.Bytes(), &on); err != nil {
		t.Fatal(err)
	}
	if on["pushed_authorization_request_endpoint"] != "https://par.example.test/oauth/par" {
		t.Fatalf("pushed_authorization_request_endpoint = %v", on["pushed_authorization_request_endpoint"])
	}
}
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/oauth/ ./internal/oidc/ ./internal/server/ ./internal/authz/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/oauth internal/oidc internal/server api internal/gen
git commit -m "feat(oauth): POST /oauth/par; discovery advertises the PAR endpoint"
```

---

### Task 8: E2E with Auth0's SDKs (m10-par)

**Files:**
- Modify: `tests/e2e/seed.yaml`, `tests/e2e/run-browser.sh`, `tests/e2e/next-app/lib/auth0.js`
- Create: `tests/e2e/m10-par.spec.mjs`
- Modify: `docs/compat/blackbox-clients.md`

**Interfaces:**
- Consumes: the whole server.
- Produces: E2E clients `e2e-par-web` (express-openid-connect, port 3004), `e2e-next-par` (nextjs-auth0, port 3002), `e2e-par-authjs` (auth0-auth-js, callback intercepted).

- [ ] **Step 1: Seed**

In `tests/e2e/seed.yaml`, tenant `e2e`: add `pushed_authorization_requests_supported: true`. Add clients:

```yaml
      - client_id: e2e-par-web
        name: E2E PAR express-openid-connect
        app_type: regular_web
        client_secret: e2e-par-web-secret-not-for-production
        token_endpoint_auth_method: client_secret_basic # express-openid-connect's default
        require_pushed_authorization_requests: true
        grant_types: [authorization_code]
        callbacks: ["http://localhost:3004/callback"]
        allowed_logout_urls: ["http://localhost:3004"]
      - client_id: e2e-next-par
        name: E2E PAR Next.js
        app_type: regular_web
        client_secret: e2e-next-par-secret-not-for-production
        token_endpoint_auth_method: client_secret_post
        require_pushed_authorization_requests: true
        grant_types: [authorization_code, refresh_token]
        callbacks: ["http://localhost:3002/auth/callback"]
        allowed_logout_urls: ["http://localhost:3002", "http://localhost:3002/"]
      - client_id: e2e-par-authjs
        name: E2E PAR auth0-auth-js
        app_type: regular_web
        client_secret: e2e-par-authjs-secret-not-for-production
        token_endpoint_auth_method: client_secret_post
        require_pushed_authorization_requests: true
        grant_types: [authorization_code]
        callbacks: ["https://par.e2e.invalid/cb"]
```

Add the three client IDs to `Username-Password-Authentication`'s `enabled_clients`.

- [ ] **Step 2: A second Next.js instance with PAR**

`tests/e2e/next-app/lib/auth0.js`: add to the `Auth0Client` options:

```js
  // run-browser.sh starts a second instance with E2E_PAR=1 for m10-par.
  pushedAuthorizationRequests: process.env.E2E_PAR === '1',
```

`tests/e2e/run-browser.sh`, after the existing `next start` block:

```bash
AUTH0_DOMAIN=https://localhost:8443 AUTH0_CLIENT_ID=e2e-next-par \
  AUTH0_CLIENT_SECRET=e2e-next-par-secret-not-for-production \
  AUTH0_SECRET="$(openssl rand -hex 32)" APP_BASE_URL=http://localhost:3002 E2E_PAR=1 \
  NODE_EXTRA_CA_CERTS="$work/cert.pem" \
  npx next start next-app -p 3002 >"$work/next-par.log" 2>&1 &
pids+=($!)
```

and extend the readiness line with `&& wait_for http://localhost:3002/`.

- [ ] **Step 3: Write the spec**

Create `tests/e2e/m10-par.spec.mjs`:

```js
// Black-box test (CLEAN_ROOM.md): Auth0's SDKs against zeroauthy's pushed
// authorization requests. Every client here requires PAR, so a login that
// succeeds proves the SDK pushed its request.
import { test, expect } from '@playwright/test';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import express from 'express';
import oidcSdk from 'express-openid-connect'; // CommonJS: no named exports under ESM
const { auth: oidc, requiresAuth } = oidcSdk;
import { AuthClient } from '@auth0/auth0-auth-js';

const IDP = 'https://localhost:8443';
const CALLBACK = 'https://par.e2e.invalid/cb';

async function login(page) {
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  await page.click('button[type=submit]');
}

// The browser never reaches the made-up callback host: Playwright answers it.
async function captureCallback(page) {
  await page.route(`${CALLBACK}**`, (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'ok' }));
}

function authorizeRequests(page) {
  const seen = [];
  page.on('request', (r) => { if (r.url().startsWith(`${IDP}/authorize`)) seen.push(new URL(r.url())); });
  return seen;
}

test('discovery advertises the PAR endpoint', async () => {
  const d = await (await fetch(`${IDP}/.well-known/openid-configuration`)).json();
  expect(d.pushed_authorization_request_endpoint).toBe(`${IDP}/oauth/par`);
});

test('express-openid-connect logs in through PAR', async ({ page }) => {
  const app = express();
  app.use(oidc({
    issuerBaseURL: IDP, baseURL: 'http://localhost:3004', clientID: 'e2e-par-web',
    clientSecret: 'e2e-par-web-secret-not-for-production', secret: randomBytes(32).toString('hex'),
    authRequired: false, pushedAuthorizationRequests: true,
    authorizationParams: { response_type: 'code', scope: 'openid profile email' },
  }));
  app.get('/me', requiresAuth(), (req, res) => res.json(req.oidc.user));
  const server = app.listen(3004, '127.0.0.1');
  await once(server, 'listening');
  try {
    const seen = authorizeRequests(page);
    await page.goto('http://localhost:3004/me');
    await login(page);
    await page.waitForURL('http://localhost:3004/me');
    expect(JSON.parse(await page.locator('body').innerText()).email).toBe('alice@e2e.local');
    expect(seen[0].searchParams.get('request_uri')).toMatch(/^urn:ietf:params:oauth:request_uri:/);
  } finally {
    server.close();
  }
});

test('nextjs-auth0 logs in through PAR', async ({ page }) => {
  const seen = authorizeRequests(page);
  await page.goto('http://localhost:3002/');
  await page.click('#login');
  await login(page);
  await page.waitForURL('http://localhost:3002/');
  await expect(page.locator('#email')).toHaveText('alice@e2e.local');
  expect(seen[0].searchParams.get('request_uri')).toMatch(/^urn:ietf:params:oauth:request_uri:/);
});

test('auth0-auth-js: PAR URL, code exchange, and a used request_uri is refused', async ({ page }) => {
  const client = new AuthClient({
    domain: 'localhost:8443', clientId: 'e2e-par-authjs', clientSecret: 'e2e-par-authjs-secret-not-for-production',
    authorizationParams: { redirect_uri: CALLBACK, scope: 'openid profile email' },
  });
  const { authorizationUrl, codeVerifier } = await client.buildAuthorizationUrl({ pushedAuthorizationRequests: true });
  expect(authorizationUrl.searchParams.get('request_uri')).toMatch(/^urn:ietf:params:oauth:request_uri:/);

  await captureCallback(page);
  await page.goto(authorizationUrl.toString());
  await login(page);
  await page.waitForURL(new RegExp(`^${CALLBACK}\\?code=`));
  const tokens = await client.getTokenByCode(new URL(page.url()), { codeVerifier });
  expect(tokens.idToken).toBeTruthy();

  // The same request_uri a second time: an error page at zeroauthy, no redirect.
  const r = await page.goto(authorizationUrl.toString());
  expect(r.status()).toBe(400);
  expect(page.url()).toContain('localhost:8443/authorize');
});

test('a client that requires PAR cannot use a plain /authorize', async ({ page }) => {
  await captureCallback(page);
  await page.goto(`${IDP}/authorize?` + new URLSearchParams({
    client_id: 'e2e-par-authjs', redirect_uri: CALLBACK, response_type: 'code', scope: 'openid', state: 's1',
  }));
  await page.waitForURL(new RegExp(`^${CALLBACK}`));
  const u = new URL(page.url());
  expect(u.searchParams.get('error')).toBe('invalid_request');
  expect(u.searchParams.get('state')).toBe('s1');
});
```

If auth0-auth-js 1.16 takes `pushedAuthorizationRequests` only in the constructor options rather than in `buildAuthorizationUrl` options, check `node_modules/@auth0/auth0-auth-js/dist/index.d.ts` (the field is declared near line 368) and move it accordingly. If Task 1 changed P4a or P5, adjust the last two tests' expectations to the observed outcome.

- [ ] **Step 4: Run the browser suite**

Run: `./tests/e2e/run-browser.sh`
Expected: every spec passes, including the four new tests and the unchanged m5 Next.js test on port 3000 (no PAR).

On failure, read `next-par.log` and `server.log` in the printed output. If an SDK rejects the PAR response, compare the JSON with RFC 9126 §2.2 (status 201, `request_uri` string, `expires_in` number).

- [ ] **Step 5: Record the black-box clients**

In `docs/compat/blackbox-clients.md`, add rows (same columns as the m10 consent rows) for express-openid-connect, nextjs-auth0 and auth0-auth-js with PAR: SDK option used (`pushedAuthorizationRequests: true`), client, what the test proves.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e docs/compat/blackbox-clients.md
git commit -m "test(e2e): pushed authorization requests with express-openid-connect, nextjs-auth0 and auth0-auth-js"
```

---

### Task 9: Documentation and final verification

**Files:**
- Create: `docs/par.md`
- Modify: `docs/compat/matrix.md`, `docs/compat/changelog-review.md`, `docs/superpowers/plan-1-followups.md`, `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`, `README.md` (only if it lists endpoints)

- [ ] **Step 1: Write the guide**

Create `docs/par.md` in the style of `docs/consent.md` (original wording):
- What PAR is and when to use it (back channel, tamper-proof parameters, no URL length limits).
- Enabling: tenant `pushed_authorization_requests_supported: true`; per client `require_pushed_authorization_requests: true` (confidential, first-party or permissive; not strict third-party). A seed example with one tenant and one client.
- Using it: SDK options (`pushedAuthorizationRequests: true` in express-openid-connect, nextjs-auth0 and auth0-auth-js) and a curl example of `POST /oauth/par` followed by the `/authorize` URL.
- Limits: 30-second lifetime, single use, 10 KB, 10 `ext-*` parameters, client-secret authentication only; other query parameters at `/authorize` are ignored (or the observed P1 rule).
- Storage plugins: plugins built before Plan 10 cannot store pushed requests; upgrade them before enabling PAR.
- Differences from Auth0, citing D-0028–D-0030.

- [ ] **Step 2: Matrix, changelog review, follow-ups, core spec**

- `docs/compat/matrix.md`: rows for `POST /oauth/par`, `request_uri` at `/authorize`, `require_pushed_authorization_requests`, the tenant setting and `pushed_authorization_request_endpoint`, each with status and the decision IDs.
- `docs/compat/changelog-review.md`: a review-log row dated 2026-10-16, "Claude (Plan 10 planning)": no PAR entries; one new entry since the previous review (Universal Login identifier and phone controls, 2026-10-16, early access), recorded under Relevant entries with impact `backlog`, target sub-project 2.
- `docs/superpowers/plan-1-followups.md`: a "Plan 10 follow-ups" section with every item from this plan's Out of Scope list.
- Core spec: §6.1 `/oauth/par` row: "RFC 9126; see the PAR design (Plan 10)"; §6.2 `request_uri` row: "From PAR; replaces every other parameter except `client_id` (D-0029)"; §13 item 10: "PAR shipped in Plan 10; device flow remains (Plan 11)."
- PAR spec: set **Status** to "Implemented (Plan 10)".

- [ ] **Step 3: Full verification**

Run: `gofmt -l . && go vet ./... && go test -race ./... && CGO_ENABLED=0 go build ./... && go generate ./... && git status --short`
Expected: no gofmt output, vet clean, all tests pass, build succeeds, `git status` shows only the docs edited in this task.

Run: `./scripts/test-sql.sh ./internal/store/... ./pkg/...`
Expected: PASS on sqlite, postgres and mysql.

Run: `./tests/e2e/run-browser.sh` and `./tests/e2e/run-m3.sh`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add docs README.md
git commit -m "docs: PAR guide, matrix, follow-ups and spec for Plan 10"
```
