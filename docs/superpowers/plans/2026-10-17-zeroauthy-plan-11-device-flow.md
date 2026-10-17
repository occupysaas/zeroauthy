# zeroauthy Plan 11: Device Authorization Flow (Milestone 10, part 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Native app gets a `device_code` and a short `user_code` from `POST /oauth/device/code` and polls `/oauth/token`. The user opens `/activate` on another device, enters and confirms the code, logs in and consents, and the app receives tokens, as on Auth0.

**Architecture:**
- **Storage:** a new `DeviceCodes` repository with atomic `Decide` and `Poll`, plus the tenant's `device_flow` settings. It is implemented in every driver: memory, SQL migration 0005, and the gRPC plugin protocol. The sweeper keeps expired device codes for 24 hours.
- **`internal/devicecode` (new):** user-code generation, normalization and display formatting from the tenant's charset and mask. It is pure code.
- **`internal/oauth`:**
  - `POST /oauth/device/code` (`device.go`).
  - The `urn:ietf:params:oauth:grant-type:device_code` grant (`grant_device_code.go`), which mints tokens through the existing `mintUserTokens`.
- **`internal/access`** gains a `Device` flow kind.
- **`internal/authz`:**
  - The end of the browser flow is refactored around a `flowReq`: an `/authorize` `Request` plus an optional device code hash. Session reuse, login, the access decision and consent are shared.
  - Only the last step differs: `/authorize` issues a code or redirects with an error, while the device flow calls `DeviceCodes().Decide` and renders a result page.
- **`internal/login`:**
  - `/activate` (code entry), `/device/confirmation`, `/device/success` and `/device/denied`, the paths Auth0 uses.
  - Three in-process throttles: per transaction, per IP and per tenant.
- **Task 1 settles the values the docs leave open (D1–D11)** on the maintainer's trial tenant before any code is written.

**Tech Stack:**
- Go 1.26+, no new Go dependencies.
- E2E:
  - Auth0's .NET Authentication API client `Auth0.AuthenticationApi` 7.49.0 (NuGet, published 2026-08-19), run in the `mcr.microsoft.com/dotnet/sdk:10.0.400-noble` image with podman.
  - Playwright 1.64 (already pinned) for the browser side.

**Spec:** `docs/superpowers/specs/2026-10-17-zeroauthy-device-flow-design.md` (approved 2026-10-17). Also core spec §6 and §13.

**Auth0 sources** (public docs; read them, never copy them):
- https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow
- https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow/call-your-api-using-the-device-authorization-flow
- https://auth0.com/docs/get-started/tenant-settings/configure-device-user-code-settings
- https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements (prompt `device-flow`: key names only)
- RFC 8628, RFC 8414 §2

## Global Constraints

- **Earlier constraints still apply:**
  - Drivers return copies, and every atomic operation is a single store method.
  - `go test -race ./...`, `go vet ./...` and `gofmt -l .` stay clean, and `go generate ./...` produces no diff.
  - `CGO_ENABLED=0 go build ./...` works.
  - SQL tests run with `./scripts/test-sql.sh <pkgs>` (podman; `ZA_TEST_POSTGRES_DSN` / `ZA_TEST_MYSQL_DSN`). Never install databases on the host. If ports 55432/53306 are taken, use a copy of the script on other ports (a known follow-up).
- **Wire names are Auth0's:**
  - endpoint `/oauth/device/code`
  - grant `urn:ietf:params:oauth:grant-type:device_code`
  - response fields `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`
  - tenant setting `device_flow: {charset: base20|digits, mask}`
  - discovery `device_authorization_endpoint`
  - custom-text prompt `device-flow`, with screens `device-code-activation`, `device-code-confirmation`, `device-code-activation-allowed` and `device-code-activation-denied`
- **Fixed values (documented or observed):**
  - `expires_in` 900, `interval` 5. Neither is configurable.
  - `slow_down` only for polls less than 1 second after the last accepted poll; the interval never grows and no `interval` key is returned (observed, D9).
  - User code minimum 8 characters (base20) or 9 (digits). Maximum 20 including separators.
  - Device clients: `app_type: native`, `token_endpoint_auth_method: none`, first party only (the Management API refuses the grant otherwise).
- **Secrets at rest:**
  - `device_code` is 24 characters from `secrets.RandomString` (observed length) and is stored only as `secrets.HashToken`.
  - The user code is stored only as `secrets.HashToken(devicecode.Normalize(code))`.
- **Defaults are safe for old data:** the new tenant columns default to `''`, which means base20 and `****-****`. Plugins that predate the proto fields decode them as `''` too.
- **Rate limits are ours (D-0034):** Auth0 publishes no numbers, and Task 1 must not probe them. Task 1 tries at most a handful of wrong codes.
- **Clean room:**
  - Task 1 records facts only: status codes, `error` values, URL paths and parameter names, screen types and their order.
  - No messages, screenshots, tenant domains, IDs or secrets.
  - The English catalog text is our own wording. Only the key names come from Auth0's docs.

## Observation-dependent values

Task 1 ran on 2026-10-17 (`docs/compat/observations/device-flow.md`, D-0031–D-0034). **The task text in Tasks 2–10 already uses the observed values**; the table records where they came from. Also observed and applied: `device_code` is 24 characters; device ID tokens carry no `sid` and no `auth_time` (Task 7); the result pages are `/device/success` and `/device/denied` (Tasks 8, 9).

| # | Question | Default | Where | Observed |
|---|---|---|---|---|
| D1 | `/activate` redirect shape; whether `verification_uri_complete` skips entry and still shows confirmation | `/activate` → 302 `/u/device?state=…`; with `?user_code=` → 302 `/u/device/confirm?state=…`; confirmation always shows | `Activate` (Task 9) || `/activate` serves the form itself (no redirect), posting `state`+`code` back to `/activate`; valid code → 302 `/device/confirmation?state=`; `?user_code=` → 302 straight to confirmation, which always shows → **change (Task 9)** |
| D2 | Default charset and mask; alphabet seen in base20 codes; separators accepted in the mask; case-insensitive entry; code accepted without separator | `base20`, `****-****`; `BCDFGHJKLMNPQRSTVWXZ`; `-` and space; yes; yes | `devicecode` (Task 5), seed (Task 5) || no `device_flow` key by default; codes `XXXX-XXXX` from exactly `BCDFGHJKLMNPQRSTVWXZ`; lower case without hyphen accepted. Separators in custom masks not tried (kept default) |
| D3 | `/oauth/device/code` for: a client without the grant; a confidential client; an unknown audience; an empty `audience=`; a `deny_all` API | `403 unauthorized_client`; `403 unauthorized_client`; `403 access_denied`; treated as absent; issued (policy checked after login) | `deviceCode` (Task 6) || **without grant / unknown client / repeated client_id: `403 unauthorized_client`; unknown audience and `deny_all` API: `400 invalid_request` at issue time; empty audience = absent; JSON body accepted; Management API refuses non-native, non-`none` and third-party device clients → change (Tasks 5, 6)** |
| D4 | Consent: a first-party client on an API with `skip_consent_for_verifiable_first_party_clients`; a returning user; a first-party client with no audience | consent shows; no consent; no consent | `deviceFirstPartyConsent` (Task 8) || **skip-consent API: no consent; non-skip API: consent via `/authorize/resume` → `/u/consent` → change (Task 8: no device-specific consent constant)** |
| D5 | Status of `expired_token`; of the later `invalid_grant`; of an unknown `device_code` | `400`; `400`; `400 invalid_grant` | `deviceCodeGrant` (Task 7) || **`403 expired_token` once, a few seconds after expiry, then `403 invalid_grant`; unknown code `403 invalid_grant`; first poll 11 min after expiry: `invalid_grant` (window not modelled, D-0031) → change (Task 7: all 403)** |
| D6 | Discovery fields | `device_authorization_endpoint` present; the grant listed in `grant_types_supported` | `Discovery` (Task 6) || as default |
| D7 | Entry page: wrong code; expired code; already-used code; empty submit | `invalid-code`; `invalid-expired-code`; `invalid-expired-code`; `no-code` (the catalog keys) | `DeviceSubmit` (Task 9) || **wrong, expired and used codes: the same "invalid or expired" message, 400; empty: `no-code` → change (Task 9)** |
| D8 | Device result after cancelling at confirmation; after declining consent | `403 access_denied` for both | `refuse` (Task 8), `DeviceConfirmSubmit` (Task 9) || cancel → 302 `/device/denied`; consent decline → `/authorize/resume` → `/device/denied`; poll: `403 access_denied` **once, then `403 invalid_grant` → change (Tasks 2, 7)** |
| D9 | `slow_down` interval growth; whether the interval is measured from the last poll | +5 s per `slow_down`; from the last poll's arrival | `Poll` (Task 2) || **polls 1 s apart: never `slow_down`; back-to-back burst: `slow_down` on alternate polls; no `interval` key → change (Tasks 2, 7: 1 s minimum gap, no growth)** |
| D10 | Code entered in a browser with a live session | Session reused silently; confirmation still shows | `ContinueDevice` (Task 8) || as default (no login screen, straight to `/device/success`) |
| D11 | A permissive third-party Native client with the device grant | Allowed; consent shows | seed (Task 5), `Decide` (Task 8) || **not observable: the Management API refuses the device grant for every third-party client, and permissive mode cannot be set → change (Task 5: refuse all third-party)** |

## Review Focus

1. **auth0.net sends `audience=` and `scope=` even when unset.** `StartDeviceFlowAsync` always puts both keys in the body. An empty `audience` must mean "no audience", which then falls back to the tenant default as at `/authorize`. It must never mean an unknown audience. Pinned in Task 6 (`TestDeviceCodeEmptyAudienceIsAbsent`).
2. **A client that polls faster than `interval`** (auth0-cli polls at interval+1 s, others at 1–2 s) must not be punished more than Auth0 does: polls 1 second apart never get `slow_down`. "Too early" is strictly less than `MinPollGap` (1 s) since the last accepted poll. Pinned in storetest `PollBoundary` (Task 2).
3. **Users type codes however they like:** lower case, no dash, spaces, a trailing newline from paste, or `bcdf-ghjk` for `BCDF-GHJK`. All must match. Pinned in Task 5 (`TestNormalize`) and Task 9 (`TestDeviceSubmitAcceptsLooseFormatting`).
4. **Double submits and two tabs.** A second confirm, or the same code entered in two tabs, gets `ErrAlreadyUsed` from `Decide`. It must show the entry page's expired/used error, and never flip an approved code to denied. Pinned in Task 8 (`TestDeviceDecideTwiceKeepsFirst`) and Task 9 (`TestDeviceConfirmTwice`).
5. **An old storage plugin without the `DeviceCodes` RPCs.** The sweeper calls `DeviceCodes().DeleteExpired` every 10 minutes on every deployment. It must not fail the other sweeps. Pinned in Task 4 (`TestOldPluginDeviceCodesSweep`).

---

## Out of Scope

Task 11 adds these to `docs/superpowers/plan-1-followups.md` under "Plan 11 follow-ups":
- A sample Android TV app: the Android Studio TV emulator reaching zeroauthy at `10.0.2.2`, then a sideloaded Fire TV.
- `auth0-cli` as a device-flow client. It hardcodes `auth0.auth0.com`, its client ID and issuer, so testing it needs that host mapped to zeroauthy in a container with a trusted test certificate.
- Management API for `device_flow` (sub-project 3). Tenant log events `fdeaz`, `fdeac`, `fdecc`, `fede`, `sede`. Actions/Rules `oauth2-device-code` protocol.
- An Authentication API rate limiter covering `/oauth/device/code`, and throttle state shared across instances.
- Running `m10-device` with `E2E_IN_CONTAINER=1` (it needs podman on the host to start the .NET client).

## File Structure

| File | Responsibility |
|---|---|
| `docs/compat/observations/device-flow.md` (new) | Task 1 facts |
| `docs/compat/decisions.md` | D-0031 endpoint and grant; D-0032 browser path and consent; D-0033 settings, seed rules, discovery; D-0034 rate-limit defaults (deliberate) |
| `internal/store/types.go`, `store.go`, `pkg/store/store.go` | `DeviceCode`, `DeviceDecision`, `DevicePoll`, `DeviceCodes`, tenant fields |
| `internal/store/memory/device_codes.go` (new), `memory.go`, `tx.go`, `clone.go` | Memory driver |
| `pkg/storetest/device_codes.go` (new), `storetest.go`, `sweep.go`, `tenants.go` | Conformance |
| `internal/app/sweeper.go`, `sweeper_test.go` | Expiry sweep with retention |
| `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0005_device_codes.sql` (new), `device_codes.go` (new), `tenants.go`, `migrate_test.go` | SQL driver |
| `proto/store/v1/store.proto` (+ generated), `internal/store/grpcstore/*` | Plugin protocol |
| `internal/devicecode/devicecode.go` (new), test | User codes |
| `internal/identity/throttle.go`, `internal/config/config.go`, `internal/app/app.go`, `internal/server/server.go` | Disabled throttle, config, wiring, routes |
| `internal/seed/{seed,validate,apply}.go`, `seed_test.go` | Seed |
| `internal/oauth/device.go` (new), `grant_device_code.go` (new), `token.go`, `refresh.go`, tests | Endpoint and grant |
| `internal/oidc/handlers.go`, test; `api/authentication.yaml`, `internal/gen/authapi/*` | Discovery, contract |
| `internal/access/access.go`, `observed.go`, test | `Device` flow |
| `internal/authz/flow.go` (new), `device.go` (new), `handlers.go`, tests | Shared completion, device continuation |
| `internal/login/device.go` (new), `consent.go`, test | Browser pages |
| `internal/ui/ui.go`, `templates/device_code.html`, `device_confirm.html`, `device_result.html` (new), `consent.html` | Rendering |
| `internal/i18n/locales/en.json`, `keys.go` | Catalog |
| `tests/e2e/dotnet-device/{DeviceE2E.csproj,Program.cs}` (new), `m10-device.spec.mjs` (new), `seed.yaml`, `run-browser.sh` | E2E |
| `docs/device-flow.md` (new), `docs/compat/{matrix,blackbox-clients,changelog-review}.md`, followups, core spec, design spec status | Docs |

---

### Task 1: Observe the open points on the maintainer's trial tenant

This task needs the maintainer. Claude runs Management API calls with auth0-cli and back-channel calls with curl. The maintainer opens browser URLs and reports only paths, parameter names and screen types. No code changes in this task.

**Files:**
- Create: `docs/compat/observations/device-flow.md`
- Modify: `docs/compat/decisions.md` (append D-0031–D-0034); this plan's Observed column

**Interfaces:**
- Produces: observed values for D1–D11, used by Tasks 2–10.

- [ ] **Step 1: Point auth0-cli at the trial tenant.** Ask the maintainer to run `! auth0 login` and choose the trial tenant. Keep the domain in a fish variable for this session only (`set -x OBS …`, as in Plan 10 Task 1). Never write it into the repository.

- [ ] **Step 2: Settings and discovery (D2 defaults, D6).** Record only the key names and the values of `charset` and `mask`:

```bash
auth0 api get tenants/settings | python3 -c 'import json,sys; print(json.load(sys.stdin).get("device_flow"))'
curl -s "https://$OBS/.well-known/openid-configuration" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("device_authorization_endpoint") is not None, [g for g in d.get("grant_types_supported",[]) if "device" in g])'
```

- [ ] **Step 3: Create the test objects** with `auth0 api post`:
  - a Native client `za-obs-device`: `token_endpoint_auth_method: none`, grants `[device_code URN, refresh_token]`, first party
  - a regular web client `za-obs-web` with a secret and the device grant requested (D3: confidential); record whether the Management API itself refuses this, and if so record that instead
  - a Native client without the grant
  - a permissive third-party Native client with the grant (D11)
  - an API `https://za-obs-device.example` with `skip_consent_for_verifiable_first_party_clients: true`, `allow_offline_access: true`
  - an API with `subject_type_authorization.user.policy: deny_all`

  Enable a database connection for the clients. Ask the maintainer to create a test user in the dashboard (no real personal data).

- [ ] **Step 4: Back-channel checks (D3, D5, D9).** One curl per case. Record the status and `error` only.
  - `/oauth/device/code` for each client in Step 3, plus: an unknown audience, `audience=` empty, the deny_all API.
  - With a fresh code: poll twice 1 s apart (D9: `slow_down`?), then poll at the returned interval and record any `interval` field.
  - Leave one code to expire (15 minutes), then poll it three times (D5).
  - Poll an unknown `device_code`.

- [ ] **Step 5: Browser checks (D1, D2, D4, D7, D8, D10).** For each case, Claude creates a fresh code and gives the maintainer the URL. The maintainer reports the address-bar path (no host, parameter names only) and the screen type at each step:
  - `verification_uri`, enter a wrong code, then the code in lower case without the dash (D7, D2)
  - `verification_uri_complete` (D1)
  - cancel at confirmation, then poll (D8)
  - accept through login and consent with the first-party client and the skip-consent API; repeat with a second code as the same user in the same browser (D4, D10)
  - a code for a client with no audience (D4)
  - decline consent with the third-party client, then poll (D8, D11)
  - one expired code entered at `verification_uri` (D7)
  - after approval, poll twice (consumed → ?)

- [ ] **Step 6: Tear down** the objects from Step 3 and the test user.

- [ ] **Step 7: Write `docs/compat/observations/device-flow.md`** in the format of `observations/par.md`: date, endpoints, doc URLs, and one line per D-point. Facts only.

- [ ] **Step 8: Record decisions** in `docs/compat/decisions.md`:
  - D-0031: `/oauth/device/code` and the grant, statuses
  - D-0032: browser path, consent and session reuse
  - D-0033: `device_flow` settings, seed rules, discovery
  - D-0034: zeroauthy's own rate-limit defaults (§5 of the design), as a deliberate deviation: Auth0 publishes none and probing is not allowed

  Each lists sources and the observation.

- [ ] **Step 9: Fill the Observed column** of this plan. Mark each changed row "→ change (Task N)".

- [ ] **Step 10: Commit**

```bash
git add docs/compat/observations/device-flow.md docs/compat/decisions.md docs/superpowers/plans/2026-10-17-zeroauthy-plan-11-device-flow.md
git commit -m "docs(compat): observe the device flow on the maintainer's tenant"
```

---

### Task 2: Store types, the memory driver, conformance and the sweep

**Files:**
- Modify: `internal/store/types.go`, `internal/store/store.go`, `pkg/store/store.go`
- Create: `internal/store/memory/device_codes.go`; modify `memory.go`, `tx.go`, `clone.go`
- Create: `pkg/storetest/device_codes.go`; modify `pkg/storetest/storetest.go`, `sweep.go`, `tenants.go`
- Modify: `internal/app/sweeper.go`, `internal/app/sweeper_test.go`

**Interfaces:**
- Produces (in `internal/store`, aliased in `pkg/store`):

```go
// Tenant gains (empty = defaults: base20, "****-****"):
DeviceFlowCharset string // "base20" | "digits"
DeviceFlowMask    string

type DeviceCodeStatus string

const (
	DeviceCodePending  DeviceCodeStatus = "pending"
	DeviceCodeApproved DeviceCodeStatus = "approved"
	DeviceCodeDenied   DeviceCodeStatus = "denied"
	DeviceCodeConsumed DeviceCodeStatus = "consumed"
)

type DeviceCode struct {
	TenantID          string
	DeviceCodeHash    string // secrets.HashToken(device_code)
	UserCodeHash      string // secrets.HashToken(devicecode.Normalize(user_code))
	ClientID          string
	Scopes            []string // requested
	Audience          string   // resolved audience; "" for none
	Status            DeviceCodeStatus
	UserID            string     // set by Decide(approved)
	GrantedScopes     []string   // set by Decide(approved)
	// LastPolledAt is the last poll that was not answered slow_down.
	LastPolledAt      *time.Time
	ExpiredReportedAt *time.Time
	ExpiresAt         time.Time
	CreatedAt         time.Time
}

// Device tokens are not bound to the browser session: Auth0's device ID
// tokens carry no sid and no auth_time (observations/device-flow.md), so
// no session ID or auth time is recorded.
type DeviceDecision struct {
	Status        DeviceCodeStatus // DeviceCodeApproved or DeviceCodeDenied
	UserID        string
	GrantedScopes []string
}

type DevicePollOutcome string

const (
	PollPending  DevicePollOutcome = "pending"   // authorization_pending
	PollSlowDown DevicePollOutcome = "slow_down" // too soon after the last accepted poll
	PollApproved DevicePollOutcome = "approved"  // this poll consumed an approved code: issue tokens
	PollDenied   DevicePollOutcome = "denied"    // this poll consumed a denied code: access_denied once
	PollExpired  DevicePollOutcome = "expired"   // first poll after expiry: expired_token (D5)
	PollInvalid  DevicePollOutcome = "invalid"   // consumed, or expired and already reported
)

// MinPollGap is the shortest gap between accepted polls (D9: Auth0 never
// answered slow_down to polls 1 s apart).
const MinPollGap = time.Second

// DevicePoll is the outcome of one poll. Code is the record after the poll.
type DevicePoll struct {
	Code    *DeviceCode
	Outcome DevicePollOutcome
}

// DeviceCodes stores device authorization requests, keyed by
// (TenantID, DeviceCodeHash). UserCodeHash is unique within a tenant.
type DeviceCodes interface {
	// Create returns ErrConflict if DeviceCodeHash or UserCodeHash exists in the tenant.
	Create(ctx context.Context, d *DeviceCode) error
	Get(ctx context.Context, tenantID, deviceCodeHash string) (*DeviceCode, error)
	GetByUserCode(ctx context.Context, tenantID, userCodeHash string) (*DeviceCode, error)
	// Decide atomically moves a pending code to dec.Status and records the
	// decision. Any other status returns the record and ErrAlreadyUsed.
	// Unknown codes return ErrNotFound. Expiry is the caller's check.
	Decide(ctx context.Context, tenantID, deviceCodeHash string, dec DeviceDecision) (*DeviceCode, error)
	// Poll atomically records a poll at `at` (see DevicePoll). Unknown codes
	// return ErrNotFound.
	Poll(ctx context.Context, tenantID, deviceCodeHash string, at time.Time) (DevicePoll, error)
	// DeleteExpired removes, in every tenant, the codes whose ExpiresAt is
	// not after before, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
// Store gains: DeviceCodes() DeviceCodes
```

**`Poll` rules, in this order** (D5, D8, D9):
1. Status `consumed` → `PollInvalid`, nothing changes.
2. If `!at.Before(ExpiresAt)`: if `ExpiredReportedAt` is nil, set it to `at` and return `PollExpired`; otherwise `PollInvalid` (D5).
3. Else if `LastPolledAt != nil` and `at.Sub(*LastPolledAt) < MinPollGap` → `PollSlowDown`. `LastPolledAt` is **not** updated (the observed alternation: slow_down, then an accepted poll).
4. Else set `LastPolledAt = at`. `pending` → `PollPending`. `approved` → status `consumed`, `PollApproved`. `denied` → status `consumed`, `PollDenied`.

- [ ] **Step 1: Write the conformance suite** `pkg/storetest/device_codes.go`, registered in `storetest.go` under the name `DeviceCodes`. Subtests and their assertions:
  - `CreateGet`: create, then `Get` and `GetByUserCode` return equal copies; mutating the returned copy does not change the stored one.
  - `CreateConflict`: the same `DeviceCodeHash` → `ErrConflict`; a different device hash with the same `UserCodeHash` in the same tenant → `ErrConflict`; the same user hash in another tenant → ok.
  - `DecideOnce`: `Decide(approved, user u1, scopes [openid])` returns status `approved` with those fields. A second `Decide(denied)` → `ErrAlreadyUsed`, and the status stays `approved`. Unknown → `ErrNotFound`.
  - `ConcurrentDecide`: 10 goroutines call `Decide` (half approve, half deny); exactly one succeeds.
  - `PollPending`: first poll → `PollPending`, `LastPolledAt` set; poll at +300 ms → `PollSlowDown`, `LastPolledAt` unchanged; poll at +1 s (from the first) → `PollPending`.
  - `PollBoundary`: poll at t, then at exactly t+1 s → `PollPending`.
  - `PollApprovedOnce`: approve, then poll → `PollApproved`, status `consumed`; poll again 2 s later → `PollInvalid`.
  - `PollDeniedOnce`: deny, then poll → `PollDenied`, status `consumed`; again 2 s later → `PollInvalid`.
  - `ConcurrentPollApproved`: 10 goroutines poll an approved code at the same instant `at` with no previous poll; exactly one gets `PollApproved`. Assert on that only: the rest may be `PollSlowDown` or `PollInvalid`.
  - `PollExpired`: poll at `ExpiresAt` → `PollExpired`; again → `PollInvalid`; `ExpiredReportedAt` unchanged.
  - `DeleteExpired`: removes only codes with `ExpiresAt <= before`, in every tenant; returns the count.
  - Add `DeviceFlowCharset` and `DeviceFlowMask` to the tenant round-trip in `tenants.go`. Add device codes to `sweep.go`'s expiry check.

- [ ] **Step 2: Run** `go test ./internal/store/memory/ -run 'TestConformance/DeviceCodes'`. Expected: build failure (no types).

- [ ] **Step 3: Add the types and the interface** as in Interfaces, and the `pkg/store` aliases.

- [ ] **Step 4: Implement the memory driver** in `internal/store/memory/device_codes.go`, following `pushed_auth_requests.go`: deep copies (`clone.go`), transaction staging (`tx.go`), and one mutex section for each of `Decide` and `Poll`.

- [ ] **Step 5: Run** `go test -race ./internal/store/memory/ ./pkg/storetest/...`. Expected: PASS.

- [ ] **Step 6: Sweep with retention.** In `internal/app/sweeper.go`, add `deviceCodeRetention = 24 * time.Hour` (comment: keeps an expired code so the device's next poll gets `expired_token` once) and the job `{st.DeviceCodes().DeleteExpired, now.Add(-deviceCodeRetention)}`. Extend `TestSweepRemovesExpiredRecords`:
  - a device code that expired 1 hour ago survives
  - a device code that expired 25 hours ago is removed

  Run `go test ./internal/app/`. Expected: PASS.

- [ ] **Step 7: Commit** with `feat(store): device codes repository and memory driver`.

---

### Task 3: SQL migration 0005 and the SQL driver

**Files:**
- Create: `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0005_device_codes.sql`, `internal/store/sqlstore/device_codes.go`
- Modify: `internal/store/sqlstore/tenants.go`, `sqlstore.go`, `migrate_test.go`

**Interfaces:**
- Consumes: Task 2 types.
- Produces: `DeviceCodes` on all three SQL databases.

- [ ] **Step 1: Bump the expected schema version** in `migrate_test.go` to 5. Run `go test ./internal/store/sqlstore/ -run Migrate`. Expected: FAIL.

- [ ] **Step 2: Write the migrations.** Each dialect follows its `0004_par.sql` for types (`BIGINT` Unix-millisecond times, MySQL `VARCHAR` keys):
  - `tenants`: add `device_flow_charset` and `device_flow_mask`, `NOT NULL DEFAULT ''`.
  - Table `device_codes` with columns `tenant_id`, `device_code_hash`, `user_code_hash`, `client_id`, `scopes` (JSON text), `audience`, `status`, `user_id`, `granted_scopes` (JSON text), `last_polled_at` (NULL), `expired_reported_at` (NULL), `expires_at`, `created_at`.
  - `PRIMARY KEY (tenant_id, device_code_hash)`, `UNIQUE (tenant_id, user_code_hash)`, and an index on `expires_at`.

- [ ] **Step 3: Tenant columns.** Read and write the two fields in `tenants.go`.

- [ ] **Step 4: Implement `device_codes.go`.**
  - `Create` maps unique violations to `ErrConflict` with the dialect helper the other repositories use.
  - `Decide` is one `UPDATE … WHERE tenant_id=? AND device_code_hash=? AND status='pending'`. With 0 rows affected, `Get` decides between `ErrNotFound` and `ErrAlreadyUsed`.
  - `Poll` runs in a transaction (`SELECT … FOR UPDATE` on postgres/mysql; sqlite serializes writers) and applies the four rules from Task 2.

- [ ] **Step 5: Run** `./scripts/test-sql.sh ./internal/store/sqlstore/`. Expected: PASS on sqlite, postgres and mysql, including `TestConformance/*/DeviceCodes`.

- [ ] **Step 6: Commit** with `feat(sqlstore): migration 0005 and device codes`.

---

### Task 4: The gRPC plugin protocol

**Files:**
- Modify: `proto/store/v1/store.proto` (+ `go generate ./...`), `internal/store/grpcstore/{codec,client_repos,server_repos,client}.go`, tests

**Interfaces:**
- Consumes: Task 2 types.
- Produces: RPCs `DeviceCodesCreate`, `DeviceCodesGet`, `DeviceCodesGetByUserCode`, `DeviceCodesDecide`, `DeviceCodesPoll`, `DeviceCodesDeleteExpired`. Tenant fields `string device_flow_charset = 17; string device_flow_mask = 18;`.

- [ ] **Step 1: Write the old-plugin test** `TestOldPluginDeviceCodesSweep`, modelled on `TestOldPluginPushedAuthRequestsSweep`. A server built without the device RPCs:
  - `DeleteExpired` through the client returns `(0, nil)`, the way the PAR one is handled
  - the sweeper's other jobs still run

  Also add a round trip of the two tenant fields.

- [ ] **Step 2: Extend the proto.** Add `message DeviceCode` (field per struct field; optional timestamps for the nullable times), `DeviceDecisionRequest`, `DevicePollRequest`, `DevicePollResult {DeviceCode code; bool too_early; bool first_expired_poll; bool issued;}`, and the six RPCs. Run `go generate ./...`.

- [ ] **Step 3: Codec, client and server repositories**, following the `PushedAuthRequests` ones. Map `ErrConflict`, `ErrNotFound` and `ErrAlreadyUsed` through the existing status mapping. On `Decide` with `ErrAlreadyUsed`, the record comes back too.

- [ ] **Step 4: Run** `go test -race ./internal/store/grpcstore/ ./cmd/zeroauthy-store-memory/...`. Expected: PASS, including the storetest suite over gRPC.

- [ ] **Step 5: Commit** with `feat(grpcstore): device codes over the plugin protocol`.

---

### Task 5: User codes, the seed, config and the disabled throttle

**Files:**
- Create: `internal/devicecode/devicecode.go`, `devicecode_test.go`
- Modify: `internal/seed/{seed,validate,apply}.go`, `seed_test.go`; `internal/identity/throttle.go`, `throttle_test.go`; `internal/config/config.go`, `config_test.go`; every seed in the repo that gives the device grant to a non-native or confidential client (find them with `grep -rn device_code --include=*.yaml`)

**Interfaces:**
- Produces:

```go
package devicecode

const (
	CharsetBase20 = "base20"
	CharsetDigits = "digits"
	DefaultMask   = "****-****"
	Base20        = "BCDFGHJKLMNPQRSTVWXZ" // D2
	Digits        = "0123456789"
)

// Settings returns the effective charset and mask ("" → defaults).
func Settings(t *store.Tenant) (charset, mask string)
// ValidateMask checks a mask for charset: only '*', '-' and ' ' (D2);
// at least 8 (base20) or 9 (digits) '*'; at most 20 characters.
func ValidateMask(charset, mask string) error
// Generate returns a random code shaped by mask, '*' replaced by a
// crypto/rand character from charset.
func Generate(charset, mask string) string
// Normalize upper-cases s and drops every character that is not a
// letter or digit. The result is what gets hashed.
func Normalize(s string) string
// Format re-applies mask to a normalized code for display; a code whose
// length does not match the mask's placeholders is returned unchanged.
func Format(normalized, mask string) string
```

- `identity.Throttle`: a nil `*Throttle` allows everything (`Attempt` returns true; `Refund` and `Success` do nothing). New constructor `NewThrottleOrOff(max int, window, lockout time.Duration) *Throttle` returns nil when `max == 0`.
- `config.Security` gains these fields, where 0 means off for the IP and tenant limits:

| Field | `koanf` key | Default |
|---|---|---|
| `DeviceActivationTxnMaxMisses` | `device_activation_txn_max_misses` | 5, must be ≥ 1 |
| `DeviceActivationIPMaxMisses` | `device_activation_ip_max_misses` | 10 |
| `DeviceActivationIPLockoutSeconds` | `device_activation_ip_lockout_seconds` | 900 |
| `DeviceActivationTenantMaxMisses` | `device_activation_tenant_max_misses` | 1000 |
| `DeviceActivationTenantWindowSeconds` | `device_activation_tenant_window_seconds` | 600 |
| `DeviceActivationTenantLockoutSeconds` | `device_activation_tenant_lockout_seconds` | 60 |

- Seed: `Tenant.DeviceFlow struct { Charset string \`yaml:"charset"\`; Mask string \`yaml:"mask"\` }` under the `device_flow` key.

- [ ] **Step 1: Write the failing tests:**
  - `TestGenerate`: 1,000 codes for base20 `****-****` each match `^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`; digits `***-***-***` match `^\d{3}-\d{3}-\d{3}$`; no duplicates among the 1,000 base20 codes.
  - `TestNormalize`: `"bcdf-ghjk"`, `"BCDF GHJK"`, `" bcdfghjk\n"` → `"BCDFGHJK"`.
  - `TestFormat`: `Format("BCDFGHJK", "****-****") == "BCDF-GHJK"`; a wrong length is returned unchanged.
  - `TestValidateMask`: `"****-***"` with base20 fails (7); `"*********"` with digits passes; 21 characters fails; `"****_****"` fails; `""` with `Settings` defaults passes.
  - `TestNilThrottleAllows`; `TestNewThrottleOrOffZero` (returns nil).
  - Config defaults are as in the table. `device_activation_ip_max_misses: 0` loads. `-1` is rejected. `device_activation_txn_max_misses: 0` is rejected.
  - Seed:
    - `device_flow: {charset: digits, mask: "***-***-***"}` applies to the tenant
    - a bad mask is rejected with the mask in the message
    - the device grant on `app_type: spa` is rejected (`requires app_type native`)
    - the device grant with `token_endpoint_auth_method: client_secret_post` is rejected (`requires token_endpoint_auth_method none`)
    - any third-party client with the grant is refused, permissive included (D11: `device grant is not available to third-party applications`); the existing strict refusal keeps passing

- [ ] **Step 2: Run** `go test ./internal/devicecode/ ./internal/identity/ ./internal/config/ ./internal/seed/`. Expected: FAIL.

- [ ] **Step 3: Implement** the package, throttle, config fields and validation (`app.go` does not use them yet), and seed fields, validation and apply. Update the repo seeds found above. Native clients that already have the grant are untouched.

- [ ] **Step 4: Run** the same command plus `go test ./...`. Expected: PASS. Existing seeds still load.

- [ ] **Step 5: Commit** with `feat: device user codes, device_flow seed settings and activation limits config`.

---

### Task 6: POST /oauth/device/code, discovery and the contract

**Files:**
- Create: `internal/oauth/device.go`, `device_test.go`
- Modify: `api/authentication.yaml` (+ `go generate ./...`), `internal/server/server.go`, `internal/oidc/handlers.go`, `handlers_test.go`

**Interfaces:**
- Consumes: `devicecode.Settings/Generate/Normalize`, `store.DeviceCodes`, `authenticateClient`.
- Produces: `func (h *Handlers) OauthDeviceCode(w http.ResponseWriter, r *http.Request)` with this response type:

```go
type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}
// constants in device.go:
const (
	GrantDeviceCode    = "urn:ietf:params:oauth:grant-type:device_code"
	DeviceCodeLifetime = 900 * time.Second
	DeviceInterval     = 5
)
```

- [ ] **Step 1: Write the failing tests** in `device_test.go`. Use the oauth fixture, extended with:
  - client `dev` (native, `none`, grants `[GrantDeviceCode, refresh_token]`)
  - client `web` (regular_web, secret, no device grant)
  - API `https://api.test` with `allow_offline_access`

  Tests:
  - `TestDeviceCodeIssues`:
    - `200` with `Cache-Control: no-store`
    - `device_code` is 24 characters
    - `user_code` matches the base20 pattern
    - `verification_uri == "https://<tenant host>/activate"`
    - `verification_uri_complete == verification_uri + "?user_code=" + url.QueryEscape(user_code)`
    - `expires_in 900`, `interval 5`
    - the stored record has `Status pending`, `Scopes [openid offline_access]`, `Audience https://api.test`, and hashes rather than plaintext
  - `TestDeviceCodeEmptyAudienceIsAbsent`: `audience=` with `scope=` → `200`; the stored `Audience` is the tenant default audience (fixture sets one), or `""` without one.
  - `TestDeviceCodeErrors` (table, D3): unknown client → `403 unauthorized_client`; `web` → `403 unauthorized_client`; unknown audience → `400 invalid_request`; an API whose user policy is `deny_all` → `400 invalid_request` (the access policy runs at issue time); repeated `client_id` → `403 unauthorized_client`.
  - `TestDeviceCodeJSONBody`: a JSON body `{"client_id":"dev","scope":"openid"}` → `200` (observed: JSON is accepted).
  - `TestDeviceCodeNoScope`: no `scope` → `200`.
  - `TestDeviceCodeUserCodeCollisionRetries`: a store wrapper whose first `Create` returns `ErrConflict` → `200`; on the third consecutive conflict → `500 server_error`.
  - `TestDeviceCodeDigitsTenant`: a tenant with `digits`/`***-***-***` → the code matches `^\d{3}-\d{3}-\d{3}$`.
  - oidc `TestDiscoveryDeviceEndpoint`: `device_authorization_endpoint == base+"/oauth/device/code"`, and `grant_types_supported` contains `GrantDeviceCode` (D6).

- [ ] **Step 2: Run** `go test ./internal/oauth/ ./internal/oidc/`. Expected: FAIL.

- [ ] **Step 3: Implement `deviceCode`** in this order:
  1. Parse the body with the token endpoint's parser (`parseTokenRequest`: form or JSON). A repeated `client_id` → `unauthorizedClient`.
  2. Look the client up by `client_id`. Unknown → `unauthorizedClient` (D3: not `invalid_client`). A request carrying a client secret or Basic credentials → `unauthorizedClient` as well, since device clients use `none`.
  3. Require the grant and `AuthMethodNone`; otherwise `unauthorizedClient`.
  4. Resolve the audience: empty → tenant default. Unknown → `invalidRequest` (D3). Then load the client's user client grant for the API and run `access.Decide(access.Input{Flow: access.Device, Client, API, ClientGrant, Scopes})`. This task adds the `Device` constant to `access` with `Interactive` behaviour; Task 8 gives it its own consent rules. `Decide` errors → `400 invalid_request`.
  5. Generate the codes and `Create`, retrying up to 3 times on `ErrConflict`.
  6. Respond `200` (documented) with `noStore`.

  The host comes from `res.Issuer()`. Access policies are checked here and again after login (observed: refused at issue time).

- [ ] **Step 4: Contract and routing.**
  - Add `/oauth/device/code` (`operationId: oauthDeviceCode`, form body with `client_id`, `scope`, `audience`; responses 200/400/401/403/404) with `x-source` the two Auth0 URLs and RFC 8628. Add `device_authorization_endpoint` to the discovery schema.
  - Run `go generate ./...`. Add `func (a authAPI) OauthDeviceCode(...)` in `server.go` and the `OPTIONS` preflight for `/oauth/device/code`.
  - Add `DeviceAuthorizationEndpoint string \`json:"device_authorization_endpoint,omitempty"\`` to `Configuration`, always set, and add the grant to `GrantTypesSupported`.

- [ ] **Step 5: Run** `go test ./internal/oauth/ ./internal/oidc/ ./internal/server/`. Expected: PASS.

- [ ] **Step 6: Commit** with `feat(oauth): POST /oauth/device/code; discovery advertises it`.

---

### Task 7: The device_code grant at /oauth/token

**Files:**
- Create: `internal/oauth/grant_device_code.go`, `grant_device_code_test.go`
- Modify: `internal/oauth/token.go` (register the grant), `internal/oauth/errors.go`, `internal/oauth/refresh.go`

**Interfaces:**
- Consumes: `DeviceCodes().Get/Poll`, `mintUserTokens`, `audienceFor`, `userScopes`, `offlineAllowed`, `newRefreshToken`, `activeUser`.
- Produces:
  - `func (h *Handlers) deviceCodeGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error)`
  - `func familyForDevice(deviceCodeHash string) string` = `"rtf_" + secrets.HashToken("family:device:"+deviceCodeHash)[:32]`
  - error helpers `authorizationPending()` (403), `slowDown()` (429), `expiredToken()` (403, D5), `deviceInvalidGrant(desc)` (`invalid_grant` with **403**, observed), all with descriptions in our own words

- [ ] **Step 1: Write the failing tests** (state table, design §4.3). Each case creates a record directly in the store:
  - `TestDeviceGrantPending` → `403 authorization_pending`.
  - `TestDeviceGrantSlowDown`: two polls 300 ms apart (fixture clock) → the second is `429 slow_down` with no `interval` key; a third 1 s after the first → `403 authorization_pending`.
  - `TestDeviceGrantDenied` → `403 access_denied`; a second poll 2 s later → `403 invalid_grant`.
  - `TestDeviceGrantExpired`: at `ExpiresAt` → `403 expired_token`; again → `403 invalid_grant`.
  - `TestDeviceGrantUnknown` → `403 invalid_grant`.
  - `TestDeviceGrantOtherClient`: an approved code polled by another device client → `403 invalid_grant`; the code is still `approved`, because the client is checked with `Get` before `Poll`. (A client without the grant already gets `403 unauthorized_client` from `token`, as observed.)
  - `TestDeviceGrantIssues`: approved with `GrantedScopes [openid offline_access]`, `Audience https://api.test` → `200` with an access token (aud = the API and `/userinfo`, no `gty`), an ID token whose claims are exactly `aud exp iat iss sub` (no `sid`, no `auth_time`, no `nonce`), and a refresh token whose family is `familyForDevice(hash)` and whose `SessionID` is empty. A second poll 2 s later → `403 invalid_grant`.
  - `TestDeviceGrantRefreshRotates`: the refresh token from above works with `grant_type=refresh_token` and rotates (existing rotation).
  - `TestDeviceGrantBlockedUser`: the user is blocked after approval → the error `activeUser` returns, as for codes.
  - `TestDeviceGrantMissingDeviceCode` → `400 invalid_request`.
  - `TestRefreshOfDeviceTokenHasNoSid`: refreshing the device refresh token gives an ID token without `sid` and `auth_time`.

- [ ] **Step 2: Run** `go test ./internal/oauth/ -run DeviceGrant`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - Register `GrantDeviceCode: (*Handlers).deviceCodeGrant` in `grantHandlers` and delete the "A later plan adds device_code" comment.
  - The grant-type check in `token` already requires the client to have the grant.
  - Mapping, in this order: `Get` (`ErrNotFound` → `deviceInvalidGrant`), then a client mismatch → `deviceInvalidGrant`. Then `Poll(now)` by `Outcome`: `PollPending` → `authorization_pending`; `PollSlowDown` → `slow_down`; `PollDenied` → `access_denied`; `PollExpired` → `expired_token`; `PollInvalid` → `deviceInvalidGrant`; `PollApproved` → mint.
  - Minting mirrors `authorizationCode` after its checks: `scopes := userScopes(GrantedScopes, rs, offlineAllowed(c, rs))`, with **no** session ID and a zero auth time. `Minter` must then omit `auth_time` (today it always writes it; make it conditional on a non-zero time, and check no existing test relied on a zero `auth_time`). A refresh token is issued when the scopes contain `offline_access`, with `familyForDevice` and an empty session ID; the refresh grant then also mints without `sid`/`auth_time` for these tokens.

- [ ] **Step 4: Run** `go test -race ./internal/oauth/`. Expected: PASS.

- [ ] **Step 5: Commit** with `feat(oauth): device_code grant at /oauth/token`.

---

### Task 8: Shared flow completion in authz and the device continuation

The largest structural change. Session reuse, login, the access decision and consent stay written once. Only approve/refuse differs between `/authorize` and the device flow.

**Files:**
- Create: `internal/authz/flow.go`, `internal/authz/device.go`, `device_test.go`
- Modify: `internal/authz/handlers.go`, `internal/access/access.go`, `observed.go`, `access_test.go`

**Interfaces:**
- Consumes: `store.DeviceCodes`, `store.DeviceDecision`.
- Produces:

```go
// access: the Device flow constant exists since Task 6; this task gives it its rules.
// D4 observed: consent follows the API's skip_consent_for_verifiable_first_party_clients
// for device clients exactly as for /authorize, so no new observed constant.

// authz/flow.go
// Transaction keys that are not request parameters.
const (
	ParamFlow       = "za_flow"
	FlowDevice      = "device"
	ParamDevice     = "za_device"    // device code hash
	ParamUserCode   = "za_user_code" // the formatted user code, for display
	ParamStage      = "za_stage"     // was the private stageKey
	StageDeviceEntry   = "device-entry"
	StageDeviceConfirm = "device-confirm"
)

// flowReq is a request on its way through login and consent: an
// /authorize request, or a device authorization (DeviceCodeHash set).
type flowReq struct {
	Request
	DeviceCodeHash string
}
func (f flowReq) params() map[string]string        // Request.Params() plus ParamFlow/ParamDevice for the device flow
func flowFromParams(p map[string]string) flowReq

// authz/device.go
// CreateTxn stores a transaction bound to this browser (sets the za_txn
// cookie) and returns it. startTxn uses it.
func (h *Handlers) CreateTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, clientID string, params map[string]string) (*store.AuthTransaction, error)
// EndTxn deletes txn and expires its cookie.
func (h *Handlers) EndTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction)
// ContinueDevice runs login (or session reuse, D10) and the access
// decision for a confirmed device code.
func (h *Handlers) ContinueDevice(w http.ResponseWriter, r *http.Request, res tenant.Resolved, dc *store.DeviceCode, uiLocales string)
// DenyDevice marks a pending code denied and redirects to /device/denied.
func (h *Handlers) DenyDevice(w http.ResponseWriter, r *http.Request, res tenant.Resolved, dc *store.DeviceCode, uiLocales string)
// ConsentView gains: Device bool (true for a device transaction; then CallbackDomain and RedirectURI are empty).
```

**How the pieces change** (`handlers.go`):
- `startLogin`, `startConsent` and `finish` take a `flowReq` instead of a `Request`. `deny` becomes `refuse(w, r, res, client, fr, e)`: the device flow calls `DeviceCodes().Decide(denied)` and redirects (302) to `/device/denied`. Otherwise it is the existing `deny`. `issueCode` is reached through `approve(w, r, res, client, fr, sess, scopes)`: the device flow calls `Decide(approved, user, scopes)` and redirects to `/device/success` (no `Sessions.AddClient`: device tokens are not bound to the session). Otherwise it is the existing `issueCode`.
- `Resume`, `Consent` and `ConsentView` build `fr := flowFromParams(txn.Params)` and validate with `h.validateFlow(ctx, res, &fr) (*store.Client, *Error, bool)`:
  - **`/authorize` flows:** `ValidateRequest`.
  - **Device flows:** the client still exists and still has the grant, and the code is still `pending` and unexpired. Failures are not redirectable and show the error page.
- `Resume` refuses every transaction whose `ParamStage` is set, whether consent or device. `Consent` and `ConsentView` accept only the consent stage, as now.
- `accessInput` sets `Flow: access.Device` for device flows.
- `ContinueDevice` builds `fr` from the code: `ClientID`, `Scope` as space-joined `Scopes`, `Audience`, `UILocales`. With no active session, or a disabled connection, it calls `startLogin`. Otherwise it calls `finish(fr, sess, accepted=false, screenShown=true)`; the device confirmation screen counts as shown.
- `access.Decide`:
  - `Device` behaves like `Interactive`, except: `Confirmation` is always false (the device confirmation screen replaces it); `prompt=none` does not apply; and `needsConsent` ignores the redirect URI (there is none), so a first-party client on an API that skips consent gets no consent (D4).
  - `checkPolicy` uses `codeAuthorizeDenied` for `Device`.

- [ ] **Step 1: Write the failing access tests:**
  - `TestDecideDeviceFirstPartySkipAPI` → `Consent` false
  - `TestDecideDeviceFirstPartyNoSkipAPI` → `Consent` true
  - `TestDecideDeviceGrantCovers` → no consent
  - `TestDecideDeviceNoAudienceFirstParty` → no consent
  - `TestDecideDeviceNeverConfirmation`
  - `TestDecideDeviceDenyAll` → `Err.Code == "invalid_request"`

- [ ] **Step 2: Write the failing authz tests** in `device_test.go`. Use the authz fixture with a device client, the skip-consent API, and a pending code. The fixture's session helper gives a logged-in browser.
  - `TestContinueDeviceNoSessionStartsLogin`: 302 to `/u/login?state=…`; the transaction has `ParamFlow=device` and `ParamDevice=<hash>`.
  - `TestContinueDeviceSessionSkipAPI` (D4, D10): with a session and the skip-consent API → the code is `approved` at once and the response is 302 to `/device/success`.
  - `TestContinueDeviceSessionShowsConsent` (D4, D10): with a session and an API that does not skip consent → 302 to `/u/consent?state=…`.
  - `TestDeviceConsentAccept`: `Consent(accepted=true)` → the code is `approved` with the session's user and `[openid offline_access]`; the response is 302 to `/device/success`; a user grant is stored.
  - `TestDeviceConsentDecline`: the code is `denied`; 302 to `/device/denied`.
  - `TestDeviceResumeAfterLogin`: `Resume` on the login transaction → the consent redirect.
  - `TestDeviceDecideTwiceKeepsFirst`: the code is already approved, then `Consent(accepted=false)` on a stale transaction → the code stays `approved`, and the page is the error page with `KeyErrSessionExpired` (`validateFlow` fails because the code is not pending).
  - `TestDeviceConsentViewHasNoCallback`: `ConsentView` → `Device` true, `CallbackDomain` `""`.
  - Existing `/authorize` tests stay unchanged and pass (regression).

- [ ] **Step 3: Run** `go test ./internal/access/ ./internal/authz/`. Expected: FAIL.

- [ ] **Step 4: Implement** `flow.go`, `device.go`, the `handlers.go` refactor and the access change, as described above. The result pages themselves are Task 9's; here only the redirects to `/device/success` and `/device/denied` are produced.

- [ ] **Step 5: Run** `go test -race ./internal/access/ ./internal/authz/ ./internal/login/`. Expected: PASS, including every existing test.

- [ ] **Step 6: Commit** with `refactor(authz): shared flow completion; device continuation after login and consent`.

---

### Task 9: The browser pages, the catalog and the activation limits

**Files:**
- Create: `internal/login/device.go`, `device_test.go`; `internal/ui/templates/device_code.html`, `device_confirm.html`, `device_result.html`
- Modify: `internal/login/login.go` (three throttle fields), `consent.go` (pass `Device`), `internal/ui/ui.go`, `templates/consent.html`, `internal/i18n/locales/en.json`, `keys.go`, `internal/app/app.go`, `internal/server/server.go`

**Interfaces:**
- Consumes: `authz.CreateTxn/EndTxn/ContinueDevice/DenyDevice`, `authz.Param*`, `devicecode.Normalize/Format/Settings`, `identity.Throttle`.
- Produces:

```go
// login.Handlers gains
DeviceTxnThrottle    *identity.Throttle // key: txn ID
DeviceIPThrottle     *identity.Throttle // key: identity.IPThrottleKey(tenant, ip); nil = off
DeviceTenantThrottle *identity.Throttle // key: tenant ID; nil = off

// Paths observed on Auth0 (D1, D7, D8).
func (h *Handlers) Activate(w http.ResponseWriter, r *http.Request)            // GET /activate: entry form, or confirmation for ?user_code=
func (h *Handlers) ActivateSubmit(w http.ResponseWriter, r *http.Request)      // POST /activate (form: state, code)
func (h *Handlers) DeviceConfirmPage(w http.ResponseWriter, r *http.Request)   // GET /device/confirmation?state=
func (h *Handlers) DeviceConfirmSubmit(w http.ResponseWriter, r *http.Request) // POST /device/confirmation (form: state, action=confirm|cancel)
func (h *Handlers) DeviceSuccess(w http.ResponseWriter, r *http.Request)       // GET /device/success (static page)
func (h *Handlers) DeviceDenied(w http.ResponseWriter, r *http.Request)        // GET /device/denied (static page)

// ui
type DeviceCodeData struct{ State, CSRF, UserCode, ErrorKey string }
type DeviceConfirmData struct{ State, CSRF, UserCode string }
func RenderDeviceCode(w http.ResponseWriter, status int, t Tenant, d DeviceCodeData)
func RenderDeviceConfirm(w http.ResponseWriter, t Tenant, d DeviceConfirmData)
func RenderDeviceResult(w http.ResponseWriter, t Tenant, allowed bool)
// ConsentData gains Device bool
```

**Catalog** (`en.json`, prompt `device-flow`): every key Auth0 documents for the four screens, with our own English text:
- `device-code-activation`: `pageTitle`, `title`, `description`, `placeholder`, `buttonText`, `logoAltText`, `invalid-code`, `invalid-expired-code`, `no-code`
- `device-code-confirmation`: `pageTitle`, `title`, `description`, `inputCodeLabel`, `confirmationText`, `confirmButtonText`, `cancelButtonText`, `logoAltText`
- `device-code-activation-allowed`: `pageTitle`, `eventTitle`, `description`
- `device-code-activation-denied`: `pageTitle`, `eventTitle`, `description`

Also our own key `zeroauthy.consent.externalDeviceApp`: the third-party notice without a callback domain. The page text names the application through `${clientName}`.

**Behaviour:**
- `Activate` creates an entry transaction: client `""`, params `{za_flow: device, za_stage: device-entry, ui_locales}`. Entry and confirmation transactions set their `za_txn_` cookie with `Path=/` (they are used at `/activate` and `/device/confirmation`, outside `/u`); `CreateTxn` takes the cookie path as a parameter.
  - Without `user_code`, it renders the entry form at `/activate` (200, hidden `state`; no redirect).
  - With `user_code`, it runs the same check as `ActivateSubmit` (throttled, D1): on success it redirects to the confirmation; on failure it renders the entry page with the error.
- **Code check, in order:**
  1. `DeviceTenantThrottle.Attempt(tenant)` and `DeviceIPThrottle.Attempt(ipKey)`. If either refuses, render the entry page with `KeyTooManyAttempts`, status 429.
  2. `DeviceTxnThrottle.Attempt(txn.ID)` refuses → `EndTxn` and the session-expired error page.
  3. Empty after `Normalize` → `no-code`, status 400.
  4. `GetByUserCode(HashToken(Normalize(code)))`: not found, expired, or not `pending` → `invalid-expired-code`, status 400 (D7: one message for all three; the `invalid-code` key stays in the catalog unused, as Auth0 documents it). A miss leaves the attempts counted.
  5. Found → `Refund` all three keys. `EndTxn(entry)`. `CreateTxn(dc.ClientID, {za_flow, za_stage: device-confirm, za_device: hash, za_user_code: Format(Normalize(code), mask), ui_locales})`. 302 to `/device/confirmation?state=…`.
- `DeviceConfirmSubmit`:
  - Reload the code by `ParamDevice`. If it is gone, expired or not pending, render the entry error `invalid-expired-code` in a new entry transaction.
  - `confirm` → `EndTxn` then `ContinueDevice`.
  - `cancel` → `EndTxn` then `DenyDevice`: 302 to `/device/denied` (D8).
- `DeviceSuccess` and `DeviceDenied` render `device_result.html` (allowed / denied) for the tenant, with no state.
- `consent.go` passes `Device` into `ConsentData`. `consent.html` shows `externalDeviceApp` instead of the callback-domain notice when `Device` is set. The form action stays `'self'`, because `formActionFor("")` already returns it.
- `app.go` builds the three throttles from config:
  - txn: `NewThrottle(TxnMax, authz.TxnLifetime, authz.TxnLifetime)`
  - IP: `NewThrottleOrOff(IPMax, IPLockout, IPLockout)`
  - tenant: `NewThrottleOrOff(TenantMax, TenantWindow, TenantLockout)`

  `server.go` wires them and adds the six routes, beside `/u/*`, outside the generated API.

- [ ] **Step 1: Write the failing tests** in `internal/login/device_test.go`:
  - `TestActivateShowsEntry`: `GET /activate` → 200 entry form with a hidden `state`, and a `za_txn_` cookie with `Path=/`.
  - `TestActivateWithUserCodeGoesToConfirm`: a pending code → 302 `/device/confirmation?state=…`; the confirm page shows the formatted code and the client's name.
  - `TestDeviceSubmitAcceptsLooseFormatting`: `" bcdf ghjk\n"` for `BCDF-GHJK` → the confirmation redirect.
  - `TestDeviceSubmitErrors` (D7): `wrongcode`, an expired code and an approved code → 400 entry page containing the `invalid-expired-code` text; `""` → 400 with `no-code`.
  - `TestDeviceTxnLimit`: 5 wrong codes, then a 6th submit → the session-expired error page, and the transaction is deleted.
  - `TestDeviceIPLimit`: with an IP limit of 3 (test config), 3 misses across fresh transactions, then a 4th with the correct code → 429 with `too-many-attempts`.
  - `TestDeviceTenantLimitOff`: with the tenant throttle nil, 20 misses across fresh transactions and IPs (IP limit off) are all served normally (400 entry page, never 429).
  - `TestDeviceSuccessRefunds`: with an IP limit of 3, 2 misses, then a success, then 2 more misses in a new transaction → no lockout.
  - `TestDeviceConfirmCancel`: the code is `denied`; 302 to `/device/denied`, whose page shows `device-code-activation-denied` `eventTitle`.
  - `TestDeviceConfirmTwice`: confirm (logged in, consent accepted elsewhere so the code is approved), then re-POST the same confirmation → the entry page with `invalid-expired-code`; the code stays `approved`.
  - `TestDeviceFullFlowWithLogin`: entry → confirm → `/u/login` → POST credentials → (consent for a no-skip API) → accept → 302 `/device/success`; the code is `approved`.
  - `TestDeviceCustomText`: a tenant `custom_text` for `device-flow.en.device-code-activation.title` appears on the entry page.
  - i18n catalog test: the new keys exist; `KeyDevice*` constants resolve.

- [ ] **Step 2: Run** `go test ./internal/login/ ./internal/ui/ ./internal/i18n/`. Expected: FAIL.

- [ ] **Step 3: Implement** the handlers, templates (styled like `consent.html` and `login.html`, one form per page, CSRF hidden field), render functions, catalog, keys, wiring and routes.

- [ ] **Step 4: Run** `go test -race ./...`. Expected: PASS.

- [ ] **Step 5: Manual smoke.** Run `go run ./cmd/zeroauthy serve` with the e2e seed, then:
  - `curl -k -d client_id=e2e-device -d scope=openid https://localhost:8443/oauth/device/code`
  - open `verification_uri_complete` in a browser, log in as alice, and accept
  - poll with curl; expect tokens

- [ ] **Step 6: Commit** with `feat(login): /activate, code entry and confirmation pages with activation limits`.

---

### Task 10: E2E with auth0.net and Chromium (m10-device)

**Files:**
- Create: `tests/e2e/dotnet-device/DeviceE2E.csproj`, `tests/e2e/dotnet-device/Program.cs`, `tests/e2e/m10-device.spec.mjs`
- Modify: `tests/e2e/seed.yaml`, `tests/e2e/run-browser.sh`, `docs/compat/blackbox-clients.md`

**Interfaces:**
- Consumes: the running server from `run-browser.sh` (`https://localhost:8443`, cert at `$E2E_CERT`).
- Produces: the client program's stdout protocol, one JSON object per line:
  - `{"event":"code","user_code","verification_uri","verification_uri_complete","interval","expires_in"}` first
  - then `{"event":"tokens","access":bool,"id":bool,"refresh":bool,"refreshed":bool}` or `{"event":"error","error":"<code>"}`
  - exit code 0 for tokens, 1 for an error

- [ ] **Step 1: Seed.** Add client `e2e-device` (Native, `token_endpoint_auth_method: none`, first party, grants `[urn:ietf:params:oauth:grant-type:device_code, refresh_token]`) to `seed.yaml`, and add it to `Username-Password-Authentication`'s `enabled_clients`.

- [ ] **Step 2: The .NET client.**
  - `DeviceE2E.csproj`: `net10.0`, `PackageReference Include="Auth0.AuthenticationApi" Version="7.49.0"`.
  - `Program.cs` takes `domain clientId audience scope` as arguments.
  - It creates `AuthenticationApiClient(new Uri(domain))` and calls `StartDeviceFlowAsync`, then prints the `code` line.
  - It polls `GetTokenAsync(new DeviceCodeTokenRequest{ClientId, DeviceCode})`. It catches `ErrorApiException` and uses `ApiError.Error`: `authorization_pending` waits the interval; `slow_down` adds 5 s; anything else prints `error` and exits 1.
  - On success it calls `GetTokenAsync(new RefreshTokenRequest{ClientId, RefreshToken})` once, then prints `tokens`.
  - About 60 lines, no other packages.

- [ ] **Step 3: Build it once in `run-browser.sh`**, before Playwright, when `E2E_IN_CONTAINER` is not set:

```bash
podman run --rm -v "$PWD/tests/e2e/dotnet-device:/src:ro" -v "$work/dotnet:/out" -v za-e2e-nuget:/root/.nuget \
  mcr.microsoft.com/dotnet/sdk:10.0.400-noble dotnet publish /src -c Release -o /out
export E2E_DOTNET_DIR="$work/dotnet"
```

When `E2E_IN_CONTAINER=1`, print `m10-device skipped: needs podman on the host` and let the spec skip itself (`test.skip(!process.env.E2E_DOTNET_DIR)`).

- [ ] **Step 4: Write `m10-device.spec.mjs`.** A helper `startDevice(audience, scope)` spawns:

```bash
podman run --rm --network host -v "$E2E_DOTNET_DIR:/app:ro" -v "$E2E_CERT:/certs/e2e.crt:ro" \
  mcr.microsoft.com/dotnet/sdk:10.0.400-noble sh -c \
  'cp /certs/e2e.crt /usr/local/share/ca-certificates/ && update-ca-certificates >/dev/null && dotnet /app/DeviceE2E.dll "$@"' -- \
  https://localhost:8443/ e2e-device <audience> <scope>
```

It resolves the first `code` line and a promise for the final line. The test timeout is 3 minutes. Tests:
  - **typed code:** start with `https://api.e2e.local` and `openid offline_access`; Chromium goes to `verification_uri`, fills the code, continues, sees the confirmation (`/device/confirmation`) with the same code, confirms, logs in as alice, sees **no** consent (`api.e2e.local` skips consent for first-party clients, D4), then `/device/success`. The client's final line is `{"event":"tokens","access":true,"id":true,"refresh":true,"refreshed":true}`.
  - **complete URI with consent:** add an API `https://consent.e2e.local` (no skip, `allow_offline_access`, scope `read:things`) to the seed. Open `verification_uri_complete` for that audience: the confirmation is the first screen (D1). Confirm. Alice's session is reused (D10), so there's no login; consent shows and is accepted; `/device/success`; tokens.
  - **cancel:** confirm page → cancel, then `/device/denied`; the client ends with `{"event":"error","error":"access_denied"}`.
  - **wrong codes:** at `verification_uri`, enter `BBBB-BBBB` (shows the `invalid-expired-code` text) 5 times, then a 6th time → the session-expired error page.

- [ ] **Step 5: Run** `./tests/e2e/run-browser.sh`. Expected: all specs pass, including `m10-device` (4 tests) and every earlier suite.

- [ ] **Step 6: Record the client** in `docs/compat/blackbox-clients.md`: the `auth0.net` row (stars from GitHub at the time), `m10-device`, and what it covers. Change the `auth0-cli` row's note to mention the device-login follow-up.

- [ ] **Step 7: Commit** with `test(e2e): device flow with auth0.net and Chromium`.

---

### Task 11: Documentation and final verification

**Files:**
- Create: `docs/device-flow.md`
- Modify: `docs/compat/matrix.md`, `docs/compat/changelog-review.md`, `docs/superpowers/plan-1-followups.md`, `docs/superpowers/specs/2026-10-13-zeroauthy-core-auth-api-design.md`, `docs/superpowers/specs/2026-10-17-zeroauthy-device-flow-design.md` (status), `README.md` if it lists features

- [ ] **Step 1: Write `docs/device-flow.md`**, in the shape of `docs/par.md`:
  - setting up a device client (the seed snippet)
  - `device_flow` settings
  - what the user sees
  - refresh tokens for TV apps, and revoking them to force a new sign-in
  - the activation limits and their config keys
  - auth0.net usage
  - differences from Auth0 (D-0034)

- [ ] **Step 2: Records.**
  - **Matrix:** rows for `/oauth/device/code`, the grant, `device_flow`, the four screens and discovery.
  - **Changelog review:** a row for Plan 11.
  - **Followups:** "Plan 11 follow-ups" with the Out of Scope list above.
  - **Core spec:** §6 lists the endpoint as shipped, and §13 marks milestone 10 complete.
  - **Design spec:** status "Implemented (Plan 11)". §5's per-transaction counter is now "an in-process throttle keyed by transaction ID", which is how Task 9 builds it.

- [ ] **Step 3: Full verification.** Run:

```bash
gofmt -l . && go vet ./... && go generate ./... && git diff --exit-code && CGO_ENABLED=0 go build ./... && go test -race ./... && ./scripts/test-sql.sh ./internal/store/sqlstore/ ./pkg/storetest/... && ./tests/e2e/run-browser.sh
```

Expected: no gofmt output, no diff, every test passes.

- [ ] **Step 4: Commit** with `docs: device flow guide, matrix, follow-ups and spec for Plan 11`.
