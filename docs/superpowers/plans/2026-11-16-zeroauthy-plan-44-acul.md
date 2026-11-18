# Plan 44 — ACUL and the remaining Universal Login modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The prompt rendering API, ACUL host pages with
`window.universal_login_context` for every screen zeroauthy renders, the
SDK form contract with state-bound CSRF, and the remaining Universal Login
controls (social button layout, secondary-action slots, custom-domain
Liquid context, passkey-first, phone MFA enrollment tickets).

**Architecture:**
- **`internal/acul`** (new): rendering rules (validation, filters, CSP
  origins), the screen → route map, the context builder (from the existing
  `ui` view models), and the host-page renderer.
- **`internal/login`** handlers consult `acul.Select(tenant, prompt, screen,
  client, org, host)` before rendering; standard rendering is unchanged.
- **Storage:** `store.PromptRenderings` (memory, SQL, gRPC
  `prompt_rendering.v1`).
- **`internal/mgmt/prompt_rendering.go`**: the four Management operations.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0, node-auth0 7.4.0, auth0-deploy-cli 9.1.0;
`@auth0/auth0-acul-js` 1.11.0 for E2E only after maintainer approval.

**Spec:** [Plan 44 design](../specs/2026-11-16-zeroauthy-acul-design.md). § refers to it.

**Gate:** Task 1 may start now. Tasks 2–10 wait for the maintainer's
rulings on spec §11 (Classic, the security boundary, canonical host, the
SDK pin). Record the rulings in D-0230 before Task 2.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin; the ACUL SDK pin
  only as approved.
- **Clean room.** CLEAN_ROOM.md "Open-source Auth0 code": record the SDK tag
  and file for every behaviour learned from it (`x-source` and D-0230); no
  SDK code copied into zeroauthy.
- **Parity.** LR44-1…6 and Z1–Z6 in **D-0230**; Z points in
  `docs/superpowers/plan-1-followups.md`; amend D-0047/D-0050 for the ACUL
  page CSP.
- **Security.** CSP as spec §6 (no `unsafe-inline`/`unsafe-eval`); SRI
  required; context JSON escaped per spec anti-goals; standard pages'
  golden HTML unchanged.
- **Limits.** Spec §3.
- **Migration.** One forward-only migration in three dialects written as
  `0041_prompt_renderings.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za44 GOTMPDIR=/dev/shm/za44 go test -p 4 ./...` plus
  `make e2e-acul` and `make e2e-branding`; push `plan-44-acul`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan44`, branch `plan-44-acul`;
  record in `docs/superpowers/2026-11-16-plan-44-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Context escaping:** a client name `</script><script>alert(1)</script>`
   and a U+2028 in user metadata render inert. Task 4 `TestContextEscaping`
   plus `FuzzContextEmbed`.
2. **CSP derived from head tags:** an `http://` URL or a tag without
   `integrity` is refused at write; the page's CSP never contains
   `unsafe-*`. Task 2 `TestRenderingRules`, Task 5 `TestACULCSP`.
3. **State-only post from another site:** `Origin: https://evil.test` with
   a valid `state` and no cookie → stale-form answer, no authentication.
   Task 6 `TestACULPostCSRF`.
4. **Filters:** `excludes_any` by client metadata excludes exactly the
   matching clients; organizations and domains combine with OR. Task 3
   `TestRenderingFilters`.
5. **Standard pages unchanged:** Plan 22 golden HTML tests still pass with
   advanced renderings stored for other screens. Task 5
   `TestStandardPagesUnchanged`.

---

## File boundaries and shared interfaces

```go
// internal/store/prompt_renderings.go
type PromptRendering struct{ TenantID, Prompt, Screen string; Config json.RawMessage; UpdatedAt time.Time }
type PromptRenderings interface {
    Get(ctx context.Context, tid, prompt, screen string) (*PromptRendering, error)
    List(ctx context.Context, tid string, f RenderingFilter, page, perPage int) ([]*PromptRendering, int, error)
    Put(ctx context.Context, r *PromptRendering) error
    PutMany(ctx context.Context, rs []*PromptRendering) error // atomic
}

// internal/acul
type Config struct{ Mode string; Context []string; DefaultHeadTagsDisabled, UsePageTemplate bool; HeadTags []HeadTag; Filters *Filters }
type HeadTag struct{ Tag string; Attributes map[string]any; Content string }
func Parse(prompt, screen string, raw json.RawMessage) (*Config, error)       // write-time rules
func (c *Config) Applies(client *store.Client, org *store.Organization, host string) bool
func (c *Config) CSP(nonce string, formActions []string) string
func BuildContext(v ui.ScreenView, c *Config) (map[string]any, error)
func RenderHost(w http.ResponseWriter, c *Config, ctx map[string]any, page *PageTemplate, nonce string) error
var Screens map[string]Route // Auth0 screen name -> zeroauthy route and handler key
```

---

### Task 1: Contracts, screen map, decisions

**Files:** `api/management.yaml` (four rendering operations, schemas,
`x-source` to the OpenAPI and the SDK tag); `internal/acul/screens.go`
(the map of spec §4, with a test listing every SDK screen as served,
stored-only or absent); `docs/compat/decisions.md` (D-0230 with the §11
questions marked open); `docs/superpowers/plan-1-followups.md` (Z1–Z6).

- [ ] **Step 1:** OpenAPI; `make generate`; `501` stubs; `go build ./...`.
- [ ] **Step 2:** Screen map + `TestScreenMapCoversSDK` (the SDK's 81 screen names are a fixture list copied by name only).
- [ ] **Step 3:** D-0230, follow-ups.
- [ ] **Step 4:** Commit `docs: freeze Plan 44 contracts and D-0230`.
- [ ] **Step 5:** Stop and ask the maintainer for the §11 rulings.

### Task 2: Rendering rules

**Files:** `internal/acul/config.go`, `config_test.go`.

- [ ] **Step 1: Failing tests** `TestRenderingRules`: each allowed tag/attribute; `http://` URL; missing `integrity`; inline script content; `style` tag; `base`; 26 head tags; bad context item; dynamic items matching the OpenAPI patterns; `advanced` without a script; filters with unknown keys.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(acul): rendering configuration rules`.

### Task 3: Storage and Management API

**Files:** `internal/store/prompt_renderings.go`, memory/sql/grpc drivers,
`pkg/storetest/prompt_renderings.go`, migration `0041_prompt_renderings.sql`,
proto (capability), `internal/mgmt/prompt_rendering.go`, tests;
`internal/acul/filters.go` (`Applies`).

- [ ] **Step 1: Failing tests**
  - storetest: put/get/list paging; `PutMany` atomic (one invalid entry → nothing stored).
  - `TestRenderingAPI`: GET default (standard) for a known pair; unknown pair `404`; PATCH partial merge; bulk PATCH; list filters; scopes.
  - `TestRenderingFilters` (Review Focus 4).
  - capability off → `501`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): prompt screen rendering API`.

### Task 4: Context builder

**Files:** `internal/acul/context.go`, `context_test.go`, `context_fuzz_test.go`;
`internal/ui` (expose a `ScreenView` per standard page: the data already
computed for rendering).

- [ ] **Step 1: Failing tests**
  - Snapshot per screen family (login-id, login-password, signup, MFA OTP challenge, reset-password, consent, organization-selection) with and without each configuration item.
  - Opt-in rule: `user.user_metadata.k` absent unless configured.
  - `TestContextEscaping` (Review Focus 1); `FuzzContextEmbed`.
  - Errors: a failed password post yields `transaction.errors[0].code` matching the standard page's error key mapping.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(acul): universal login context builder`.

### Task 5: Host page and CSP

**Files:** `internal/acul/host.go`, `host_test.go`; `internal/login`
render paths (one hook in the shared render function); Plan 22 page
template integration.

- [ ] **Step 1: Failing tests**
  - `TestACULHostPage`: head tags in order with `crossorigin`; mount point; JSON context element; nonce'd bootstrap; default head tags present/absent.
  - `TestACULCSP` (Review Focus 2).
  - `TestACULPageTemplate`: `use_page_template` wraps the host page.
  - `TestStandardPagesUnchanged` (Review Focus 5).
  - `TestACULOnlyWhenFilterApplies`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(acul): advanced rendering host page`.

### Task 6: Form contract and CSRF

**Files:** `internal/login/*` POST handlers (accept SDK field names and
`action` values per screen through one mapping table), `internal/acul/forms.go`,
tests.

- [ ] **Step 1: Failing tests**
  - Per screen family: SDK-shaped POST (`username`, `password`, `action=default`, `state`, `acul-sdk`) authenticates exactly like the standard form.
  - Federated button post (`connection=google-oauth2`) starts the upstream attempt.
  - `TestACULPostCSRF` (Review Focus 3): missing cookie, foreign Origin, missing Origin and foreign Referer → stale-form answer.
  - Standard-page posts still require the CSRF field.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(login): ACUL form contract with state-bound CSRF`.

### Task 7: Remaining Universal Login controls

**Files:** `internal/ui` (social layout, secondary slots), `internal/liquid`
context (`transaction.custom_domain`), `internal/login/identifier.go`
(passkey-first), `internal/mfa` ticket handler (phone).

- [ ] **Step 1: Failing tests**: layout `top`/`bottom`; secondary-action slots render and obey Plan 22 control rules; Liquid `transaction.custom_domain.domain` on custom hosts only; passkey-first offers the passkey ceremony on the identifier page and falls back to password; `POST /guardian/enrollments/ticket` with phone → ticket page enrolls SMS.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(ui): social layout, secondary slots, passkey-first and phone tickets`.

### Task 8: Console

- [ ] **Step 1:** Branding → Universal Login → Rendering tab per screen (mode, head tags with SRI field, context items picker, filters), validation messages from the server; synthetic-context preview in the Plan 22 sandbox; Vitest; `console/dist`.
- [ ] **Step 2:** Commit `feat(console): ACUL rendering editor`.

### Task 9: Deploy CLI and auth0-cli

- [ ] **Step 1:** Four-cell Deploy CLI round trip with `screenRenderers`; remove the ACUL exclusion from the m20 manifest.
- [ ] **Step 2:** `auth0 acul config` commands that call only the rendering API, if 1.37.0 has them (record which).
- [ ] **Step 3:** Commit `test(e2e): ACUL rendering round trips`.

### Task 10: E2E lane, docs, final verification

- [ ] **Step 1:** `make e2e-acul` (`run-m44-acul.sh`): operator bundle built with the approved SDK pin, local HTTPS CDN with SRI, Playwright through login-id → login-password, signup, MFA OTP, reset password; node-auth0 rendering calls; add to `.github/workflows/ci.yml`.
- [ ] **Step 2:** Docs: new `docs/acul.md` (setup, security boundary, context items, limits, differences); update `docs/branding.md`, `docs/compatibility.md`, `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 3:** Fast tier + `make e2e-acul` + `make e2e-branding`; push `plan-44-acul`; record CI.
- [ ] **Step 4:** Whole-branch review, fix wave, green CI, maintainer approval.
