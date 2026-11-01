# Plan 32 implementation record

Plan: `docs/superpowers/plans/2026-11-01-zeroauthy-plan-32-event-streams.md`.
Base: `17d749c`. Branch: `implement-plan-32`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan32`.

Implementation in progress. No completed-plan or full-regression claim.

## Evidence and decisions

- Public catalog 0.13.6 and Management OpenAPI fetched on 2026-11-01 from the spec's URLs. Frozen catalog contains structural validation constraints and examples, without documentation prose. No SDK implementation source used.
- E1–E8: no firewalled observer record was present. No Auth0 tenant observation performed by the implementer. Spec §8 defaults apply; all eight gaps remain explicit in the inventory and D-0058.
- Catalog's organization-name negative lookahead is expressed as an equivalent `pattern` plus `not` because Go's regex engine cannot parse lookahead. Pattern acceptance is unchanged.
- Catalog 0.13.6 omits `a0purpose`; the frozen validator permits the documented `"test"` extension for the test endpoint.

## Task evidence

Task 1: initial `GOTOOLCHAIN=go1.26.7 go test ./internal/eventrules -count=1` failed on missing contract functions. After implementation it passed (0.118s). Controller generation and focused API/eventrules checks passed after fixing missing prefixed schema references and Go-incompatible lookahead (exit 0, api 0.808s/eventrules 0.153s).

### Task 1 refinement and rulings

- Kept the full reduced catalog constraints and original examples; removed the
  duplicated API CloudEvent model tree in favor of a raw event object and SSE
  string boundary. The API schemas still validate stream configuration, filters
  and credentials. Existing API YAML outside these additive paths/schemas is
  byte-identical to HEAD after removing Task 1 additions.
- **Ruling:** anchor stream/event IDs to the spec's exact length and close event
  object/previous-object roots to their catalog fields. Metadata remains open.
  Recursive inventory paths enumerate identity/profileData fields individually;
  app_metadata/user_metadata remain customer-controlled arbitrary objects.
- **Ruling:** separate create/PATCH credential schemas from response schemas;
  password/token/header_value are write-only, required on create and omitted-secret
  preserving on PATCH. Runtime method-change validation belongs to Task 6.
- **Ruling:** canonical fetched OpenAPI URLs provide route provenance; delivery
  list scopes are alternatives, not a requirement for both scopes.
- Published deferred group examples fail their own group-ID pattern. Preserved
  their raw examples and strict schema, validated all 16 emitted examples, and
  recorded the upstream example mismatch without claiming deferred examples pass.
- E1–E8 remain open. No observer record created and no tenant observed.

Additional TDD evidence:
- Credential RED: `GOTOOLCHAIN=go1.26.7 go test ./api -run TestEventStreamCredentialContracts -count=1`
  failed on six absent create/PATCH credential schemas (test exit 1; shell wrapper
  printed the log and returned 0). Log: `/tmp/plan32-secret-red.log`.
- Credential GREEN: same command passed, exit 0 (0.106s); log
  `/tmp/plan32-secret-green.log`.
- Validator RED: `GOTOOLCHAIN=go1.26.7 go test ./internal/eventrules -count=1`
  failed, exit 1, on unanchored IDs and accepted password_hash. Exploring all
  examples also exposed the deferred group example mismatch. Log:
  `/tmp/plan32-validation-red.log`.
- Validator GREEN: same command passed, exit 0 (0.122s), with all 16 emitted
  examples plus negative IDs, version, missing-data, unknown-type, object secret,
  identity token and malformed-JSON cases. Log: `/tmp/plan32-validation-green.log`.
- Final generation: `GOTOOLCHAIN=go1.26.7 make generate`, exit 0;
  `/tmp/plan32-generate-final.log`.
- Final focused tests: `GOTOOLCHAIN=go1.26.7 go test ./api ./internal/eventrules -count=1`,
  exit 0 (api 0.477s, eventrules 0.148s); `/tmp/plan32-final-tests.log`.
- Earlier mgmt/app compile-only check passed, exit 0, with no tests run;
  `/tmp/plan32-compile.log`. No database or broad regression suite run for Task 1.

- Final generated-consumer compile check:
  `GOTOOLCHAIN=go1.26.7 go test ./internal/server ./internal/orgrules ./internal/mgmt ./internal/app -run '^$'`,
  exit 0; no tests selected (0.021s/0.005s/cached/cached), log
  `/tmp/plan32-compile-final.log`. Existing server adapter already embeds
  `mgmtapi.Unimplemented`, so Task 1 routes remain 501 until later handler tasks;
  no temporary runtime stub or unrelated handler edit was required.
- CLI discovery (offline): `AUTH0_CLI_ANALYTICS=false auth0 --version` reports
  1.37.0 (`a6239f907a81238e081a4abb1882c028558b2655`), exit 0;
  `auth0 --help`, exit 0, lists event-streams CRUD, trigger, deliveries,
  redeliver/redeliver-many and subscribe. Logs `/tmp/plan32-cli-version.log` and
  `/tmp/plan32-cli-help.log`. The preliminary `auth0 version` syntax failed
  (usage error); `--version` is the supported spelling. No tenant API call made.
- `git diff --check` passed, exit 0. Full suites, database tests, console/E2E and
  runtime acceptance are not run or claimed by Task 1.
- Task 1 commit: `docs: freeze Plan 32 event streams contracts` (the commit
  containing this entry). Controller review follows this implementation report.

### Task 1 important review fixes (base 10705b3)

- Closed all 30 user identity profileData schema branches across object and
  previous_object. **Ruling:** this is deliberately stricter than the published
  open schema, following the spec's recursive privacy allowlist. Cost: arbitrary
  undocumented profileData values are rejected. Customer app_metadata and
  user_metadata stay open, including arbitrary customer keys resembling secrets.
- Required subscription.event_type and reused the 25-type catalog enum. Tests
  exercise valid, absent and unknown types through actual create/PATCH schemas.
- Minor aws_partner_event_source readOnly annotation intentionally deferred by
  controller instruction; not included in this fix.
- RED: focused nested-privacy/subscription command failed, exit 1. All 60 nested
  secret combinations were accepted and four malformed create/PATCH subscription
  cases were accepted. `/tmp/plan32-review-red.log`.
- GREEN: same focused command passed, exit 0 (eventrules 0.139s/API 0.116s).
  `/tmp/plan32-review-green.log`. All five identity provider branches, both object
  roots and all three user types are covered; metadata openness is checked before
  injecting each prohibited nested field.
- `GOTOOLCHAIN=go1.26.7 make generate` passed, exit 0;
  `/tmp/plan32-review-generate.log`. Generated subscription.EventType is now a
  required catalog enum rather than an optional arbitrary string.
- Final `GOTOOLCHAIN=go1.26.7 go test ./api ./internal/eventrules -count=1`
  passed, exit 0 (API 0.777s/eventrules 0.178s), `/tmp/plan32-review-tests.log`.
- Generated-consumer compile command:
  `GOTOOLCHAIN=go1.26.7 go test ./internal/server ./internal/orgrules ./internal/mgmt ./internal/app -run '^$'`
  passed, exit 0 (server 0.042s, others cached; no tests selected),
  `/tmp/plan32-review-compile.log`.
- `git diff --check` passed, exit 0. No broad suites or database tests run.
- Fix commit: `fix: tighten event privacy and subscription contracts` (the commit
  containing this entry). No runtime implementation or minor review fix added.

## Task 2 — CloudEvent builder

- Added events Build, request Context, cryptographic event/stream IDs and Stamp.
  All emitted catalog examples validate after building; nested dotted allowlists
  remove identity/ProfileData tokens and hashes, while customer metadata remains
  open (including app_metadata.password). Source uses CanonicalHost, independently
  of request/custom domain, and times use UTC milliseconds.
- Extracted the existing user, identity, organization and connection response
  functions into internal/resourceview; existing Management API wrappers delegate
  there. Connection configuration sealing stays in the handler, and event build
  never decrypts sealed configuration. This avoids an events/mgmt import cycle
  for Task 8 without duplicating serializer logic.
- Prerequisite ruling: added only store.TenantEvent from Task 3's frozen contract;
  Task 3 extends internal/store/events.go. No Events interface was introduced.
- Request ruling: FromRequest uses httpx.ClientIP(r, false), which honors an
  authenticated boundary's recorded client IP but ignores untrusted forwarding
  headers. Resolved request host identifies a custom domain; source remains the
  tenant canonical host. Missing request/client/connection context is omitted.
- RED: `go test ./internal/events -run 'Build|IDFormats|Stamp' -count=1`
  failed with exit 1 before implementation: undefined Build, ErrNotEmitted,
  FromRequest, WithContext, NewEventID, NewStreamID and Stamp. Nine named task
  tests were written before production code. Log: /tmp/plan32-task2-red.log.
  Initial shell default was go1.27.3-X:nodwarf5; final verification uses required
  Go 1.26.7 explicitly.
- GREEN: `GOTOOLCHAIN=go1.26.7 go test ./internal/events -run 'Build|IDFormats|Stamp' -count=1`
  passed, exit 0, 0.273s. Log: /tmp/plan32-task2-green-1.26.log. Additional
  coverage exercises every emitted catalog example, invalid input, organization
  serialization, resolved custom domains and normal/invalid Stamp behavior.
- Compile: `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt ./internal/app -run '^$' -count=1`
  passed, exit 0, no tests selected. Log: /tmp/plan32-task2-compile.log.
- Self-review: checked serializer extraction equivalence and recursive projection;
  fixed import grouping and stored model time to UTC. `git diff --check` passed.
  No database, integration, broad or full suites run; these remain deferred to
  Task 14. No upstream observations and no dependencies added.
- Commit: `feat: build Auth0 CloudEvents` (this entry's containing commit).
