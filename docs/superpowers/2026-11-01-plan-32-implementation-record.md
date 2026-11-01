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
