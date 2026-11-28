# Plan 39d implementation record

Status: **merged** 2026-11-28 (PR #107, merge commit `bffaac2e`), from
`plan-39d-social-tier2`, based on `main` after PR #106. Plan-branch CI green
(run 46094178117; one rerun of an unrelated `internal/adhub` timing flake,
recorded on the PR).

Plan: [Plan 39d](plans/2026-11-28-zeroauthy-plan-39d-social-tier2.md). Spec:
[Tier 2 social providers](specs/2026-11-28-zeroauthy-social-tier2-design.md).
Decisions: D-0182 (LR39d-1…6, SD-1…7). Guide:
[social connections](../social-connections.md). No live provider or Auth0 call
was made.

Maintainer rulings (2026-11-27/28): fixtures only; retired providers stored and
refused at sign-in; GitHub stays on its Plan 39c adapter; approach 1 (general
descriptor features).

## What was built

1. Task 1: contracts (strategy enum, `ConnectionOptionsSocialFreeScope`,
   `ConnectionOptionsExact`, `ConnectionOptionsEvernote`), inventory rows,
   D-0182, SD-1…7, the GitHub note corrected.
2. Task 2: descriptor keys (token request shape, redirect name, fixed
   parameters, profile auth modes, token values, `[N]` paths, retired, free
   scope, base URL hosts, OAuth 1.0a protocol) and their option rules.
3. Task 3: the generic provider's token request builder, auth modes, token
   values and bounded URL substitution; the E2E stand-in learned them all.
4. Task 4: 11 OAuth 2.0 descriptors (plus WordPress and Exact from Task 2);
   Fitbit and Instagram retired.
5. Task 5: Evernote on an OAuth 1.0a descriptor.
6. Task 6: console, seed, stand-in OAuth 1.0a, the E2E lane and Deploy CLI
   cells extended to Tier 2, docs.

## Verification

Local, 2026-11-28, at `8cf12839`, TMPDIR/GOTMPDIR on `/dev/shm`:

- `go test -p 4 ./...` (no `-race`): exit 0, 124 packages ok.
- `make e2e-social-providers`: exit 0; 33 Chromium tests (every live Tier 1
  and Tier 2 strategy, retired Fitbit/Instagram refusal, denial, Shopify
  without a shop) and the Deploy CLI 9.1.0 YAML and directory cells with 32
  connections.
- `make e2e-social`, `e2e-deploy`, `e2e-github`, `e2e-apple`: exit 0
  (`E2E_CHROMIUM` set to the system Chromium).
- Console: `vitest run` 779 tests, `vue-tsc` and `eslint` clean; two
  clean-clone `make console` builds identical and committed.
- Final review: self-review (subagents only on request); no Critical or
  Important findings.
