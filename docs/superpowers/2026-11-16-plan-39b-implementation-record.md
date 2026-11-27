# Plan 39b implementation record

Status: **merged** 2026-11-27 (PR #105, merge commit `36d42f16`), from
`plan-39b-social-providers`, based on `main` after PR #104. Plan-branch CI
green (run 45970075639, 70 checks).

Plan: [Plan 39b](plans/2026-11-16-zeroauthy-plan-39b-social-providers.md).
Spec: [remaining social providers](specs/2026-11-16-zeroauthy-social-providers-design.md).
Decisions: D-0180 (LR39b-1…11, SP-1…9). Operator guide:
[social connections](../social-connections.md). Sources: Auth0's Management
OpenAPI and social connection pages, and each provider's developer
documentation, cited per strategy in the descriptors and in
`internal/federation/inventory.json` (`social_descriptors`). No live provider
or Auth0 call was made.

Maintainer rulings (2026-11-27): Tier 1 in the listed order; Tier 2 in a later
plan (Task 6 not built); fixture providers only, no live checks.

## What was built

1. Task 1: the Tier 1 strategies and `oauth1` in the OpenAPI strategy enum
   with `ConnectionOptionsSocial`, per-strategy schemas and
   `ConnectionOptionsOAuth1`; the inventory's `social_descriptors`; D-0180;
   SP-1…9.
2. Task 2: `internal/federation/providers` (embedded JSON descriptors, strict
   decoding plus validation as the schema), `rules.parseSocial`, the generic
   `socialProvider`, the fixture rewrite and hook registry, and the
   `social.v1` store capability (memory, SQL, events, gRPC RPC) gating
   connections, users, identity keys, attempts and imports.
3. Task 3: Facebook (`appsecret_proof`), LinkedIn (versions 1 and 2 refused),
   Amazon, PayPal and sandbox, Salesforce, sandbox and community (identity URL
   on the token host), Yahoo, LINE (ID-token email via verify), Dropbox, Box,
   Bitbucket (emails endpoint) and Shopify (shop from `login_hint`).
4. Task 5 (built before Task 4, ruled): `internal/federation/oauth1sig` (RFC
   5849 signatures), the `oauth1` strategy, request-token attempts, callback
   binding, sealed token secrets, OAuth 1.0a profile scripts with
   host-signed `request.get({oauth})`, `access_token_secret` exposure.
5. Task 4: Twitter on OAuth 2.0 (descriptor) and 1.0a (verify_credentials).
6. Task 7: native Google ID-token and Facebook session-info exchanges on the
   generalized Plan 39a native framework.
7. Task 8: console (descriptor form from the generated `descriptors.json`),
   seed coverage, the `make e2e-social-providers` lane (every Tier 1 strategy
   through Chromium; Deploy CLI 9.1.0 YAML and directory round trip with one
   connection per strategy), docs.

## Verification

Local, 2026-11-27, at `df2e8b07`, TMPDIR/GOTMPDIR on `/dev/shm`:

- `go test -p 4 ./...` (no `-race`): exit 0, 124 packages ok.
- `make e2e-social-providers`: exit 0; 17 Chromium tests (every Tier 1
  strategy, denial, Shopify without a shop) and the Deploy CLI 9.1.0 YAML
  and directory cells with 15 connections.
- `make e2e-social`: the first run failed to launch Playwright's bundled
  browser (not installed on this host); rerun with
  `E2E_CHROMIUM=$(command -v chromium)`: exit 0.
- `make e2e-deploy`, `make e2e-apple`, `make e2e-github`: exit 0.
- Console: `vitest run` 774 tests, `vue-tsc` clean, `eslint` clean; two
  clean-clone `make console` builds identical and committed.
- Final review: self-review (subagents only on request); no Critical or
  Important findings. Deferred minors are in the final report.

## Maintainer rulings after review (2026-11-27)

- GitHub stays on its Plan 39c adapter in this plan; the next social batch
  (Tier 2) ports it to a descriptor, with Plan 39c's adapter tests as the
  acceptance tests and public IDs unchanged.
- SP-3: the local native Google URN
  `http://auth0.com/oauth/token-type/google-id-token` stands.
- Native Google accepts only tokens whose `aud` is the connection's
  `client_id`; no extra audiences.
