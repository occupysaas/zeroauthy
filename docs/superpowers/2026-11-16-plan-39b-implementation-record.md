# Plan 39b implementation record

Status: **implemented and verified locally**, on `plan-39b-social-providers`
(worktree `/mnt/nvme2/code/zeroauthy-plan39b`), based on `main` after PR #104.
Plan-branch CI and maintainer approval pending.

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

Recorded in the final report and below as runs complete.

## Follow-ups and rulings for the maintainer

- GitHub stays on its Plan 39c adapter; porting it to a descriptor is a
  maintainer decision (plan, "GitHub moved out").
- SP-3: Auth0 documents no native Google `subject_token_type`; the local URN
  `http://auth0.com/oauth/token-type/google-id-token` is used.
- The spec's "client's allowed native audiences" for Google has no client
  field; only the connection's `client_id` is accepted.
- Tier 2 providers: a later plan (maintainer ruling).
