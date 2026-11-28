# Plan 39d — Tier 2 social providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The 16 Tier 2 social strategies on the Plan 39b descriptor
framework (14 live, Fitbit and Instagram stored and refused), through nine
general descriptor features and one OAuth 1.0a descriptor mode.

**Architecture:** New descriptor keys in `internal/federation/providers`
(loader validation), their behaviour in `rules/social.go` and
`federation/social.go`, Evernote through the Plan 39b OAuth 1.0a core, the
stand-in in `tests/e2e/social/provider` learning each feature.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0, auth0-deploy-cli 9.1.0.

**Spec:** [Plan 39d design](../specs/2026-11-28-zeroauthy-social-tier2-design.md). § refers to it.

## Global Constraints

- **Rulings (maintainer, 2026-11-27/28):** fixtures only; retired providers stored and refused at sign-in; GitHub stays on its Plan 39c adapter; approach 1.
- **Decisions:** LR39d-n and SD-1…7 in **D-0182**; observation points in `docs/superpowers/plan-1-followups.md`.
- **Clean room:** endpoints from each provider's own docs, cited in the descriptor `source` and the inventory; anything unconfirmed is an SD point.
- **Strict loader:** every new key validated; unknown keys still refused.
- **Never logged or in errors:** access tokens (including query-parameter tokens), client secrets, OAuth 1.0a secrets.
- **Free scope (LR39d-1):** at most 20 tokens, each 1–128 printable characters without spaces or commas.
- **Exact hosts (LR39d-2):** `start.exactonline.nl`, `.be`, `.co.uk`, `.com`, `.de`, `.fr`, `.es`.
- **Token-response substitution:** values matching `^[A-Za-z0-9._-]{1,128}$` only, URL-escaped, into a fixed template.
- **Verification** per `AGENTS.md`: focused tests per task; final tier `go test -p 4 ./...` on `/dev/shm`, `make e2e-social-providers e2e-social e2e-deploy e2e-github`; push `plan-39d-social-tier2`; report CI.
- **Worktree:** `/mnt/nvme2/code/zeroauthy-plan39d`, branch `plan-39d-social-tier2`; record in `docs/superpowers/2026-11-28-plan-39d-implementation-record.md`.
- **Commits** signed off; build on `/dev/shm` (TMPDIR/GOTMPDIR), `/tmp` is often full.

## Review Focus

1. **Weibo `uid` from a hostile token response** (`../`, `@evil`, overlong) → refused before any profile call. Task 3 `TestTokenValueSubstitution`.
2. **Query-parameter access tokens** (Baidu, Untappd, VK) never appear in an error. Task 3 `TestQueryTokenNotInErrors`.
3. **Exact `baseUrl` outside the allowlist** (lookalike `start.exactonline.nl.evil.com`, http, path tricks) → 400. Task 2 `TestExactBaseURL`.
4. **Retired strategy** creates, reads, PATCHes and exports normally, but `/authorize` refuses with no upstream call. Task 4 `TestRetiredProviders`.
5. **Evernote's empty token secret** is accepted only for descriptors that declare it; generic `oauth1` still refuses it. Task 5 `TestEvernoteEmptySecret`.

---

### Task 1: Contracts, D-0182, roadmap correction
**Files:** `api/management.yaml`, `internal/federation/inventory.json` (`social_descriptors.tier2`), `docs/compat/decisions.md`, `docs/superpowers/plan-1-followups.md`, roadmap, `docs/superpowers/README.md`, D-0180, 39b record.
- [ ] Add the 16 strategies to the strategy enum with `ConnectionOptionsSocialFreeScope` (client_id, client_secret, scope) and `ConnectionOptionsExact` (`baseUrl`, `profile`); Evernote under `ConnectionOptionsOAuth1Common`; note retired strategies.
- [ ] Inventory rows per strategy: endpoints, auth, user id, email rule, status (`live`/`retired`/`unverified`), sources; SD-1 for anything unconfirmed.
- [ ] D-0182 (rulings, LR39d-1/2, SD-1…7); replace "the next batch ports GitHub" in roadmap, README, D-0180 and the 39b record with the 2026-11-28 ruling.
- [ ] `go test ./internal/federation/ -run Inventory` passes; regenerate `internal/gen/mgmtapi`; commit `docs: freeze Plan 39d contracts and D-0182`.

### Task 2: Descriptor format and rules
**Files:** `internal/federation/providers/loader.go`, `providers_test.go`, `internal/federation/rules/social.go`, `social_test.go`.

**Interfaces — Produces** (Descriptor fields, JSON names in brackets): `TokenMethod` [`token_method`: "GET"|"POST"], `TokenClientAuth` adds `"query"`, `TokenResponsePath` [`token_response_path`], `TokenAccept` [`token_accept`], `RedirectParam` [`redirect_param`], `AuthorizeParams`/`TokenParams`/`ProfileParams` [`authorize_params`, …: map[string]string], `ProfileAuth` adds `query:<p>` and `scheme:<S>`, `Retired *Retired{Date, Reason, Source}` [`retired`], `FreeScope bool` [`free_scope`], `BaseURLHosts []string` [`base_url_hosts`], `Protocol` [`protocol`: ""|"oauth1"] with `OAuth1 *OAuth1Endpoints{RequestTokenURL, AccessTokenURL, AuthorizationURL, EmptySecret}` [`oauth1`]. Lookup gains `name[N]`; profile paths may start with `token:`. `rules.SocialSettings` gains `BaseURL string`.
- [ ] Tests first: `TestParseStrict` cases for each new key (bad method, unknown auth, param names with `=`/spaces, retired without reason, `free_scope` with flags, `oauth1` without URLs); `TestLookup` adds `d.results[0].UserID` and out-of-range `[5]`; rules `TestSocialFreeScope` (default base scopes; operator array and string accepted; 21 tokens, a space, a comma → error; returned as stored); `TestExactBaseURL` (each allowlisted host OK; lookalike, http, userinfo, path, port → error; endpoints built under it; `profile` stored only).
- [ ] Implement loader validation and rules; commit `feat(federation): descriptor features for Tier 2`.

### Task 3: Generic provider features
**Files:** `internal/federation/social.go`, `social_test.go`.
- [ ] Tests first against the existing `socFixture` with synthetic descriptors (as `TestSocialPKCENone`): `TestTokenRequestShape` (GET with query credentials, nested `response.access_token`, form-encoded answer turned to JSON via `token_accept`); `TestRedirectParamAndFixedParams` (`redirect_url` on authorize and token, `type=web_server` both places, `v` on profile); `TestProfileAuthModes` (`query:access_token`, `scheme:OAuth`); `TestTokenValues` (`token:user_id`, `token:email` mapped; `{token.uid}` substituted); `TestTokenValueSubstitution` (Review Focus 1: `../x`, `a@b`, `a/b`, 129 chars, missing → `ErrProviderResponse`, zero profile calls); `TestQueryTokenNotInErrors` (Review Focus 2: profile 401/500/garbage with a query token → error text lacks the token and URL).
- [ ] Implement in `socialProvider`; commit `feat(federation): Tier 2 provider features`.

### Task 4: Live OAuth 2.0 descriptors and retired providers
**Files:** one JSON per strategy in `internal/federation/providers/`, hooks generalization in `social_hooks.go`, `tier1_test.go` table (rename file to `descriptors_table_test.go`), `providers/inventory_test.go`.
- [ ] Add `tier1Cases`-style rows for baidu, bitly, daccount, dwolla, exact, planningcenter, soundcloud, thirtysevensignals, untappd, vkontakte, weibo, wordpress, yandex (subject, email, `email_verified` per inventory) → RED; `TestDescriptorsMatchInventory` extended to the `tier2` rows.
- [ ] `TestRetiredProviders` (Review Focus 4): fitbit and instagram create/read/PATCH via `newConnEnv` → 201/200; `SocialEndpoints` → `ErrConnectionUnusable` with the reason; flow `Begin` makes no fixture request; LinkedIn v1/v2 behaviour unchanged.
- [ ] Write the descriptors; replace the LinkedIn-only refusal with a generic retired check (LinkedIn keeps its version hook); commit per group: `feat(social): Baidu, Bitly, d Account, Dwolla, Exact`, `feat(social): Planning Center, SoundCloud, 37signals, Untappd`, `feat(social): VK, Weibo, WordPress, Yandex; Fitbit and Instagram retired`.

### Task 5: Evernote on an OAuth 1.0a descriptor
**Files:** `evernote.json`, `evernote-sandbox.json`, `internal/federation/oauth1.go`, `rules/social.go`, tests.
- [ ] Tests first: `TestEvernoteFlow` (o1Fixture at `/evernote/oauth`: request token, verifier, access response `oauth_token=…&oauth_token_secret=&edam_userId=123&edam_shard=s1` → user `evernote|123`, no email, token stored); `TestEvernoteEmptySecret` (Review Focus 5: empty secret OK for evernote; generic `oauth1` and twitter oauth1 still refuse it).
- [ ] Route descriptors with `protocol: oauth1` through `oauth1Provider` (rules set `Settings.OAuth1` from the descriptor); profile from the access-token response through `token:` paths; commit `feat(social): Evernote on OAuth 1.0a`.

### Task 6: Console, seed, stand-in, E2E, docs, final verification
**Files:** `providers/console.go` (+ `retired`, `free_scope`, `base_url_hosts`), regenerated `descriptors.json`, `console/src/pages/connections/social/{social.ts,DescriptorOptions.vue}`, tests; `internal/seed` test; `tests/e2e/social/provider/descriptor.go` (each new feature, Evernote OAuth 1.0a), `TestSocialStandIn` over every live strategy; `tests/e2e/m39b-social.spec.mjs` and `m39b-social-deploy.mjs` extended; docs (`docs/social-connections.md`, matrix, CHANGELOG, record).
- [ ] Console: free-scope text field, Exact region select, retired banner (create still allowed); vitest cases for each.
- [ ] Stand-in learns the features; `TestSocialStandIn` green for all live Tier 2; browser lane signs in to each live Tier 2 strategy and checks a retired one refuses; Deploy CLI round trip includes all 16.
- [ ] Fast tier + E2E lanes; two clean-clone `make console` builds identical; self-review; push; report CI; maintainer approval.
