# Plan 39b — Remaining social providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Data-driven provider descriptors for every remaining Auth0
social strategy (Tier 1, then Tier 2), the generic `oauth1` strategy,
Twitter on OAuth 2.0 and 1.0a, and the Google and Facebook native
exchanges.

**GitHub moved out (maintainer, 2026-11-18):** `github` is built by Plan 39c ([design](../specs/2026-11-16-zeroauthy-github-connection-design.md), [plan](2026-11-18-zeroauthy-plan-39c-github.md)) as a dedicated Go adapter. Leave it out of this plan's descriptors and Tier 1 group. After Task 2 (the descriptor framework), decide with the maintainer whether to port `github` to a descriptor plus hook, keeping Plan 39c's adapter tests green and public IDs unchanged.

**Architecture:** `internal/federation/providers/` (JSON descriptors + Go
loader + hooks), a generic descriptor-driven `Provider` on the Plan 24
core, `internal/federation/oauth1.go`, native exchanges on Plan 39a's
framework in `internal/oauth/grant_native_social.go`.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0, node-auth0 7.4.0, auth0-deploy-cli 9.1.0.

**Spec:** [Plan 39b design](../specs/2026-11-16-zeroauthy-social-providers-design.md). § refers to it.

**Gate:** provider order per ruling §8.1 (default Tier 1 → Tier 2).
**Depends on:** Plan 39a (native framework, client fields).

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Clean room.** Endpoints and profile fields from each provider's own
  docs, cited in the descriptor (`"source"` field) and D-0180.
- **Parity.** LR39b-1 and SP-1…9 in **D-0180**; follow-ups.
- **Never logged:** provider tokens and secrets, OAuth 1.0a secrets,
  `appsecret_proof`.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za39b GOTMPDIR=/dev/shm/za39b go test -p 4 ./...` plus
  `make e2e-social e2e-deploy`; push `plan-39b-social-providers`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan39b`, branch
  `plan-39b-social-providers`; record in
  `docs/superpowers/2026-11-16-plan-39b-implementation-record.md`.
- **Commits** signed off; one commit per provider group.

## Review Focus

1. **Email verification per provider** follows the descriptor rule and
   never defaults to true. Task 3 `TestDescriptorEmailRules`.
2. **OAuth 1.0a signatures** match RFC 5849 vectors; the request-token
   secret never leaves the sealed attempt. Task 5 `TestOAuth1Signatures`.
3. **Native Google ID token** with another app's `aud` → refused. Task 7
   `TestNativeGoogleAudience`.

---

### Task 1: Contracts and decisions
- [ ] `api/management.yaml` strategy enum and option schemas for every listed strategy; inventory entries; D-0180; follow-ups → commit `docs: freeze Plan 39b contracts and D-0180`. Ask for §8 rulings.

### Task 2: Descriptor format and generic provider
**Files:** `internal/federation/providers/schema.json`, `loader.go`, `generic.go`, tests.
- [ ] Tests: schema validation of every descriptor; generic authorize/exchange/profile with the fixture; hooks registry → implement → commit `feat(federation): descriptor-driven social providers`.

### Task 3: Tier 1 descriptors
**Files:** one descriptor per Tier 1 strategy, hooks (Facebook `appsecret_proof`, Salesforce identity URL and community/sandbox hosts, Shopify shop domain), rules in `internal/federation/rules`, tests.
- [ ] Tests per provider: option rules (switch → scope table), authorize URL, token exchange, profile mapping, `TestDescriptorEmailRules` (Review Focus 1), user ID → implement → commit per group (`feat(social): Facebook, LinkedIn`, `feat(social): Amazon, PayPal, Salesforce, Yahoo`, `feat(social): LINE, Dropbox, Box, Bitbucket, Shopify`).

### Task 4: Twitter/X
- [ ] OAuth 2.0 (PKCE) and OAuth 1.0a variants by `protocol`; email handling; tests → commit `feat(social): Twitter on OAuth 2.0 and 1.0a`.

### Task 5: Generic `oauth1`
**Files:** `internal/federation/oauth1.go`, rules, script context, tests.
- [ ] `TestOAuth1Signatures` (Review Focus 2), request-token flow, verifier check, `fetchUserProfile` context → implement → commit `feat(federation): generic OAuth 1.0a connections`.

### Task 6: Tier 2 descriptors (per ruling §8.2)
- [ ] Same test pattern as Task 3 for each Tier 2 strategy → commit `feat(social): Tier 2 providers`.

### Task 7: Native Google and Facebook
**Files:** `internal/oauth/grant_native_social.go` (new token types), Google JWKS verification (Plan 24 key cache), Facebook debug endpoint call, tests.
- [ ] Tests: `TestNativeGoogleAudience` (Review Focus 3); Facebook token validation and `user_profile`; flags off → `invalid_request` → implement → commit `feat(oauth): native Google and Facebook sign-in`.

### Task 8: Console, seed, Deploy CLI, E2E, docs, final verification
- [ ] Console picker and generated settings; seed; Deploy CLI round trip with Tier 1 connections; `make e2e-social` extended; docs (`docs/social-connections.md` provider table, marketplace `oauth2` examples per LR39b-1, compatibility files, `CHANGELOG.md`, roadmap, implementation record); fast tier + E2E; push; review; maintainer approval.
