# Plan 24 implementation record

Social connections (Google, custom OAuth 2) and basic back-channel OIDC.
Branch `plan-24-social-connections`, baseline `b54388f`. Operator guide:
[social-connections.md](../social-connections.md).

## Acceptance map

| Criterion | Evidence |
|---|---|
| AC1 inventory | `internal/federation/inventory.json`, `TestFederationInventory`; observation gaps and changelog status in `docs/compat/observations/social-connections.md` |
| AC2 storage | `pkg/storetest` Federation suite on memory, gRPC (memory and SQLite servers), SQLite/PostgreSQL/MySQL; `TestMigration0021*` backfill and abort; `TestFederationIndependentHandles`; `TestOldPluginFederationUnavailable` |
| AC3 adapters | `TestOIDCValidation`, `TestGoogleAdapter`, `TestOAuthExchange`, `TestFederationTransport`, `TestProfileScript`, `TestScriptBroker`; m24 browser logins through actual code exchange for all three adapters |
| AC4 races | `TestSocialCallbackRace` (replay, wrong browser/host, malformed, concurrent callbacks, config change, disable, delete, block, user deletion without resurrection, transaction end), `TestSocialDomainRemovedDuringCallback`, `TestFederatedIdentityLifecycle` concurrent provisioning |
| AC5 secrets/tokens | `TestSocialConnectionsContract`, `TestIDPTokenProjection`, `TestIDPTokenScopeNotImplied`, `TestFederatedToken`; m24 SDK token scope checks |
| AC6 browser paths | `TestSocialLoginFlow` (explicit, buttons, hidden, social-only, prompt=none, denial), `TestSocialCaptchaOnExplicitSelection`, `TestSocialIdentifierFirst`, `TestSocialProtection`; m24 Playwright (6 cases). Device/consent use the unchanged resume path; no dedicated social device/consent browser case |
| AC7 clients/migration | node-auth0 7.4.0 and auth0-cli 1.37.0 (m24). **Not done:** strict Deploy CLI social fixtures with materialized scripts and secret reinjection |
| AC8 console/docs | social Vitest specs (14), `make console`; operator guide |

## Review

Self-review against the five Review Focus items (no reviewer subagent was
dispatched in this session; a fresh review is advisable before merge). Fixed:
the pre-commit origin recheck compared the request origin with itself; it now
re-resolves the callback host binding (`TestSocialDomainRemovedDuringCallback`,
RED proven). The browser lane also found that Chromium applies the login
page's `form-action` to the redirect after a social POST; posted choices now
hand off through an auto-submitted GET page limited to the provider origin.
Deferred minors are listed in `plan-1-followups.md`.

## Verification (2026-10-26)

| Check | Actual result |
|---|---|
| Three SQL dialects | `./scripts/test-sql.sh ./internal/store/sqlstore/... -timeout=30m`: exit 0, 954.426s |
| Generation | `go generate ./...` twice: exit 0, no diff |
| Sources / vet | `make check-sources`: exit 0; `go vet ./...`: exit 0 |
| Full Go race | `go test -race -timeout=30m ./...`: exit 0, 65 packages ok |
| Console | `make console`: exit 0, 53 files / 386 tests, build |
| Social E2E | `make e2e-social`: exit 0; SDK setup/verify, 6 browser cases, CLI |
| Deploy CLI | `make e2e-deploy`: exit 0 (existing lanes only; no social fixtures) |
| Baseline / branding / email / domains | `make e2e`: exit 0 (24 passed, 15 skipped); `e2e-branding`: 4 passed; `e2e-email`: 1 passed; `e2e-domains`: exit 0 |
| Conformance (local, not certification) | basic 21 pass/0 fail/6 warn/4 review/4 skip; config 1 pass; form-post 21/0/6/4/4; RP logout 3 pass/8 review |
| Live Google / Auth0 observation | Not run (unavailable; no credentials authorized) |
