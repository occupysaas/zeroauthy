# Authentication API and OAuth/OIDC protocol review

## Summary
The core protocol paths hold up: authorization code with S256 PKCE (required for public clients at `/authorize` and again at `/oauth/token`), exact redirect_uri matching with a single-label https wildcard, code replay that revokes the code's refresh family, atomic refresh rotation with family revocation, revocation, `/v2/logout` and `/oidc/logout` validated before the session ends, userinfo audience/type/expiry checks, origin binding and client authentication. No critical or high defect was found. Findings: 0 critical, 0 high, 2 medium, 3 low. 1 is fix-before-1.0: the `/oauth/token` `invalid_grant` contract (status and wording) differs from what the repo's own Auth0 observations recorded. The rest are refresh-rotation parity details, a redirect_uri strictness gap and one stale matrix line.

Known follow-ups re-checked (not re-reported): deleting a user grant (`DELETE /api/v2/grants/{id}`, `/grants?user_id=`) still leaves its refresh tokens valid (`internal/mgmt/grants.go:49-89`; Auth0: "When a grant is revoked, so are all tokens issued in the context of that grant", https://auth0.com/docs/secure/tokens/refresh-tokens/revoke-refresh-tokens). The refresh grant also does not re-check `allow_offline_access`. Neither is a 1.0 blocker, but the first should be named in the 1.0 compatibility page.

## Findings

### F1 [medium] [parity-gap] `/oauth/token` `invalid_grant` uses status 400 and its own wording where Auth0 was observed returning 403 and fixed messages
- Where: `internal/oauth/errors.go:100-102` (`invalidGrant` uses 400); `internal/oauth/grant_password.go:30,191` (`"wrong email/username or password"`); `internal/oauth/grant_refresh_token.go:43` (`"invalid refresh token"`); `grant_authorization_code.go` (all `invalidGrant`); `grant_passwordless.go:80`.
- What: a wrong password on the password and password-realm grants returns `400 invalid_grant "wrong email/username or password"`. An unknown, revoked or reused refresh token returns `400 invalid_grant "invalid refresh token"`. The repo's own observations of Auth0 record `403 invalid_grant` for a wrong password-realm password, the text `Wrong email or password.`, and `invalid_grant "Unknown or invalid refresh token."` for a deleted refresh token. The same code already uses 403 for `Password change required.` (`grant_password.go:194`) and for every device-flow `invalid_grant`, so the inconsistency is internal too.
- Evidence: `docs/compat/observations/organizations.md:307` ("password-realm | allow | wrong password … | 403 | `invalid_grant`"); `docs/compat/observations/management-jobs.md:86-87` (403 `Password change required.`; "`Wrong email or password.`"); `docs/compat/observations/management-users.md:102` ("A deleted refresh token gives `invalid_grant` "Unknown or invalid refresh token.""). No D-entry chooses 400 or the current wording (D-0017 fixes only the code). Impact on SDKs is PLAUSIBLE: native Auth0 SDKs classify invalid credentials and deleted refresh tokens by `error` plus description and/or status, so they will misclassify these errors.
- Verdict: CONFIRMED (the code differs from the recorded observations); SDK impact PLAUSIBLE
- Recommendation: fix-before-1.0. This is the core login and refresh error contract, the fix is small, and the evidence is already in the repo.
- Suggested fix: give `/oauth/token` `invalid_grant` status 403 for user grants (password, password-realm, passwordless OTP, refresh, code; Auth0's 403 for code and refresh is PLAUSIBLE, so record it in a D-entry). Use `Wrong email or password.` and `Unknown or invalid refresh token.` as the descriptions. Keep `/oauth/revoke`'s 400 (D-0013).

### F2 [medium] [parity-gap] Turning on rotation does not convert a client's existing non-rotating refresh tokens
- Where: `internal/oauth/refresh.go:85` (`Rotating` is copied onto each token when it is issued); `internal/oauth/grant_refresh_token.go:70,166-188,212` (branches on the token's stored `rt.Rotating`, not on the client's current policy).
- What: after a client's `rotation_type` changes to `rotating`, its earlier tokens keep `Rotating=false`. Exchanging one only extends its idle expiry (`Touch`) and returns no new refresh token. The token stays a long-lived reusable bearer credential with no reuse detection, and other non-rotating tokens of the client are not removed. The reverse change has the matching effect: rotating tokens keep rotating.
- Evidence: https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation: "Exchanging a non-rotating refresh token issues a new rotation refresh token" and it "deletes all the non-rotating tokens issued for the same `client_id`."
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45 (security hardening), or a new "Refresh tokens II" plan (see Roadmap)
- Suggested fix: in the refresh grant, when the client is now rotating and `rt.Rotating` is false, rotate into a rotating token in the same family (new absolute expiry from the policy). In the same transaction, revoke the client's other non-rotating tokens.

### F3 [low] [defect] The rotation leeway accepts tokens older than the previous one
- Where: `internal/store/sqlstore/refresh_tokens.go:123-130`, `internal/store/memory/refresh_tokens.go:106-113`
- What: the leeway is measured only from the presented token's own `rotated_at`. In a chain A→B→C built inside one leeway window, presenting A (second-to-last) still succeeds and starts another branch instead of triggering breach detection. The grant-side early check (`grant_refresh_token.go:70-79`) has the same rule.
- Evidence: configure-refresh-token-rotation page: "Only the previous token can be reused; if the second-to-last one is exchanged, breach detection will be triggered."
- Verdict: CONFIRMED (code path; only reachable with `leeway > 0`, default 0)
- Recommendation: defer-to-Plan-45
- Suggested fix: inside the leeway, accept a rotated token only if its direct successor has not itself been rotated (track the successor ID, or a per-family generation counter). Otherwise treat it as reuse.

### F4 [low] [parity-gap] `/authorize` requires `redirect_uri`; Auth0 documents it as optional
- Where: `internal/authz/validate.go:40-42`
- What: a request without `redirect_uri` gets the error page "redirect_uri is required". Auth0's Authentication API reference lists `redirect_uri` as optional for the code and PKCE flows. What Auth0 does without it (presumably the first allowed callback) is not documented, so this is PLAUSIBLE. D-0006 records exact matching, not the requirement.
- Evidence: https://auth0.com/docs/api/authentication/authorization-code-flow-with-pkce/authorize-with-pkce (`redirect_uri`: Optional).
- Verdict: PLAUSIBLE
- Recommendation: defer-to-Plan-41
- Suggested fix: observe Auth0's behaviour without `redirect_uri`. Either default to the client's first non-wildcard callback (store it on the code so the token-endpoint comparison still works) or record the deviation in D-0006.

### F5 [low] [docs-drift] The compatibility matrix still says OIDF certification is pending
- Where: `docs/compat/matrix.md:72-74`
- What: Basic, Config and Form Post OP rows say "certification: pending", but README.md:361 and docs/conformance.md:74 record certification of commit `38b4229` on 2026-10-30. The 1.0 plan generates the public "what's compatible" page from this matrix. The RP-Initiated row (75) correctly stays uncertified.
- Evidence: README.md:361; docs/conformance.md:74
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0 is cheap, but by the brief's rule this is low; do it with the first-run docs (Plan 46)
- Suggested fix: change the three rows to "certified 2026-10-30 (commit 38b4229)".

## Checked and found correct (no finding)
- PKCE: S256 only; public clients need `code_challenge` at `/authorize` (`validate.go:118-127`), and the token endpoint refuses a challenge-less code for a public client and a stray verifier (`grant_authorization_code.go:85-97`). The verifier's grammar is checked and the comparison is constant time.
- redirect_uri: exact match, or https single-label wildcard with the same path and query; fragment and userinfo rejected; checked again at the token endpoint. `form_post` and `web_message` restricted; the web_message target origin must be a strict origin.
- Codes: 60 s, single use, hashed, origin-bound; replay revokes the code family, including a replay in the middle of an exchange (`grant_authorization_code.go:150-166`).
- Refresh: ownership and origin checked before any revocation; reuse is detected before the expiry and scope checks; rotation and reuse revocation are atomic and serialized (SQL `FOR UPDATE`, `revokeUntilStable`). Narrowing `scope` only narrows; the user's Version is checked at mint.
- `/oauth/revoke`: client authentication enforced, a token of another client refused untouched, family revoked (D-0013).
- Logout: `/v2/logout` `returnTo` is validated against the client's list (or the tenant's) before the session ends. Go's parser rejects host-confusion inputs (backslash, encoded `@`, userinfo), checked with a scratch program. `/oidc/logout` matches `post_logout_redirect_uri` exactly, checks `id_token_hint` issuer, audience and signature, binds the confirmation CSRF to a cookie, and appends `state` correctly.
- Userinfo: RS256 only, `typ` JWT/at+jwt, issuer, userinfo audience, `exp`, `openid` scope and an active user are all required.
- Client auth: one method only; registered method enforced; malformed Basic not silently ignored; secrets compared in constant time; expired secrets skipped.
- Actions `event.request.body` strips credentials (`internal/actions/event.go:176,379`).

## Changelog entries reviewed
Reviewed-through in `docs/compat/changelog-review.md` is 2026-10-27. I fetched https://auth0.com/changelog/llms-full.txt (738,344 bytes) on 2026-11-03.
- 2026-10-29 — HTTP Message Signatures added to Tenant Network ACLs — not relevant to this area (tenant ACLs).
- 2026-10-30 — Exponential backoff for phone MFA SMS delivery — not this area (MFA/phone; Plan 34/45).
- No other entries after 2026-10-27. Earlier entries in this area were re-checked against the backlog. MRRT (2025-08-11/2026-04-14), online refresh tokens (2026-05-11), refresh-token metadata and bulk revoke (2026-06), private-key-JWT audience (2025-10-10) and federated logout (2025-04/2026-05) are all logged as open backlog rows. The Resource Parameter Compatibility Mode (GA, MCP launch entry) is covered only as the inert tenant field `resource_parameter_profile`. It is deferred, but no plan owns it; see the Roadmap.

## Roadmap suggestions
- Name a plan for "Refresh tokens II": MRRT (`refresh_token.policies`, refresh with a different `audience`), online/session-bound refresh tokens, the rotation migration in F2 and the leeway rule in F3, plus revoking refresh tokens when a user grant is deleted (the Plan 9 follow-up). Today these sit under "Later (refresh tokens)" with no plan number. Plan 45 or a new Plan 35b would fit.
- Put the RFC 8707 `resource` parameter alias (`resource_parameter_profile: compatibility`) into Plan 35 (token exchange) or Plan 41. Auth0 markets it for MCP clients, and the repo stores the setting but does not act on it.
- Plan 45 (rate limiting) could add Auth0's `X-RateLimit-*` headers on `/userinfo`, which the Authentication API reference documents.
