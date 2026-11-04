# Hosted login, MFA and passwordless review

## Summary
Overall the hosted login, MFA and passwordless paths are carefully built. Every
POST under `/u/*` checks the transaction, its browser cookie and the CSRF token
(`postedTxn`). Hosted steps use revision CAS, so parallel submits cannot race.
Sessions rotate on every login. Every route that issues a code or a device
approval goes through `approve → requireMFA`. Code and OTP proofs have durable
per-user throttles and per-code attempt caps. Reset requests do not reveal
whether an account exists.

I found one real MFA bypass. It is a race: a hosted *enrollment* transaction
does not re-check, when the code is confirmed, that the user is still
unenrolled. The other findings are a broken error redirect, two docs claims the
code does not back up, and small parity gaps.

Counts: 0 critical, 0 high, 3 medium, 5 low. **3 fix-before-1.0** (F1, F2, F3).

## Findings

### F1 [medium] [defect] Stale hosted MFA enrollment transaction lets a password-only attacker add a factor and finish MFA after the victim has enrolled
- Where: internal/login/mfa.go:617-640 (`proveMFA`), internal/authz/mfa.go:156-230 (`PendingMFA`), internal/mfa/service.go:312-320
- What: `Requirement.Enroll` is decided once at `/authorize` and sealed into the 15-minute MFA transaction (`TxnLifetime`, authz/handlers.go:37). When the code is confirmed, the hosted path calls `ConfirmEnroll`, not `ConfirmFirstEnroll` (unless it is a ticket or an Action enroll). Nothing re-checks that the user still has no usable factor. `PendingMFA` only re-checks blocked status and `RememberBrowserEpoch`, and enrolling a factor does not bump that epoch.
- Attack: an attacker who knows the password of a user with no factor keeps opening `/authorize` transactions, each one ending at enrollment. The victim then enrolls (for example TOTP) and believes the account is protected. Inside the window, the attacker confirms their own TOTP on an open transaction. That marks the session MFA-done (`MarkMFA`). `MFAComplete → finish → approve` then re-runs `Decide` with a non-zero `SessionMFAAt`, so a code is issued. The attacker also keeps a permanent second factor on the account.
- Evidence: the ROPG/MFA-API path already guards this correctly. internal/oauth/grant_mfa.go uses `svc.ConfirmFirstEnroll` for non-explicit enrollment. Only the hosted path is inconsistent.
- Verdict: CONFIRMED (code path traced; no runtime reproduction, since the repo is read-only)
- Recommendation: fix-before-1.0 (an MFA bypass class; one-line fix)
- Suggested fix: in `proveMFA`, use `ConfirmFirstEnroll` whenever `Requirement.Enroll` comes from policy, confidence or mfa-api, i.e. every reason except `action` with mode `enroll` (which keeps `WithNewFactorEnrollment`) and tickets with `allow_multiple`. Add a test: open an enroll transaction, confirm another factor out of band, then submit the stale transaction and expect `invalidCode`.

### F2 [medium] [defect] Invalid or stale MFA pages redirect to an unrouted `/authorize/resume` (404)
- Where: internal/login/mfa.go:40-42 (`mfaInvalid`), used by `loadMFA` at mfa.go:55,67,73
- What: any GET of an MFA page whose transaction is expired, already used or bound to a different session returns `303 /authorize/resume?error=invalid_request`. That path is not registered. internal/server/server.go:276-311 only routes `/authorize` (authapi), and no `/authorize/resume` handler exists anywhere in `internal/`. So the user gets a bare 404 instead of the hosted error page. Common triggers are Back or Refresh after finishing MFA, or opening the MFA link in a second tab.
- Evidence: `grep -rn authorize/resume internal` finds only mfa.go:41 and mfa_test.go:297. The test asserts the Location header but never follows it.
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0 (wrong result on the core login flow)
- Suggested fix: render `h.invalidTxn`/`ui.RenderErrorDetail` (the same page as `authz.invalidMFA`) instead of redirecting.

### F3 [medium] [docs-drift] Phone-provider protection `exponential` is documented as enforced but is stored only; the 2026-10-30 changelog feature is missing
- Where: docs/attack-protection.md:162-171; internal/tenantrules/phone.go:36,65; internal/mgmt/phone_protection.go; internal/mfa/phone.go; internal/login/phone_codes.go:44-62
- What: the docs say "`type: exponential` … adds send backoff to the existing IP, identifier and per-user budgets". Nothing reads `PhoneSettings.ProviderProtection`. The frozen `phonerules.Limits.Backoff*` values (D-0060 LR6) are also never used. Only static budgets apply. Operators who turn this on to stop SMS pumping get no backoff.
- Evidence: `grep -rn "\.ProviderProtection\|BackoffImmediate" internal` matches only the GET handler and the struct definitions. Changelog, October 30 2026: "it replaces static rate limits on outbound SMS verification requests with progressive delays … starting at 1 minute and scaling up to a maximum cooldown of 32 minutes … Logs throttled send attempts as `limit_phone`" (https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors/exponential-backoff-for-sms).
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0 for the docs (misleads people about a security control). Implementation defers to Plan 45 (operational hardening) or new plan.
- Suggested fix: change attack-protection.md (and the deploy-cli/tenant-settings mentions) to "stored, not enforced". Optionally enforce LR6 in `preparePhone` and `sendIdentifierCode` when `exponential` is set.

### F4 [low] [docs-drift] compat matrix still describes Plan 33/34 as pre-merge (passwordless "501", MFA/code templates "stored-only")
- Where: docs/compat/matrix.md:216-224 (Plan 34 section), :210-211, :57, :40
- What: the matrix says `/passwordless/start` and `verify_redirect` "answer `501 passwordless_unavailable` until Task 10". It says phone/SMS/voice configuration is "stored for Plan 34". The email-templates row says "code, MFA … remain stored-only". In code, passwordless is served (server.go:261), `mfa_oob_code` is sent (internal/mfa/email.go:14), and `verify_email_by_code`/`reset_email_by_code` are live (login/phone_codes.go:118-127). Plan 34 has been merged (d23dfad).
- Verdict: CONFIRMED
- Recommendation: fix-before-1.0 is cheap, but this is not a security issue, so it is not counted as a blocker. Fold it into the release docs pass.
- Suggested fix: refresh the Plan 33/34 sections and the email-templates row to match what is merged.

### F5 [low] [parity-gap] MFA enrollment tickets never offer the phone factor
- Where: internal/login/mfa.go:722-729 (`MFATicket` factor loop `[]string{"otp","email"}`); internal/mgmt/guardian_tickets.go:21 (factor is not validated)
- What: `POST /guardian/enrollments/ticket` accepts `factor: phone` (the OAS enum is `push-notification, phone, email, otp, webauthn-*`). The ticket page then has no factors and shows "invalid ticket". With no `factor` set, phone is never offered even when SMS MFA is enabled, although the hosted page can already enroll phone (`startMFAMethod`).
- Evidence: Management OAS `GuardianEnrollmentFactorEnum`; api/management.yaml:13514-13522.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-44 (remaining Universal Login modes) or a Plan 34 follow-up
- Suggested fix: add `phone` to the loop when `PhoneMethods` is non-empty. Reject unsupported ticket factors at creation, or document them as stored-only.

### F6 [low] [parity-gap] Signup verification codes live 5 minutes, not the frozen 900 s; the send budget is not connection-scoped
- Where: internal/login/phone_codes.go:44 (key has no `ConnectionID`, and signup/reset share `identifier-phone`) and :74 (`ExpiresAt: now+5m` for every kind)
- What: D-0060 freezes "Signup verification codes live 900 s; `limit_signup_otp` is scoped to tenant, identifier and connection" (`phonerules.Limits.SignupOTPLifetimeSeconds` = 900, which is never read). Signup codes expire after 5 minutes, and one budget is shared across connections and across the signup and reset purposes.
- Verdict: CONFIRMED
- Recommendation: defer-to-Plan-45
- Suggested fix: use `SignupOTPLifetimeSeconds` for `kind=="signup"`. Add `ConnectionID` and the kind to the protection key.

### F7 [low] [parity-gap] Side effects run before MFA: invitation acceptance, auto-membership and `last_login`/`logins_count`
- Where: internal/authz/handlers.go:370-388 (`Resume` → `acceptInvitation`/`claimInvitationCompletion` before `finish`/`approve`); internal/login/login.go:441-462 (`EnsureMembership` in the password commit); login.go:817 (`RecordLogin` in `complete`)
- What: with only the first factor, someone who knows the password can consume an organization invitation and create membership, and the login counters move, even if MFA is then abandoned. Tokens are still correctly withheld. This is the same family as the known M1 (consent before MFA) but these are separate side effects.
- Verdict: CONFIRMED (ordering); Auth0 ordering is PLAUSIBLE, not observed
- Recommendation: defer-to-Plan-45 (or fix together with M1)
- Suggested fix: move invitation acceptance and membership commit after `requireMFA` passes (in `approve`, just before code issue).

### F8 [low] [defect] A pre-MFA session is a full SSO session record
- Where: internal/login/login.go:809-821 (`complete` → `Sessions.Start` before `Resume`); internal/passwordless/redirect.go:303
- What: the session cookie and row are created before MFA, and MFA state lives only in `MFAAt`. Every code-issuing path re-checks MFA, so I found no token bypass. But the session shows up as an active session (Management sessions list, `logins_count`), and it replaces any MFA-completed session already in that browser. Auth0 establishes the session after MFA.
- Verdict: CONFIRMED (behaviour); no bypass found
- Recommendation: defer-to-Plan-45
- Suggested fix: mark sessions "pending MFA" and exclude them from session listings and from replacing a completed session, or create the session only after `requireMFA` passes.

## Checked with no finding
- CSRF: `postedTxn` (txn cookie hash + constant-time CSRF) on every `/u/*` POST, plus device and consent. Magic-link and typed-code confirmation are bound to a SameSite=Strict browser cookie inside the sealed state. The confirmation page shows the target identifier (D-0060).
- Session fixation: `Sessions.Start` deletes any presented session and issues a new token.
- MFA bypass paths: password, signup, social, passwordless (hosted and `verify_redirect`), invitation, org picker, `/continue`, consent and device all reach `approve → requireMFA`. `prompt=none` returns `interaction_required`. The MFA API needs MFA for users who have a factor. Remember-browser cookies are bound to tenant, user, kind and epoch.
- OTP brute force: 10 failures per user per factor per 15 min (durable). Email and SMS challenges allow 5 attempts each. TOTP step replay is blocked (`LastStep`). Passwordless allows 3 attempts per code with Plan 19 protection. Identifier codes allow 3 attempts, with 10 sends/h per identifier and 50/h per IP.
- Enumeration: reset requests always render the same page. Identifier-first never looks up the user. A blocked user is reported only after the password check (identity/database.go:106).
- Open redirect: hosted redirects use validated `redirect_uri`, internal paths, Action redirect URLs or a Management-set `result_url`.
- XSS: html/template everywhere. Custom text goes through `renderText` (escaped, https/mailto links only). Partials pass an allow-list validator.

## Changelog entries reviewed
(Coverage in `docs/compat/changelog-review.md` ends 2026-10-27; full text re-fetched 2026-11-03, 738,344 bytes.)
- 2026-10-30 — MFA: Exponential Backoff for Phone MFA SMS Delivery — relevant — **missing** (stored-only; see F3); implementation deferred to Plan 45/new plan
- 2026-10-29 — HTTP Message Signatures for Tenant Network ACLs — not this area — deferred to Plan 38 (network ACLs)
- 2026-10-27 — Universal Portals Developer Preview (consumer portal MFA enrollment, step-up) — relevant to MFA enrollment UX — already recorded → Plan 42

## Roadmap suggestions
- Add a "phone send backoff (exponential provider protection)" item to Plan 45, or to a Plan 34 follow-up, to enforce D-0060 LR6.
- Plan 45: move first-factor side effects (invitation, membership, login counters, M1 consent) after MFA, and add the pending-MFA session marker (F7, F8).
- Plan 44: phone (and later WebAuthn) factors on enrollment tickets (F5).
