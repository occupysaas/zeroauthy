# Plan 37a implementation record

Status: **implementation and local verification complete**, starting from
`main` commit `5cf04cfa` (PR #79 merged). Branch: `plan-37a-saml`; worktree:
`/mnt/nvme2/code/zeroauthy-plan37a`. Full plan-branch CI and maintainer
approval govern integration.

Spec: [SAML design](specs/2026-11-16-zeroauthy-saml-design.md). Plan:
[Plan 37a](plans/2026-11-16-zeroauthy-plan-37a-saml.md). Decisions: D-0130
(LR37a-1…20). Operator guide: [SAML](../saml.md).

## Progress

1. Task 1: contracts (OpenAPI, D-0130, observation points) frozen.
2. Tasks 2–4: `internal/samlcore` on vendored goxmldsig v1.6.1 and etree
   v1.8.1 (safe parsing, exclusive c14n, wrapping-resistant verification,
   XML-Enc, messages, bindings, metadata, fuzz target).
3. Tasks 5–6: IdP add-on (`addons.samlp`), SSO, IdP-initiated SSO, metadata,
   single logout, `api.samlResponse`; migration 0044, `saml.v1` capability.
4. Tasks 7–8: `samlp` connections, SP login, encrypted assertions, replay
   store, `metadataUrl`, SP metadata and single logout.
5. Task 9: console (add-on tab, SAML connection pages), seed, preserved-ID
   bootstrap and federation import.
6. Task 10: `make e2e-saml`, docs, local verification, review.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; Node 26.

| Check | Result |
|---|---|
| Focused Go tests per task (`task-done` ledger) | passed |
| Console: Vitest 741 tests, `vue-tsc`, ESLint | passed |
| `make console` twice | second and third builds identical file contents; dist committed |
| `make e2e-saml` (`tests/e2e/run-m37a-saml.sh`) | Playwright 3 passed (node-saml 5.2.0 SP login and signed SLO both ways; unsigned LogoutRequest refused; samlify 2.15.1 IdP login and upstream signed SLO), secret scan passed, Deploy CLI four cells passed |
| Fast tier `go test -count=1 ./...` (no `-race`, tmpfs), commit `54352163` (pre-review) | first run exit 1: `internal/federation/script` (`TestProfileScript/cancellation_releases_the_slot` timeout) and `internal/noderunner` (two cancellation-timing tests) failed while the fuzz smoke and govulncheck ran concurrently; both packages passed when rerun alone; 109 other packages ok |
| Fuzz smoke `FuzzParse` 60 s (`internal/samlcore`) | passed, 291,742 executions |
| `govulncheck` v1.10.0 | no vulnerabilities (v1.1.4 panics on this toolchain's AST) |
| zizmor | not installed locally; runs in CI (one matrix value added) |

## Findings during the plan

- **Events decorator hid the SAML store interfaces.** In production the
  store is wrapped by `internal/events`; the wrapper did not forward
  `SAMLReplayStore`, so every SP login failed on the commit transaction,
  and `CheckSAMLSupport` reported support for any wrapped store. Found by
  the E2E lane; fixed with `TestDecoratorForwardsSAMLReplay` and the
  capabilities test.
- **Deploy CLI certificate form.** The pinned CLI exports `signingCert` as
  base64 of the PEM and imports it unchanged; the rules now accept that
  form (S37-16, `TestParseSAML`).
- **`AuthnStatement` not required** in upstream responses (S37-15),
  recorded as an observation.
- The E2E fixtures needed samlify configuration (short binding names,
  spliced statements because `replaceTagsByValue` escapes values, and
  `wantLogoutResponseSigned` on the SP entity).

## Rulings

Implementation rulings are LR37a-4…20 in D-0130; the per-task ledger is in
`.superpowers/sdd/2026-11-16-zeroauthy-plan-37a-saml/progress.md`.

## Whole-branch review

One independent security-focused review of `5cf04cfa..54352163` (read-only;
focused unit tests in a separate worktree). Verdict: ready with fixes; no
critical issues. Wrapping defence, verified-content use, trust and algorithm
policy, assertion checks, input bounds, `za_saml` non-injectability, guarded
metadata fetch, storage and key handling were confirmed.

| Finding | Severity | Resolution |
|---|---|---|
| `metadataUrl` fetched inside the update transaction (holds the write lock for the fetch) | Important | Fixed: fetched before `WithTx`, only when `options` are written (`TestSAMLConnectionMetadataRefresh`) |
| Re-fetch on update never replaced the stored certificate | Important | Fixed: an options write without `signingCert` takes the metadata's current certificate; LR37a-19 updated |
| AudienceRestrictions ORed together | Minor | Fixed: each restriction must name the SP (SAML Core §2.5.1.4; `TestAssertionBuildParseCheck`) |
| Unused `logoutMessage.signed` | Minor | Removed |
| Audience defaults to the request `Issuer` | Minor | Auth0 default; documented advice to set `audience` or `signingCert` |
| AES-CBC always accepted; LogoutRequest freshness/replay | Minor | Recorded as follow-ups in plan-1-followups.md |

## CI

Pending.
