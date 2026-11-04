# zeroauthy pre-1.0 full review — shared brief

zeroauthy (this repo, `/mnt/nvme2/code/zeroauthy`, branch `main`) is a clean-room,
drop-in Auth0-compatible identity server in Go with a Vue console. Plans 1–34 are
implemented and merged. 1.0 will be an **early preview release** so people can try
it; Plans 35+ (see the roadmap) still get built afterwards.

## Your job

Review **your assigned area only** (given in your prompt) for:

1. **Correctness and security defects** in what is implemented: wrong behaviour,
   auth/authz bypass, token/session/secret handling, injection, SSRF, tenant
   isolation, secrets reaching logs, race conditions. Verify each by reading
   the code path; cite `file:line`.
2. **Missed Auth0 behaviour within the implemented scope**: documented Auth0
   behaviour, parameters, fields, error codes or defaults that the owning plan
   claimed to cover but the code does not implement or implements differently.
   Evidence must be public Auth0 documentation:
   - docs: https://auth0.com/docs (fetch the specific pages)
   - machine-readable specs (best evidence): https://auth0.com/docs/oas/management/v2/management-api-oas.json,
     https://auth0.com/docs/oas/events/events-schema.json, https://auth0.com/docs/oas/tenant-logs/logs-schema.json
   - changelog: https://auth0.com/changelog. Read `docs/compat/changelog-review.md`
     first; review entries **after its last reviewed date** that touch your area.
3. **Docs drift**: `docs/*.md`, `docs/compat/matrix.md` claims that the code does not
   back up.

Existing decisions are in `docs/compat/decisions.md` (D-00xx). Deliberate,
recorded deviations are **not** findings unless the recorded reasoning is wrong.
Known open items are in `docs/superpowers/plan-1-followups.md`; don't re-report
them, but do say if one is a 1.0 blocker. The roadmap with Plans 35–47 is
`docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md`, and
the 1.0 scope is `docs/superpowers/specs/2026-11-02-zeroauthy-v1-release-scope.md`.

## Rules

- **Read-only.** Do not edit any repository file, commit, or push. Write exactly one
  file, your report, at `.tmp/v1/review/<area-slug>.md` (gitignored).
- **Do not run** database-backed tests, E2E suites, `make e2e*`, `scripts/test-sql.sh`
  or long suites. Another process is using the E2E ports. Focused `go test` runs of
  pure packages (no DB, < 1 min) are OK if needed to confirm a defect.
- Clean room (`CLEAN_ROOM.md`): use public docs and specs only; never copy Auth0
  proprietary source. Do not contact any Auth0 tenant.
- Be concrete and verified. A finding you could not confirm in code is labelled
  `PLAUSIBLE`, not stated as fact. No style nits.

## Report format (markdown)

```
# <Area> review

## Summary
<3–6 lines: overall state, count by severity>

## Findings
### F1 [critical|high|medium|low] [defect|parity-gap|docs-drift] <title>
- Where: path:line
- What: one or two sentences
- Evidence: code path and/or Auth0 doc URL (quote the key sentence briefly)
- Verdict: CONFIRMED | PLAUSIBLE
- Recommendation: fix-before-1.0 | defer-to-Plan-NN (name the roadmap plan, or "new plan" with a one-line scope)
- Suggested fix: one or two lines

## Changelog entries reviewed
<date — title — relevant? — covered/missing/deferred-to-Plan-NN>

## Roadmap suggestions
<items to add to or move between Plans 35–47>
```

Rank findings most-severe first. Rule of thumb for "fix-before-1.0": security
defects at high or above, data loss or corruption, a wrong result on a core flow
(login, token, refresh, logout, user CRUD, Management auth), or docs that would
mislead a first-time user. Everything else defers to a named later plan.
