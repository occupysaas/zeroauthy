# Parallel work paths Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the remaining roadmap into claimable items with short briefs and GitHub issues, guard migration order across parallel branches, and make agent sessions start by asking which item to work on.

**Architecture:**
- **Docs:** `docs/paths/` holds the rules (`README.md`) and one brief per item.
- **Session rules:** `AGENTS.md` carries the session protocol.
- **Migration check:** a new script fails a pull request whose migration isn't numbered above main's latest, run by the existing `dco` pull-request workflow.
- **GitHub:** issues and labels are created after the docs merge, so their links resolve.

**Tech Stack:** Markdown, bash, GitHub Actions, `gh` CLI.

**Spec:** `docs/superpowers/specs/2026-11-13-zeroauthy-parallel-paths-design.md`

## Global Constraints

- Branch `plan-parallel-paths` from `main`; every commit signed off (`git commit -s`) with the session's Co-Authored-By trailer.
- Brief file names: `docs/paths/<ID>-<slug>.md`, IDs exactly as in the spec's track table (P1–P6, F1–F5, S1–S2, A1–A2, U1–U2, H1, M1, O1–O5, X1).
- Branch name in every brief: `plan-<id>-<slug>` with a lowercase id (e.g. `plan-p2-refresh-tokens-ii`).
- Decision-ID blocks: P1 keeps D-0063; then blocks of ten in table order starting at D-0070 (P2 D-0070–0079, P3 D-0080–0089, P4 D-0090, P5 D-0100, P6 D-0110, F1 D-0120, F2 D-0130, F3 D-0140, F4 D-0150, F5 D-0160, S1 D-0170, S2 D-0180, A1 D-0190, A2 D-0200, U1 D-0210, U2 D-0220, H1 D-0230, M1 D-0240, O1 D-0250, O2 D-0260, O3 D-0270, O4 D-0280, O5 D-0290, X1 D-0300).
- Migrations are never reserved; they're numbered at merge time.
- Labels: `path`, `track:p`, `track:f`, `track:s`, `track:a`, `track:u`, `track:h`, `track:m`, `track:o`, `track:x`, `claimed`, `maintainer-only`.
- Plain English in all docs, no Auth0 internals beyond what the roadmap already states (CLEAN_ROOM.md).

## Review Focus

- **Two migrations in one PR,** one above main's latest and one at or below it: the check must fail and name the bad one (Task 1 test `two_files_one_stale`).
- **The same version in all three dialect directories** (`sqlite`, `postgres`, `mysql`) must be counted once, not flagged as a duplicate (Task 1 test `three_dialects_same_version`).
- **A PR that adds no migration** must pass (Task 1 test `no_migrations`).
- **Fork contributor claim:** a "claiming" comment without the `claimed` label must show as "claim requested", not free (Task 4 protocol text, checked in Task 5 dry run).
- **No `gh` or no network:** the session protocol must still list the briefs and say claim status is unknown, not fail (Task 4 protocol text).

---

### Task 1: Migration-order check

**Files:**
- Create: `scripts/check-migrations.sh`
- Create: `scripts/check-migrations_test.sh`
- Modify: `.github/workflows/dco.yml` (add a second job)
- Modify: `CONTRIBUTING.md` (one paragraph under "Workflow")

**Interfaces:**
- Produces: `scripts/check-migrations.sh <base> <head>`, which exits 0 or 1 and prints `::error::` lines naming each offending file.

- [ ] **Step 1: Write the failing test** `scripts/check-migrations_test.sh`.
  - It builds a throwaway git repo in `mktemp -d` with `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0035_x.sql` on a base commit, then runs these cases, each on its own branch from base:
    - `no_migrations`: only a README change → exit 0.
    - `next_number`: adds `0036_y.sql` in all three dialects → exit 0.
    - `stale_number`: adds `0035_z.sql` → exit 1, output contains `0035_z.sql`.
    - `two_files_one_stale`: adds `0036_y.sql` and `0034_w.sql` → exit 1, output names `0034_w.sql` and not `0036_y.sql`.
    - `three_dialects_same_version`: `0036_y.sql` in all three → exit 0.
  - It prints `ok <case>` or `FAIL <case>` per case and exits non-zero on any failure.
- [ ] **Step 2: Run it to make sure it fails.**
  - Run: `bash scripts/check-migrations_test.sh`
  - Expected: FAIL (the script doesn't exist).
- [ ] **Step 3: Implement `scripts/check-migrations.sh`.**
  - `latest` = the highest 4-digit prefix under `internal/store/sqlstore/migrations/*/` at `<base>` (`git ls-tree -r --name-only`).
  - Added files = `git diff --diff-filter=A --name-only <base>...<head> -- internal/store/sqlstore/migrations`.
  - Any added file whose prefix is `<= latest` is an error.
  - The message tells the contributor to rename to `latest+1` and to keep one number per migration across dialects.
- [ ] **Step 4: Run the test to make sure it passes.**
  - Run: `bash scripts/check-migrations_test.sh`
  - Expected: five `ok` lines, exit 0.
  - Also run: `bash scripts/check-migrations.sh origin/main HEAD` → exit 0.
- [ ] **Step 5: Add the CI job.**
  - Add job `migration-order` to `.github/workflows/dco.yml`: same checkout as `sign-off` (`fetch-depth: 0`, head SHA), running `./scripts/check-migrations.sh "$BASE" "$HEAD"` with the same env.
  - Add one sentence to the workflow's header comment.
- [ ] **Step 6: Document it** in `CONTRIBUTING.md` "Workflow": migrations are numbered when the branch merges; rename yours to main's latest + 1 before merging; the `migration-order` check enforces it.
- [ ] **Step 7: Commit:**

```bash
git add scripts/check-migrations.sh scripts/check-migrations_test.sh .github/workflows/dco.yml CONTRIBUTING.md
git commit -s -m "ci: reject pull requests whose migration is not above main's latest"
```

### Task 2: Paths README and the P, F, S, A briefs

**Files:**
- Create: `docs/paths/README.md`
- Create: `docs/paths/P1-client-credentials-jar-token-exchange.md`, `P2-refresh-tokens-ii.md`, `P3-oidc-extras-logout.md`, `P4-dynamic-client-registration.md`, `P5-ciba.md`, `P6-token-vault.md`
- Create: `docs/paths/F1-enterprise-oidc.md`, `F2-saml.md`, `F3-ws-federation.md`, `F4-scim-self-service-sso.md`, `F5-ad-ldap.md`
- Create: `docs/paths/S1-apple.md`, `S2-social-providers.md`
- Create: `docs/paths/A1-actions-iii.md`, `A2-forms-and-flows.md`

**Interfaces:**
- Produces: the brief template (the headings below), which Task 3 reuses verbatim, and `docs/paths/README.md` section anchors `#claiming`, `#numbering` and `#session-protocol`, which Task 4 links to.

- [ ] **Step 1: Write `docs/paths/README.md`** with these sections:
  - **Overview:** what paths are, and a link to the roadmap.
  - **Tracks and items:** the spec's track table, each item linking its brief.
  - **Claiming:** the spec's claiming, releasing and finishing rules, plus the free-item definition.
  - **Numbering:** decision-ID blocks and the migration rule.
  - **Session protocol:** the spec's three steps.
  - **Adding an item:** a new brief plus a new issue, done by the maintainer or approved in a PR.
- [ ] **Step 2: Write each brief** using exactly these headings: `Track and order`, `Depends on`, `Size`, `Scope`, `Out of scope`, `Code areas`, `Decisions needed from the maintainer`, `Reserved decision IDs`, `How to start`.
  - **Scope:** restate the item's roadmap section (`specs/2026-10-19-zeroauthy-management-roadmap-design.md` §3/§3a), including its pre-1.0 review additions. Splits follow the spec:
    - 41 → P3 (`claims`, `acr_values`, `address`/`phone` scopes, remaining `profile` claims, RFC 8707 `resource`, optional `redirect_uri` question, front-/back-channel logout, certification submission with logout profiles and a `client_secret_post` run), P4 (Dynamic Client Registration), P5 (CIBA).
    - 37 → F2 (SAML IdP addon and SAML SP connections, metadata, SAML logout), F3 (`wsfed` addon, `adfs`), F4 (SCIM configuration and inbound SCIM 2.0, self-service profiles and SSO tickets, directory groups if Auth0 documents them).
    - 38 → F5 (AD/LDAP), A2 (Forms and Flows, `api.prompt.render`), O1 (network ACLs; Task 3), M1 (remaining resources; Task 3).
    - 39 → S1 (Apple), S2 (the rest).
  - **How to start:** for P1, point to the existing spec `specs/2026-11-08-…-design.md` and plan `plans/2026-11-08-zeroauthy-plan-35-…md` (migration 0036 is the next free number) and say it's ready to execute. For all others: claim the issue → brainstorm → spec at `docs/superpowers/specs/YYYY-MM-DD-zeroauthy-<slug>-design.md` → plan → branch `plan-<id>-<slug>` → verification per `AGENTS.md`.
  - **Decisions needed** (copy into the matching brief; "none known" otherwise):
    - **P3:** each spec-vs-Auth0 conflict found by conformance (default spec-compliant plus an opt-in environment variable is already ruled); whether `/authorize` may omit `redirect_uri`.
    - **P5:** which approval channel CIBA uses, given Guardian push is not planned (roadmap §5).
    - **P6:** refresh, revocation and consent policy for stored upstream tokens.
    - **F2:** the XML-signature library and its dependency policy.
    - **F4:** whether directory groups ship.
    - **F5:** speak the open-source AD/LDAP connector's protocol, or an own LDAP bind.
    - **S2:** provider order.
    - **A1:** which Early Access members count as available at build time.
    - **A2:** console flow-builder scope.
- [ ] **Step 3: Self-check:**
  - Run: `ls docs/paths/ | wc -l` → 16.
  - Run: `grep -L "## Reserved decision IDs" docs/paths/[PFSA]*.md` → no output.
  - Each brief's D block matches Global Constraints.
- [ ] **Step 4: Commit:**

```bash
git add docs/paths
git commit -s -m "docs: paths README and briefs for protocol, federation, social and Actions tracks"
```

### Task 3: U, H, M, O, X briefs

**Files:**
- Create: `docs/paths/U1-my-account-api.md`, `U2-my-organization-api.md`, `H1-acul-universal-login-modes.md`, `M1-management-api-gaps.md`, `O1-network-acls.md`, `O2-security-hardening.md`, `O3-flow-and-api-fixes.md`, `O4-infrastructure-hardening.md`, `O5-release-leftovers.md`, `X1-hosted-zeroauthy.md`

**Interfaces:**
- Consumes: the brief template from Task 2.

- [ ] **Step 1: Write each brief** with the Task 2 headings.
  - **Scope splits** from the roadmap:
    - 42 → U1 (My Account API), U2 (My Organization API, Early Access since 2026-09).
    - 44 → H1 whole, including the phone factor on MFA enrollment tickets.
    - 38 → M1 (encryption-key and network-ACL key routes, OAS gap routes, ignored list parameters, `GET /logs` sorting, remaining resources) and O1 (network ACLs with HTTP message signatures).
  - **Plan 45 deferred list, split across O items:**
    - **O2:** master-key rotation with versioned sealed formats, OS-level runner sandbox and shared runner prelude, runner retirement on spent log/mask caps, HSTS, database TLS defaults, plugin stderr scrubbing.
    - **O3:** pre-MFA side effects ordering, which must cite the 2026-11-08 ruling that Actions running before MFA stays as is; also signup code lifetime and send scope, `limit_sul` duplication, console passwordless test CORS, admin CSP tenant domains, `PATCH /users` nulls and `verify_phone_number`, `organization_id` on jobs/tickets, `/users/{id}/organizations` scopes, v1 `connection` filter, email-provider non-secret fields, the per-tenant attack-protection row lock.
    - **O4:** certificate retry schedule, DNS providers and challenge delegation, custom public signing JWKS, CORS origin index, sealed-token sweep, custom-script Try limiting, phone-provider exponential backoff, Plan 27 MySQL freshness closure, console accessibility audit.
    - **O5:** Plan 46 leftovers.
  - **X1:** mark it `maintainer-only`; state the open product decisions listed in roadmap Plan 47, including the custom-domain claim expiry.
  - **Decisions needed:**
    - **U1/U2:** audiences, scopes and consent screens.
    - **H1:** the content-security boundary for tenant browser JavaScript.
    - **O2:** the sealed-format versioning scheme and the sandbox mechanism.
    - **O4:** which DNS providers.
    - **O5:** which languages and the Android TV sample scope.
    - **X1:** all of it.
- [ ] **Step 2: Self-check:**
  - Run: `ls docs/paths/*.md | wc -l` → 26 (README + the spec table's 25 items).
  - Every ID in `docs/paths/README.md` resolves to a file.
- [ ] **Step 3: Commit:**

```bash
git add docs/paths
git commit -s -m "docs: briefs for end-user API, hosted pages, management gaps, operations and hosting"
```

### Task 4: Session protocol and pointers

**Files:**
- Modify: `AGENTS.md` (new first section `## Starting and finishing a session`)
- Modify: `CONTRIBUTING.md` ("How work is planned and built": paragraph linking `docs/paths/`)
- Modify: `docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md` (note under §0 pointing to `docs/paths/`)

**Interfaces:**
- Consumes: README anchors `#claiming` and `#session-protocol` from Task 2.

- [ ] **Step 1: Add `## Starting and finishing a session` to `AGENTS.md`.**
  - **At the start of every session, unless the person already named a task:**
    - Run `gh issue list --label path --state open --json number,title,labels,assignees,comments --limit 100`.
    - Classify each item:
      - **free:** per the README rules.
      - **claimed by @login:** has the `claimed` label.
      - **claim requested by @login:** has a comment starting "claiming" but no label.
      - **blocked by #n:** a dependency issue is open, or another item in its track is claimed (O items exempt).
      - **maintainer-only.**
    - Show free items first, then ask which item the person wants to work on.
    - If `gh` fails: list `docs/paths/*.md` titles and say claim status is unknown.
  - **On a chosen item:**
    - Comment "claiming" on its issue.
    - Add `claimed` and assign the person only if `gh` has write access; otherwise say the maintainer will confirm.
    - Read the brief; follow its "How to start".
  - **When the item's PR merges, or the person stops:**
    - Close the issue on merge, or remove `claimed` with a comment on stopping.
    - Ask what's next, listing free items again.
  - Link the README `#session-protocol` anchor for detail.
- [ ] **Step 2: Add the pointers** in `CONTRIBUTING.md` and the roadmap §0 (one paragraph each).
- [ ] **Step 3: Check links:**
  - Run: `grep -o "docs/paths/[A-Za-z0-9#._-]*" AGENTS.md CONTRIBUTING.md docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md`
  - Confirm each path exists.
- [ ] **Step 4: Commit:**

```bash
git add AGENTS.md CONTRIBUTING.md docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md
git commit -s -m "docs: ask which path to work on at session start and what is next at the end"
```

### Task 5: Verify, merge, then labels and issues

**Files:**
- Create: `scripts/paths-issues.sh` (creates labels and one issue per brief; skips any brief that already has an issue whose title starts with its ID)

**Interfaces:**
- Consumes: briefs from Tasks 2–3. Issue title: `<ID>: <brief H1 title>`. Body: link to `docs/paths/<file>` on `main`, then "Depends on" as issue references, then "Track: <letter>".

- [ ] **Step 1: Write `scripts/paths-issues.sh`.**
  - The issue body format is fixed above. Creation follows the track-table order, so every dependency's issue number exists before an issue references it.
  - Dry-run with `DRY_RUN=1` and check:
    - 25 planned issues.
    - X1 carries `maintainer-only`.
    - P3's body references P1's planned issue.
- [ ] **Step 2: Commit:**

```bash
git add scripts/paths-issues.sh
git commit -s -m "chore: script that creates path labels and issues from the briefs"
```

- [ ] **Step 3: Fast local tier:**
  - Run: `bash scripts/check-migrations_test.sh && ./scripts/check-dco.sh origin/main HEAD && ./scripts/check-migrations.sh origin/main HEAD`
  - Expected: all exit 0.
  - Docs and scripts only; no Go changes.
- [ ] **Step 4: Push and wait for CI:**
  - Push `plan-parallel-paths` and open a PR; wait for every check, including the new `migration-order` job.
  - On green, merge `--no-ff` to `main` and push (maintainer approved 2026-11-13).
- [ ] **Step 5: Run `scripts/paths-issues.sh` for real** on `main`:
  - Expected: 12 labels and 25 issues.
  - Verify: `gh issue list --label path --limit 100 | wc -l` → 25.
- [ ] **Step 6: Run the session protocol as a fork contributor would:**
  - Expected: P1, F1, S1, A1, U1, H1, M1 and O1–O5 free; all other P, F, S, A and U items blocked; X1 maintainer-only.
