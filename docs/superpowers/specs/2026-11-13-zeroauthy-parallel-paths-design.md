# zeroauthy — Design: parallel work paths for multiple contributors

Status: draft for maintainer approval (2026-11-13).

## Intent

Several people now work on zeroauthy at once. The remaining roadmap
(`specs/2026-10-19-zeroauthy-management-roadmap-design.md`, Plans 35–48) is
written as one sequential queue, so contributors can't tell what they can
safely pick up, and parallel branches would collide on code areas and on
sequential numbers. This design breaks the roadmap into claimable items with
short briefs, and makes every agent session start by asking the contributor
which item they want and end by asking what is next.

## Goals

- Every remaining roadmap item has a short brief a contributor can claim and
  turn into a full spec and plan.
- Two contributors never work on colliding items at the same time, and nobody
  starts an item before its dependencies have merged.
- Claims are visible on GitHub to the maintainer and every agent.
- An agent session starts by showing the free items and asking which one to
  work on; finishing an item ends with "what is next?".
- Parallel branches never break the database migration order.

## Non-goals

- Full specs or implementation plans for the items (contributors write them,
  using the existing brainstorming → spec → plan workflow).
- Re-deciding roadmap scope; the briefs restate the roadmap and the pre-1.0
  review additions, nothing more.
- A project board, milestones or other GitHub tooling beyond issues and labels.

## Approaches considered

1. One path per roadmap plan: most parallel, but nothing stops two people
   changing the token endpoint at once or starting Plan 41 before Plan 35.
2. About six code-area tracks, one person per track: collision-proof, but each
   track is a queue and one holder can block a lot of work.
3. **Hybrid (chosen by the maintainer):** one brief and one issue per item;
   each item belongs to a track that fixes its order and code area. An item is
   claimable when its dependencies have merged and no other item in its track
   is in progress. Items marked *independent* run alongside anything.

Claims: GitHub issues (chosen) over a status table in the repo, which would
let two people claim in the gap before a PR merges and would conflict
constantly. Depth: short briefs (chosen) over full specs up front, which would
need many maintainer rulings today.

## Design

### Tracks and items

| Track | Items, in order | Code area |
|---|---|---|
| P — Protocol and tokens | P1 Plan 35 client credentials, `private_key_jwt`, JAR, token exchange (spec and plan already written) → P2 Plan 48 refresh tokens II → P3 Plan 41a OIDC claims, `acr_values`, `resource`, front/back-channel logout and logout certification → P4 Plan 41b Dynamic Client Registration → P5 Plan 41c CIBA → P6 Plan 43 Token Vault | `/oauth/*`, token issuance |
| F — Enterprise federation | F1 Plan 36 enterprise OIDC → F2 Plan 37a SAML (IdP and SP) → F3 Plan 37b WS-Federation and ADFS → F4 Plan 37c SCIM and self-service SSO → F5 Plan 38a AD/LDAP | connections, federation core |
| S — Social providers | S1 Plan 39a Apple → S2 Plan 39b remaining social providers | social adapters on the federation core |
| A — Actions and Forms | A1 Plan 40 Actions III → A2 Plan 38b Forms and Flows | Actions runtime, triggers |
| U — End-user APIs | U1 Plan 42a My Account API → U2 Plan 42b My Organization API | new API audiences |
| H — Hosted pages | H1 Plan 44 ACUL and remaining Universal Login modes | `/u/*`, branding |
| M — Management API gaps | M1 Plan 38d remaining resources and OAS gap routes | `/api/v2` |
| O — Operations (each item independent) | O1 Plan 38c network ACLs; O2 Plan 45a security hardening (master-key rotation, runner sandbox, HSTS, database TLS, plugin stderr); O3 Plan 45b flow and API correctness fixes; O4 Plan 45c infrastructure (certificate retries, DNS providers, CORS index, sealed-token sweep, phone send backoff); O5 Plan 46 release leftovers (versioned docs links, Android TV sample, translations) | spread |
| X — Hosting | X1 Plan 47 hosted zeroauthy, **reserved for the maintainer** | product |

Cross-track dependencies come from the roadmap: P3–P6 need P1; P6 also needs
social token storage (done); U1 needs Plan 33b (done). Each brief lists its
own.

### Files

- `docs/paths/README.md`: the track table, the claim rules, the numbering
  rules and the session protocol, linked from `AGENTS.md`, `CONTRIBUTING.md`
  and the roadmap.
- `docs/paths/<ID>-<slug>.md`: one brief per item, about one page:
  - track, size and dependencies
  - scope, restating the roadmap section and its pre-1.0 additions
  - out of scope
  - code areas it touches
  - decisions it needs from the maintainer
  - reserved decision IDs
  - how to start: spec path, plan path, branch name `plan-<id>-<slug>`
- The roadmap gets a pointer to `docs/paths/` and keeps its history.

### GitHub

- Labels: `path`, `track:<letter>`, `claimed`, `maintainer-only`.
- One open issue per item. Its body links the brief and lists dependencies as
  issue references.
- **Claiming:** comment "claiming" on the issue. A contributor with write
  access, or their agent, adds `claimed` and assigns themselves. Fork
  contributors can't label, so their claim counts once the maintainer labels
  it; until then agents show it as "claim requested".
- **Releasing:** remove `claimed` and comment.
- **Finishing:** the merge closes the issue.
- **Free item:** open, not `claimed`, every dependency issue closed, no other
  `claimed` item in the same track (O items are exempt), not
  `maintainer-only` unless the maintainer is asking.

### Agent session protocol (in `AGENTS.md`)

- **At session start, unless the person already named a task,** the agent
  lists the items with `gh issue list --label path --state open`, shows each
  one as free, claimed (by whom), claim requested or blocked (by what), and
  asks which item to work on. Without `gh`, it lists the briefs and says that
  claim status is unknown.
- **On a chosen item,** the agent claims it, reads its brief, then runs
  brainstorming → spec → plan → execution as today.
- **When the item's PR merges or the work stops,** the agent updates the
  issue and asks what is next, showing the free items again.

### Numbering

- **Decision IDs:** each brief reserves a block of ten (P2 D-0070–0079, P3
  D-0080–0089, …; P1 keeps its D-0063). They carry no ordering, so blocks are
  safe.
- **Migrations:** these must not be reserved in blocks. The runner applies
  only versions above the highest one already applied (`migrateTo` in
  `internal/store/sqlstore/migrate.go`), so a lower number merged later would
  be silently skipped on any database that ran the higher one. Rule: a
  branch's migration takes its number when the branch merges (next after
  main's latest; rename before merging).
- **Migration check:** the `dco` pull-request workflow gains a job that fails
  when a pull request adds a migration numbered at or below main's latest.

## Left to the builder

- Brief wording.
- Exact label colours.
- Whether the migration check is a new script or part of `check-dco.sh`'s
  workflow.
