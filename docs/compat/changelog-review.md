# Auth0 Changelog Review

zeroauthy aims to be a one-to-one replacement for Auth0, so features Auth0 adds
or changes after the spec was written must reach the roadmap. Auth0's public
changelog (https://auth0.com/changelog) is the signal for this. It is a
permitted source under `CLEAN_ROOM.md`: read it for *what* changed, then
implement from the linked public documentation. Never copy changelog text;
summarize each entry in your own words.

## When to review

- **Before writing each milestone's plan:** review every entry since the last
  review recorded below. Entries that touch the milestone's surfaces become plan
  tasks, decisions (`decisions.md`), or matrix notes (`matrix.md`).
- **Entries outside the current milestone** go to the backlog below, tagged with
  the milestone or sub-project they belong to (spec §1.1, §13).
- **Deprecations and removals** count too: if Auth0 changes or retires a
  behavior we copied, record whether zeroauthy follows (default: follow, per
  the parity-first rule) and log a decision.

## How to record an entry

One row per relevant entry. Irrelevant entries (dashboard-only, pricing, other
Okta products) need no row; the "Reviewed through" date covers them.

| Field | Content |
|---|---|
| Date | The entry's publication date |
| Summary | One line in our own words |
| Surface | Endpoint, grant, SDK, hosted page, Management API, Actions, … |
| Impact | `none`, `plan` (current milestone), `backlog`, or `decision` |
| Outcome | Link to the plan task, decision ID or backlog row |

## Review log

| Reviewed on | Reviewed through | By | Notes |
|---|---|---|---|
| — | — | — | First review is due before the milestone 9 (`custom-db`) plan; it covers everything since the spec date (2026-10-13), plus earlier entries that affect milestones 1–8 and are not yet in the matrix. |

## Relevant entries

| Date | Summary | Surface | Impact | Outcome |
|---|---|---|---|---|

## Backlog (from the changelog)

| Entry date | Feature, in our words | Target milestone / sub-project | Status |
|---|---|---|---|
