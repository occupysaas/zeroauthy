# Auth0 Changelog Review

zeroauthy aims to be a one-to-one replacement for Auth0, so features Auth0 adds
or changes after the spec was written must reach the roadmap. Auth0's public
changelog (https://auth0.com/changelog) is the signal for this. It is a
permitted source under `CLEAN_ROOM.md`: read it for *what* changed, then
implement from the linked public documentation. Never copy changelog text
or code blocks; summarize each entry in your own words.

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
| 2026-10-16 | 2026-10-12 (newest entry) | Claude (Plan 8 planning) | First review. Read the whole changelog page back to mid-2025 for entries that affect milestones 1–9 or later sub-projects. No entry changes a behavior zeroauthy already implements. Custom-database items are recorded below; most are later features. |
| 2026-10-16 | 2026-10-12 (newest entry) | Claude (Plan 9 planning) | No entries since the previous review. Re-read entries on consent and third-party applications; the 2026 third-party security modes, access policies and confirmation prompt are taken from the current documentation into the Plan 9 design. |
| 2026-10-16 | 2026-10-16 (newest entry) | Claude (Plan 10 planning) | No entries on PAR. One new entry since the previous review, recorded under Relevant entries: Universal Login identifier and phone controls (early access). |
| 2026-10-17 | 2026-10-16 (newest entry) | Claude (Plan 11 planning) | No entries on the device flow. No new entries since the previous review. Device behaviour was taken from the current documentation and the tenant observation (observations/device-flow.md). |
| 2026-10-20 | 2026-10-20 (newest entry) | Claude (Plan 18 planning) | Covers 2026-10-16 to 2026-10-20 (the Plan 12–17 planning reviews were not logged here). No entry on jobs, import or export; the 2026-09-17 custom user ID entry excludes bulk import. New since the previous logged review: tenant ACL rule builder (2026-10-12), Actions token scope customization GA (2026-10-09), bot detection IPv6 update (2026-10-20); none affects implemented behavior. The 2026-01-21 `enabled_clients` deprecation is now enforced on the maintainer's tenant (observations/management-jobs.md). |
| 2026-10-22 | 2026-10-21 (newest entry) | Codex (Plan 19 observer) | Reviewed public https://auth0.com/changelog since 2026-10-20. One newer entry: CLI Agent Mode (2026-10-21); keep pinned v1.37.0 and its documented commands. The 2026-10-20 IPv6 bot-model update concerns proprietary classification, represented by the explicit local risk difference. No newer tenant/session/attack-settings wire change found. |
| 2026-10-25 | 2026-10-21 (newest entry found) | Codex (Plan 20 implementation) | Re-read the public changelog through 2026-10-25. No newer signing-key, deploy-cli migration or retired Rules/Hooks change found; the Oct 21 CLI Agent Mode entry does not affect these surfaces. See Plan 20's documented evidence boundary in `observations/management-signing-keys.md` and `observations/management-deploy-cli.md`. |
| 2026-10-25 | 2026-10-21 (newest entry found) | Codex (Plan 21 implementation) | Reviewed public changelog pages through 2026-10-25 for email provider and template changes. No newer relevant change was identified in the pages checked; tenant behavior remains unobserved. See `observations/management-email.md`. |

| 2026-10-25 | 2026-10-22 (newest entry found) | Codex (Plan 22 implementation) | Fetched the full public changelog HTML (4.4 MB) and extracted dated entries, not search snippets. Since the previous review: Oct 22 CIMD dynamic registration and Application Profiles EA concern future OAuth/application work; the Oct 22 configurable brute-force unblock mode belongs to the Plan 19 follow-up. No newer branding/theme/template/prompt entry through Oct 25. No upstream tenant was queried. |
| 2026-10-26 | 2026-10-22 (newest entry found) | Codex (Plan 23 planning) | Fetched and text-extracted the complete public changelog after browser size-limit failure. No entries newer than the previous review. Revisited Apr 8, 2026 multiple-custom-domain GA and Dec 15, 2025 weak TLS cipher retirement for the domain/certificate design. Current API adds a diagnostic operation to the roadmap inventory; the spec separates API TXT verification from older CNAME setup prose. No upstream tenant queried; implementation pending. |

| 2026-10-26 | 2026-10-26 (newest entry found) | Codex (Plan 24 Task 1) | Separate full public-HTML retrieval succeeded (4,434,886 bytes), with dated text extraction after the design's oversized-tool retrieval failed. Oct 26 Identity Conversion Suite EA covers anonymous sessions and login experimentation, outside social federation; backlog below. No newer social wire-contract change found. See observations/social-connections.md for hash and source boundary. |

## Relevant entries

| Date | Summary | Surface | Impact | Outcome |
|---|---|---|---|---|
| 2026-10-01 | Newly issued refresh tokens become longer; integrations should not assume a fixed length | Refresh tokens | none | zeroauthy refresh tokens are opaque and stored hashed; Plan 8 Task 7 adds a matrix note |
| 2026-04-09 | The hosted "forgot password" call to action was renamed to "reset password" | Hosted login | none | Our copy is original; no change needed |
| 2026-04-02 | Fields captured by customized signup and login prompts are passed to custom database scripts | Custom DB, hosted login | backlog | Sub-project 2 (custom prompts) |
| 2026-09-17 | A pre-registration Action can assign a custom `user_id` at signup, including on custom databases with migration (EA) | Signup, custom DB | backlog | Sub-project 2 (Actions) |
| 2025-07-21 | Passkeys work on custom database connections with import mode off (EA) | Custom DB | backlog | Sub-project 2 (passkeys) |
| 2025-10-28 | Callback URIs that cannot be verified (custom schemes, loopback) get a login confirmation step, and `prompt=none` is refused for them in some cases | `/authorize` | backlog | Milestone 10 (consent) — decide whether to follow |
| 2026-10-16 | Universal Login gains identifier and phone number controls (early access) | Hosted login | backlog | Sub-project 2 |
| 2026-01-21 | Editing a connection's `enabled_clients` through the connection object is deprecated in favor of dedicated endpoints | Management API | backlog | Sub-project 3 |

## Backlog (from the changelog)

| Entry date | Feature, in our words | Target milestone / sub-project | Status |
|---|---|---|---|
| 2026-10-26 | Anonymous sessions and login experimentation grouped in Identity Conversion Suite EA | Future anonymous-session / hosted-login experimentation planning; outside Plan 24 | open |
| 2026-10-22 | Configurable automatic/manual recovery-link unblock mode for brute-force protection | Plan 19 follow-up | open |
| 2025-10-28 | Confirmation step for non-verifiable callback URIs; `prompt=none` limits | Milestone 10 (Plan 9) | done (Plan 9) |
| 2025-10-10 | Private-key-JWT client assertions must use the issuer string as `aud` | When `private_key_jwt` client auth is added | open |
| 2025-08-11 / 2026-04-14 | Multi-resource refresh tokens (one refresh token, several APIs) | Later (refresh tokens) | open |
| 2025-11-07 / 2026-02-10 | Session metadata, carried in back-channel logout tokens | Sub-project 2 | open |
| 2026-05-11 | Online refresh tokens bound to the session | Later (refresh tokens) | open |
| 2026-06-11 / 2026-06-22 | Refresh token search, bulk revoke and metadata through the Management API | Sub-project 3 | open |
| 2025-08-22 / 2026-05-13 | Non-unique emails on new database connections | Sub-project 3 | open |
| 2026-08-13 | Flexible password policy (new connections default to it) | Sub-project 3 (connections API); zeroauthy keeps the legacy policy shape until then | open |
| 2026-01-21 | Dedicated endpoints for a connection's enabled clients | Sub-project 3 | open |
| 2026-05-26 | Federated logout for OIDC and Okta connections | Sub-project 2 | open |
| 2026-07-20 | Anonymous sessions (`POST /anonymous/token`, beta) | Unassigned | open |
| 2026-04-02 | Custom prompt fields reach custom database scripts | Sub-project 2 | open |
| 2026-09-17 | Custom user IDs at signup via a pre-registration Action | Sub-project 2 | open |
| 2025-07-21 | Passkeys on custom database connections | Sub-project 2 | open |


## Plan 19 implementation disposition (2026-10-24)

Tenant settings, attack policy APIs, automatic blocks and console controls now
implement the frozen 2026-10-22 evidence. D-0045 and the compatibility matrix
retain the explicit local bot-risk/provider/corpus differences. CLI stays at
1.37.0 and node-auth0 at 7.4.0. This is an implementation record, not a new
upstream changelog review; the reviewed-through date above is unchanged.

## Plan 22 implementation disposition (2026-10-26)

The implementation uses the frozen 2026-10-25 branding/prompt inventory and
local restricted-rendering choices (D-0048). The pinned deploy client also
provides the finite future prompt/screen enum used for text discovery. Classic,
WebAuthn-first, ACUL, custom domains and custom prompt fields in custom-database
scripts remain deferred. This is an implementation disposition, not a new live
changelog review; it does not advance the reviewed-through date.

## 2026-10-26 — Plan 23 custom domains

Fetched the full public changelog because the browser response exceeded its size
limit. Latest visible entry remains October 22, 2026; no later custom-domain
contract change was found. Current public API multiple-domain schemas supersede
older single-domain setup prose. The nine-operation inventory uses TXT ownership
proof and recommended TLS only. Live tenant observation remains unavailable.

Plan 23 implementation disposition: the frozen nine-operation inventory now
has local API/console/runtime implementation. Template GET supplies `body`
while preserving the `template` alias. Local hosted wildcard, TXT-only proof,
proxy admission and canonical-origin upgrade rules are recorded in the custom
domain guide. This does not advance the reviewed-through date or imply a live
upstream tenant observation. ACUL and WebAuthn RP enforcement remain deferred.
