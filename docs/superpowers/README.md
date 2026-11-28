# Specs, plans and records

This folder holds how zeroauthy is designed and built:

- `specs/` — design documents (one per roadmap plan), plus the
  [Management API roadmap](specs/2026-10-19-zeroauthy-management-roadmap-design.md)
  and the [parallel paths design](specs/2026-11-13-zeroauthy-parallel-paths-design.md).
- `plans/` — step-by-step implementation plans for agents (TDD tasks,
  files, tests, verification).
- `*-implementation-record.md` here — what each finished plan actually did,
  with commits and test results.
- `plan-1-followups.md` — open follow-ups and observation points.
- `reviews/` — whole-project reviews.

P2 / Plan 48 is implemented, locally verified and reviewed on
`plan-48-refresh-tokens-ii`, including DPoP and dedicated acceptance.
Full plan-branch CI remains pending. See
[its record](2026-11-16-plan-48-implementation-record.md).

## What to work on next

Every remaining roadmap item except X1 (hosted zeroauthy, maintainer-only)
has a spec and a plan, written 2026-11-16. Implementation and verification states are recorded per item.

F1 / Plan 36 enterprise OIDC is implemented, locally verified and reviewed on
`plan-36-enterprise-oidc`; full CI and maintainer approval remain before merge.
see [the record](2026-11-16-plan-36-implementation-record.md) for verification state.

S1 / Plan 39a (web and native Apple login) is implemented and merged into
`main` (2026-11-17, plan-branch CI green at `74752598`); see
[its record](2026-11-16-plan-39a-implementation-record.md).

O3 / Plan 45b (flow and API fixes) is implemented: all 14 tasks, the
whole-branch review and local verification are complete; see
[its record](2026-11-16-plan-45b-implementation-record.md). Review follow-ups
R1–R7 are in [plan-1-followups.md](plan-1-followups.md).

Start at the roadmap's **"Designed 2026-11-16"** table
([roadmap §0](specs/2026-10-19-zeroauthy-management-roadmap-design.md)).
It lists each item with its spec and the maintainer rulings it still
needs. Items without open rulings can be picked up now, subject to their
track order in the [parallel paths design](specs/2026-11-13-zeroauthy-parallel-paths-design.md).

| Item | Plan | Spec | Implementation plan |
|---|---|---|---|
| F1 | 36 Enterprise OIDC (merged 2026-11-19, PR #70) | [spec](specs/2026-11-16-zeroauthy-enterprise-oidc-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-36-enterprise-oidc.md) |
| F2 | 37a SAML ([merged 2026-11-22](2026-11-16-plan-37a-implementation-record.md), PR #81) | [spec](specs/2026-11-16-zeroauthy-saml-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-37a-saml.md) |
| F3 | 37b WS-Federation and ADFS (merged 2026-11-23, PR #85) | [spec](specs/2026-11-16-zeroauthy-ws-federation-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-37b-ws-federation.md) |
| F4 | 37c SCIM, groups, self-service SSO (merged 2026-11-24, PR #87) | [spec](specs/2026-11-16-zeroauthy-scim-self-service-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-37c-scim-self-service.md) |
| F5 | 38a AD/LDAP ([merged 2026-11-24](2026-11-16-plan-38a-implementation-record.md), PR #88) | [spec](specs/2026-11-16-zeroauthy-ad-ldap-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-38a-ad-ldap.md) |
| A2 | 38b Forms and Flows | [spec](specs/2026-11-16-zeroauthy-forms-flows-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-38b-forms-flows.md) |
| O1 | 38c Network ACLs | [spec](specs/2026-11-16-zeroauthy-network-acls-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-38c-network-acls.md) |
| M1 | 38d Management API gaps | [spec](specs/2026-11-16-zeroauthy-management-gaps-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-38d-management-gaps.md) |
| S1 | 39a Sign in with Apple | [spec](specs/2026-11-16-zeroauthy-apple-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-39a-apple.md) |
| S2 | 39b Remaining social providers, Tier 1 ([merged 2026-11-27](2026-11-16-plan-39b-implementation-record.md), PR #105; Tier 2 is Plan 39d; GitHub stays on its adapter (ruled 2026-11-28)) | [spec](specs/2026-11-16-zeroauthy-social-providers-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-39b-social-providers.md) |
| S2 | 39c GitHub social connection (split out of 39b; merged 2026-11-19, PR #71) | [spec](specs/2026-11-16-zeroauthy-github-connection-design.md) | [plan](plans/2026-11-18-zeroauthy-plan-39c-github.md) |
| A1 | 40 Actions III | [spec](specs/2026-11-16-zeroauthy-actions-iii-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-40-actions-iii.md) |
| P3 | 41a OIDC extras and logout ([merged 2026-11-21](2026-11-16-plan-41a-implementation-record.md), PRs #74, #76) | [spec](specs/2026-11-16-zeroauthy-oidc-extras-logout-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-41a-oidc-extras-logout.md) |
| P4 | 41b Dynamic Client Registration, CIMD ([merged 2026-11-26](2026-11-16-plan-41b-implementation-record.md), PR #102) | [spec](specs/2026-11-16-zeroauthy-dynamic-client-registration-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-41b-dynamic-client-registration.md) |
| P5 | 41c CIBA ([merged 2026-11-26](2026-11-16-plan-41c-implementation-record.md), PR #103) | [spec](specs/2026-11-16-zeroauthy-ciba-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-41c-ciba.md) |
| U1 | 42a My Account API ([merged 2026-11-26](2026-11-16-plan-42a-implementation-record.md), PR #98) | [spec](specs/2026-11-16-zeroauthy-my-account-api-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-42a-my-account-api.md) |
| U2 | 42b My Organization API ([Phase A merged 2026-11-26](2026-11-16-plan-42b-implementation-record.md), PR #99) | [spec](specs/2026-11-16-zeroauthy-my-organization-api-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-42b-my-organization-api.md) |
| U2b | 42b Phase B My Organization API: domains, identity providers, provisioning ([merged 2026-11-26](2026-11-26-plan-42b-phase-b-implementation-record.md), PR #100) | [spec §5](specs/2026-11-16-zeroauthy-my-organization-api-design.md) | [plan](plans/2026-11-26-zeroauthy-plan-42b-phase-b-my-organization-sso.md) |
| P6 | 43 Token Vault | [spec](specs/2026-11-16-zeroauthy-token-vault-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-43-token-vault.md) |
| H1 | 44 ACUL and Universal Login modes | [spec](specs/2026-11-16-zeroauthy-acul-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-44-acul.md) |
| O2 | 45a Security hardening | [spec](specs/2026-11-16-zeroauthy-security-hardening-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-45a-security-hardening.md) |
| O3 | 45b Flow and API fixes (merged 2026-11-18, PR #64) | [spec](specs/2026-11-16-zeroauthy-flow-api-fixes-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-45b-flow-api-fixes.md) |
| O4 | 45c Infrastructure hardening | [spec](specs/2026-11-16-zeroauthy-infrastructure-hardening-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-45c-infrastructure-hardening.md) |
| O5 | 46 Release leftovers | [spec](specs/2026-11-16-zeroauthy-release-leftovers-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-46-release-leftovers.md) |
| P2 | 48 Refresh tokens II (merged 2026-11-21, PR #73) | [spec](specs/2026-11-16-zeroauthy-refresh-tokens-ii-design.md) | [plan](plans/2026-11-16-zeroauthy-plan-48-refresh-tokens-ii.md) |

P1 (Plan 35) and S1 (Plan 39a) are implemented and merged, and so are the items marked merged above. Still open: P6, S2 (39b Tier 2), A1, A2, H1, M1, O1, O2, O4, O5 and X1 (maintainer-only).

## Before implementing an item

1. Read its spec, then its plan. Each plan names its worktree, branch
   (`plan-<id>-<slug>`), decision-ID block and verification steps.
2. Check the roadmap table for open maintainer rulings; get them first.
3. Migration numbers in the plans are provisional (0037 onward). Rename
   yours to `main`'s latest + 1 before merging.
4. Verify as `AGENTS.md` says: focused tests per task, then the fast local
   tier, then push the plan branch for full CI.
