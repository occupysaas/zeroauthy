# Plan 37a — SAML 2.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** zeroauthy as SAML IdP (the `samlp` client addon, metadata, SLO,
IdP-initiated, `api.samlResponse`) and as SAML SP (`samlp` connections,
ACS, SP metadata, encrypted assertions, IdP-initiated, SLO, keys).

**Architecture:**
- **`internal/samlcore`** (new): safe XML parsing, exc-c14n, XML-DSig
  sign/verify, XML-Enc, message builders/parsers, metadata. Built on the
  §9.1-approved implementation.
- **`internal/samlidp`** (new): addon rules, endpoint handlers, assertion
  builder, claim mapping, SLO participants.
- **`internal/federation`**: the `samlp` provider (start = AuthnRequest,
  completion = ACS response) on Plan 24's attempt/identity pipeline.
- **`internal/actions`**: `api.samlResponse` setters (A1 inventory update).

**Tech Stack:** Go 1.26.10; XML signature code per ruling §9.1 (vendored
into `internal/third_party` by default; **no module added without the
ruling**); Vue/TypeScript console; Playwright 1.64.0; npm SAML SP/IdP pins
for E2E only after ruling §9.2.

**Spec:** [Plan 37a design](../specs/2026-11-16-zeroauthy-saml-design.md). § refers to it.

**Gates:** all ruled 2026-11-21 (spec §11): vendor goxmldsig + etree; E2E `@node-saml/node-saml` and `samlify`; SHA-1/RSA-1_5 opt-in only.
**Depends on:** Plan 36 (connection keys repository, HRD) merged first.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; vendored code keeps its license
  file and `NOTICE` entry; keep every pin.
- **Clean room.** CLEAN_ROOM.md; `node-samlp` provenance per default in
  D-0130.
- **Parity.** LR37a-1…3 and S37-1…14 in **D-0130**; follow-ups.
- **Security limits.** Input ≤ 256 KiB, depth ≤ 50, no DTD; skew 2 min;
  assertion IDs single use; SHA-1/RSA-1_5 only by explicit configuration
  (ruling §9.3).
- **Never logged:** private keys; SAML payloads only with `debug: true`
  and scrubbed.
- **Migration.** One forward-only migration in three dialects written as
  `0050_saml.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; fuzz targets run 60 s
  each locally; final fast tier `TMPDIR=/dev/shm/za37a GOTMPDIR=/dev/shm/za37a go test -p 4 ./...`
  plus `make e2e-saml` and `make e2e-deploy`; push `plan-37a-saml`;
  report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan37a`, branch `plan-37a-saml`;
  record in `docs/superpowers/2026-11-16-plan-37a-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Signature wrapping corpus** (moved assertion, duplicate assertion,
   unsigned response wrapping a signed assertion from elsewhere, NameID
   comment injection) → all refused. Task 3 `TestVerifyWrappingCorpus`.
2. **Replay:** the same assertion posted twice (two replicas) → second
   refused. Task 7 `TestACSReplay`.
3. **IdP-initiated policy:** unsolicited response with IdP-initiated
   disabled → refused; enabled → lands only on the configured client.
   Task 7 `TestIdPInitiatedPolicy`.
4. **ACS URL on the IdP side:** an `AuthnRequest` naming an ACS outside
   the client's callbacks → error page, no response posted. Task 5
   `TestIdPACSAllowlist`.

---

### Task 1: Contracts, decisions, vendoring proposal
**Files:** `api/management.yaml` (`addons.samlp` schema, `samlp` connection
options, keys strategies), `api/authentication.yaml` (IdP and SP routes),
`make generate`, stubs; `internal/federation/inventory.json` (`samlp`
block); D-0130 with node-samlp provenance table; follow-ups.
- [ ] Edits → build → commit `docs: freeze Plan 37a contracts and D-0130`. Ask for §9 rulings.

### Task 2: XML parsing and canonicalization (gated §9.1)
**Files:** `internal/third_party/goxmldsig`, `internal/third_party/etree`
(if vendored, with LICENSE), `internal/samlcore/xml.go`, `c14n.go`, tests,
fuzz targets.
- [ ] Tests: W3C exc-c14n vectors; DTD/XXE refusal; size/depth limits; fuzz → implement → commit `feat(samlcore): safe XML parsing and canonicalization`.

### Task 3: Signatures
**Files:** `internal/samlcore/sign.go`, `verify.go`, tests.
- [ ] Tests: round trips per algorithm; `TestVerifyWrappingCorpus` (Review Focus 1); SHA-1 only when allowed; certificate thumbprint matching (SHA-1 and SHA-384) → implement → commit `feat(samlcore): XML signatures`.

### Task 4: Encryption and messages
**Files:** `internal/samlcore/encrypt.go`, `messages.go`, `metadata.go`, tests.
- [ ] Tests: encrypted assertion round trips; AuthnRequest/Response/Logout*/EntityDescriptor build+parse; Redirect deflate encoding; POST encoding; `requestTemplate` substitution → implement → commit `feat(samlcore): encryption, messages and metadata`.

### Task 5: IdP addon rules and SSO
**Files:** `internal/samlidp/rules.go`, `sso.go`, `assertion.go`,
`mapping.go`, routes, tests; `internal/clientrules` (addon validation);
`internal/mgmt/clients.go` (store and return the addon).
- [ ] Tests: addon rules; SP-initiated Redirect and POST; `TestIdPACSAllowlist` (Review Focus 4); `connection` and `organization` parameters; assertion contents table (§4.2) with node-samlp defaults; mappings/probes/UPN/typed attributes; `signResponse` → implement → commit `feat(samlidp): SAML IdP single sign-on`.

### Task 6: IdP metadata, IdP-initiated, SLO, `api.samlResponse`
**Files:** `internal/samlidp/metadata.go`, `slo.go`, `internal/actions`
(setters, inventory), storage `saml_sessions`, tests.
- [ ] Tests: metadata with current/next certs; IdP-initiated SSO; SLO request/response and propagation with `slo_enabled`; each `api.samlResponse` setter; invalid setter values throw → implement → commit `feat(samlidp): metadata, IdP-initiated SSO, single logout and Actions setters`.

### Task 7: SP connection rules and login
**Files:** `internal/federation/rules/samlp.go`, `internal/federation/saml.go`,
ACS handler on `/login/callback?connection=`, metadata fetch, storage
(`saml_replay`, metadata cache), keys API strategies (Plan 36 handler),
tests.
- [ ] Tests: rules table (metadata URL/XML/manual, thumbprints computed, `entityId` default); login via fixture IdP; encrypted assertion; `TestACSReplay` (Review Focus 2); skew; `TestIdPInitiatedPolicy` (Review Focus 3); `fieldsMap`; user ID format; HRD with `domain_aliases` → implement → commit `feat(federation): SAML service-provider connections`.

### Task 8: SP metadata and SLO
**Files:** SP metadata route, SP logout send/receive, `disableSignout`,
back-channel initiators, tests.
- [ ] Tests: SP metadata contents (entityID, ACS, signing/encryption keys); logout sends LogoutRequest; IdP-initiated logout ends the session → implement → commit `feat(federation): SAML SP metadata and single logout`.

### Task 9: Console, seed, Deploy CLI
- [ ] Console addon editor + usage tab; SAML connection pages; seed; Deploy CLI four-cell round trip with an addon client and a `samlp` connection; commit `feat(console): SAML addon and connections`.

### Task 10: E2E, docs, final verification (E2E gated §9.2)
- [ ] **Step 1:** `make e2e-saml` (`run-m37a-saml.sh`): approved npm SP library against zeroauthy IdP; approved npm IdP against zeroauthy SP; Playwright both directions; SLO; CI matrix.
- [ ] **Step 2:** Docs: new `docs/saml.md`; `docs/enterprise-connections.md`, compatibility files, `NOTICE` (vendored code), `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 3:** Fast tier + fuzz smoke + E2E; push `plan-37a-saml`; record CI; security-focused whole-branch review; maintainer approval.
