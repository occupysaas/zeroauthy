# Plan 41a implementation record

Status: **in progress**, starting from `main` commit `18d01994` (Plan 48
merged). Branch: `plan-41a-oidc-extras-logout`; worktree:
`/mnt/nvme2/code/zeroauthy-plan41a`. Nothing has been pushed or submitted for
certification. The full plan remains active until all tasks, final local
checks and branch review are complete.

## Progress

1. Contracts, D-0080 and conformance inventory: in progress.
2. Compatibility switches: implemented; focused verification passed. Later protocol tasks still need to consume them.
3. Claims and client OIDC restrictions: in progress. The bounded claims request parser is tested; scope selection and protocol integration remain pending.
4. MFA step-up and acr: pending.
5. Client ID-token signing algorithms: pending.
6. Resource profile and redirect fallback: pending.
7. Logout settings and storage: pending.
8. Durable back-channel delivery and session-ending triggers: pending.
9. Logout session metadata: pending (Plan 48 fields already available).
10. Global revocation: pending; reserved route returns 501 without mutation.
11. Console: pending.
12. Seed and Deploy CLI: pending.
13. Conformance and certification kit: pending.
14. E2E, documentation, fast local tier, review and CI: pending.

## Verification

Local toolchain: Go `1.27.4-X:nodwarf5`; go.mod minimum stays 1.26.11. The
plan's historical 1.26.10 pin is superseded by the repository's patched
minimum; no dependency or toolchain downgrade was made.

- Baseline `go test ./api ./internal/tenantrules ./internal/logrules`: exit 0.
- API contract test: failed on missing client fields, algorithms, parameters
  and revocation route before the schemas changed; passed afterwards.
- Schema validation test: failed when both OIDC scope controls were
  permitted; passed after making them mutually exclusive.
- `make generate`: exit 0.
- `go build ./...`: exit 0 after adding the generated route's 501 adapter.
- [Implicit/Hybrid inventory](2026-11-16-plan-41a-conformance-check.md):
  Implicit exit 1; separate Hybrid run exit 1. Both abort on unsupported response types. No certification claim.

Task 2 added strict environment parsing and per-switch startup warnings.
`go test ./internal/compat ./internal/config` passed (exit 0). The real
application startup test failed before Warn was connected and passed
with all three enabled switches producing one warning each. Empty/0/false
are disabled; 1/true are enabled. Other values fail configuration without
echoing their contents. Unknown switch names still fail strict decoding.

Task 3's claims parser accepts Core claim requests and ignores unknown
members, validates target/claim object shapes and value controls, rejects
trailing JSON and invalid UTF-8, and enforces a 4096-byte bound before
parsing. Errors contain no claim values. `go test ./internal/claims` passed
(exit 0). The parser is not yet connected to authorization or token issuance.

Full Go, E2E, full conformance, vulnerability and workflow checks have not run.
There is no CI run yet; partial plan work must not be pushed.

## Rulings

The ledger and D-0080 record these choices:

- Use the current public log catalog names, rather than the plan's older
  sslo/fslo shorthand. Consumers expecting those short aliases must use
  oidc_backchannel_logout_succeeded/failed.
- Keep inventories accurate during implementation: enable emitted flags
  and active-setting descriptions alongside their runtime consumers.
- Use main's next available migration number and recheck before merge.
- Preserve go.mod's patched Go minimum; record the installed local compiler.
- Exclude optional Implicit/Hybrid profiles based on their actual failed
  inventory runs; implementing those grants remains outside this plan.
- Keep FromEnv's proposed signature and validate invalid values separately
  in config.Load; both paths use the caller-supplied environment snapshot.
- Accept canonical 0/false as explicit disabled values; other nonempty
  spellings beyond 1/true fail startup.
