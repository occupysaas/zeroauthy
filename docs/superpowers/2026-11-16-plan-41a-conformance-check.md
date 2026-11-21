# Plan 41a Implicit and Hybrid conformance inventory

Checked 2026-11-20 against the pinned OpenID Foundation suite
`release-v5.3.3`, starting from `main` commit `18d01994` with Plan 41a Task 1
contract changes. Runtime authorization behavior was unchanged. The installed
local compiler was Go `1.27.4-X:nodwarf5`; go.mod requires Go 1.26.11.

The suite's public plan classes are
[OIDCCImplicitTestPlan.java](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.3/src/main/java/net/openid/conformance/openid/OIDCCImplicitTestPlan.java)
and
[OIDCCHybridTestPlan.java](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.3/src/main/java/net/openid/conformance/openid/OIDCCHybridTestPlan.java).
Both accept `server_metadata=discovery` and
`client_registration=static_client`; response types, client authentication
and response mode are fixed by the plan.

Temporary entries in tests/conformance/run.sh selected those plans with the
existing basic.json config. The script was restored after each command.
Neither optional profile is added to the committed plan list by this check.
No expected warning or skip was added or weakened.

## Implicit

Command: `./tests/conformance/run.sh implicit hybrid` (temporary entries).
Actual exit status: **1**. Local artifacts:
`tests/conformance/results/20261121T012211Z/` (ignored; contains only the
local suite fixtures and per-run throwaway credentials).

The suite created Implicit plan `27uvdnjdCvCoB` with 54 modules. Its first
`oidcc-server` module for response_type=id_token became **INTERRUPTED**.
The server returned unsupported_response_type; the suite could not extract
an ID token from the authorization response. Several subsequent modules
were interrupted for the same reason before the runner aborted. No plan
summary or export was produced. The Python runner also reported an
unawaited-coroutine warning on abort. This is not a passing profile.

The second plan in that command was **not reached**. Hybrid therefore
requires a separate command, rather than being labeled failed from the
Implicit result.

## Hybrid

Separate command: `./tests/conformance/run.sh hybrid` (temporary entry).
Actual exit status: **1**. Artifacts:
`tests/conformance/results/20261121T012430Z/` (ignored).

The suite created Hybrid plan `tNQqYQTy9yUSz`. The first oidcc-server module
for response_type=code id_token became **INTERRUPTED**; subsequent userinfo
modules were interrupted as well, and the runner aborted without a completed
plan summary or export. The authorization endpoint rejects this response
type with unsupported_response_type. The runner again reported an
unawaited-coroutine warning on abort. This is not a passing profile.

## Eligibility

The design's statement that zeroauthy already issues implicit/hybrid
responses is inconsistent with this base. internal/authz/validate.go accepts
only response_type=code, and existing tests explicitly require rejection of
token responses. Implicit/Hybrid are optional in this plan, contingent on a
passing inventory check; adding their protocol implementation is outside
Plan 41a. Neither profile qualifies for the local certification plan list
on the evidence above. No Auth0 hosted page or live tenant was observed.
