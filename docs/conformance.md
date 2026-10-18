# OpenID conformance

zeroauthy is checked against the OpenID Foundation conformance suite (https://gitlab.com/openid/conformance-suite). The suite tests the OpenID specifications, not Auth0, so it is a permitted test tool under the clean-room rules. The design is in `docs/superpowers/specs/2026-10-17-zeroauthy-oidf-conformance-design.md`; the harness is described in `tests/conformance/README.md`.

## Profiles and variants

| Plan | Profile |
|---|---|
| `oidcc-basic-certification-test-plan` | Basic OP |
| `oidcc-config-certification-test-plan` | Config OP |
| `oidcc-formpost-basic-certification-test-plan` | Form Post OP (basic) |
| `oidcc-rp-initiated-logout-certification-test-plan` | RP-Initiated OP |

- Every plan uses discovery (`server_metadata=discovery`) and static clients (`client_registration=static_client`), because zeroauthy has no registration endpoint.
- Basic and Form Post use `client_secret_basic`. The suite also runs one module with `client_secret_post`. A full `client_secret_post` variant run is a follow-up.
- Not attempted, because the feature is missing: Implicit, Hybrid, Dynamic OP, front-channel and back-channel logout.

## Running it

```bash
make conformance                 # all four plans
make conformance PLANS=config    # a subset: basic, config, formpost, logout
CONFORMANCE_RUNTIME=docker ./tests/conformance/run.sh
CONFORMANCE_KEEP=1 ./tests/conformance/run.sh config   # leave the containers up to debug
```

Prerequisites:
- Linux (teardown uses util-linux `setsid`);
- podman with `podman-compose`, or docker with the compose plugin;
- Python 3, Go, `openssl` and `curl`;
- about 2 GB of RAM;
- 10 to 20 minutes for a full run.

Port 8443 on 127.0.0.1 is shared with the browser E2E suite, so never run the two at once; `run.sh` reports a listener already there. Exit status 0 means every module finished and nothing unexpected happened.

On demand in CI: the `conformance` workflow (`.github/workflows/conformance.yml`, `workflow_dispatch` only) runs the same script and uploads the results directory.

## How a run works

`run.sh` builds zeroauthy from the working tree, makes a CA and certificate, starts the suite (mongodb, server, nginx) and zeroauthy in one compose project, checks that the suite can reach zeroauthy over TLS, runs the selected plans with the suite's own `run-test-plan.py` (pinned and hash-checked), and tears everything down. The suite's built-in browser drives zeroauthy's login, consent and logout pages as plain HTML forms.

## Reading the results

Each run writes `tests/conformance/results/<UTC timestamp>/` (ignored by git):
- `runner.log`, the full runner output;
- the suite's exported plan zips, with HTML and JSON logs per module;
- `zeroauthy.log` and `suite-server.log`.

`run.sh` ends with one summary line per plan: modules passed, failed, warning, review and skipped. Review modules need a person to look at a screenshot and do not fail the run. When a run covers only some plans, filtered copies of the expected files are written to the results directory.

## Expected failures, warnings and skips

`tests/conformance/expected-failures.json` and `expected-skips.json` use the suite's own format. The runner fails on any failure, warning or skip not listed, and on any listed entry that did not happen.

Process for each entry:
1. A conformance result that differs from the spec is classified (bug, configuration, Auth0-parity conflict, unclear, or feature gap). Plain bugs and configuration problems are fixed.
2. Everything else goes to the maintainer, one case at a time.
3. The ruling is recorded as a compat decision in `docs/compat/decisions.md`, and the entry's `comment` names it.

The current entries are accepted warnings and skips, recorded in D-0036 (with D-0035 and D-0037 for the request-object refusal and the two additive request shapes). The dry-run results and the maintainer's rulings are in `tests/conformance/triage-2026-10.md`. There are no expected failures.

## Non-compliant switches

Spec-compliant behaviour is the default. Where the maintainer rules that Auth0's behaviour must stay available, it goes behind a server-wide environment variable `ZEROAUTHY_COMPAT__NONCOMPLIANT_<BEHAVIOUR>` (default off, a startup warning when on, and the conformance run uses the defaults). Each case is decided by the maintainer.

| Switch | Auth0 behaviour it restores | Decision |
|---|---|---|
| (none) | | |

No such switch exists today.

## Certification checklist

Steps 2 to 6 need the maintainer's hands (deploying, signing, emailing). Fill the placeholders in during the hosted run.

1. **Local pass.** All four plans exit 0 locally with the approved expected lists. Bump `suite-version` to the version the hosted suite runs and repeat. Hosted suite version: TBD. Date of last local pass: TBD.
2. **Public deployment** (by hand). Deploy zeroauthy on a DigitalOcean droplet on a subdomain with a valid public TLS certificate. Seed the conformance tenant with fresh, throwaway client secrets, signing key and test user; certification logs are published, so use nothing else. Notes to be completed with the deployment: binary and config, seed, TLS, firewall. Hostname: TBD.
3. **Hosted run** on www.certification.openid.net against the public deployment, using the same configs with the public URLs. The maintainer completes screenshot and review modules in the suite's UI. Every module must reach FINISHED; warnings are acceptable. Plan IDs and dates: TBD. Before the run, confirm in OIDF's current instructions whether results from a locally run suite are acceptable; the hosted run is preferred either way.
4. **Packages.** One per profile, each with the exported logs and the signed "OpenID Certification of Conformance" document (needs the maintainer's signature). Package status: TBD.
5. **Waiver and submission.** The maintainer emails certification@oidf.org to ask for the open-source fee waiver, stating that zeroauthy's primary maintainers are not paid by an employer for the project (https://openid.net/certification/open-source-project-certification-policy/). Submit per https://openid.net/certification/instructions/ once answered. Waiver and submission dates: TBD.
6. **Teardown.** Deactivate the clients, rotate or remove the signing key, destroy or wipe the droplet. Reuse nothing from the public run's seed. Teardown date: TBD.
