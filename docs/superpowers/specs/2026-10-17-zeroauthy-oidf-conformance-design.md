# zeroauthy — Design: OpenID conformance testing and certification (Plan 12)

- **Status:** Draft, awaiting review
- **Date:** 2026-10-17
- **Scope:** run the OpenID Foundation (OIDF) conformance suite against zeroauthy, locally and on demand in CI. Reach a clean pass for four OpenID Provider certification profiles. Certify those profiles with OIDF under its open-source fee-waiver policy.

## 1. Goal

zeroauthy passes the OIDF conformance suite for the profiles it implements, keeps passing as it changes, and is listed as an OpenID Certified provider.

The maintainer wants the suite as a guard against drifting out of conformance, not only as a one-off certification exercise. It is too heavy for every push: three containers, roughly 10–20 minutes, browser-driven logins. So it runs:
- locally, on demand (`make conformance`), when a change might affect it;
- in CI, through a manually triggered workflow;
- later, as a gate in the release pipeline. That pipeline is the last milestone, after the management UI (sub-project 3); it is out of scope here, but this plan must leave a script it can call.

**Success:**
- `make conformance` starts the suite and a seeded zeroauthy on this machine and runs the four plans headless. It exits 0 only when every test module finishes without failure, apart from the checked-in expected failures and skips. Those files start empty, and each entry needs a recorded decision.
- The `conformance` GitHub workflow (`workflow_dispatch`) runs the same script and uploads the suite's results as an artifact.
- Certification: the four plans pass on OIDF's hosted suite against a temporary public zeroauthy on the maintainer's DigitalOcean subdomain. The submission packages are prepared, and the fee-waiver request is sent to OIDF.

**Anti-goals:**
- Making ordinary pushes slower: the suite stays out of the push and PR CI.
- Quietly changing Auth0-compatible behaviour to pass a test. Every conflict between Auth0 behaviour and the specs goes to the maintainer (§5).
- Publishing secrets: certification logs are published, so the public run uses throwaway clients, keys and users only.

## 2. Profiles

| OIDF test plan | Certification profile | Why |
|---|---|---|
| `oidcc-basic-certification-test-plan` | Basic OP | Authorization code flow, the core of zeroauthy |
| `oidcc-config-certification-test-plan` | Config OP | Discovery and JWKS |
| `oidcc-formpost-basic-certification-test-plan` | Form Post OP (basic) | `response_mode=form_post` is supported |
| `oidcc-rp-initiated-logout-certification-test-plan` | RP-Initiated OP | `/oidc/logout` exists |

**Variants** (OIDF certifies per variant selection):
- every plan uses `server_metadata=discovery` and `client_registration=static_client` (zeroauthy has no registration endpoint);
- Basic and Form Post use `client_auth_type=client_secret_basic`, the variant the RP-initiated logout plan fixes. `client_secret_post` is a later, optional extra run;
- RP-initiated logout fixes its own variants (discovery, `client_secret_basic`, default response mode).

**Not attempted** (zeroauthy lacks the feature): Implicit, Hybrid and their form-post variants (no implicit or hybrid response types), Dynamic OP (no dynamic client registration), front-channel and back-channel logout. Each is a candidate for a later plan once the feature exists. The FAPI, CIBA and identity-assurance plans are out of scope.

## 3. Sources

- OIDF conformance suite: https://gitlab.com/openid/conformance-suite (MIT). It is a permitted test tool under CLEAN_ROOM.md "Permitted sources", which already covers open standards. Using an OIDF tool raises no clean-room issue: it tests the specs, not Auth0.
- OpenID Connect Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0, and the OAuth 2.0 Form Post Response Mode.
- OIDF certification: https://openid.net/certification/instructions/, https://openid.net/certification/op_submission/, https://openid.net/certification/open-source-project-certification-policy/
- The suite's own CI (`.gitlab-ci/run-tests.sh`, `scripts/run-test-plan.py`, `expected-failures-*.json`), as the model for automated runs.

## 4. Local and CI harness

### 4.1 Pieces

- **`tests/conformance/`** (new):
  - `run.sh`: the entry point, used by `make conformance` and the workflow.
  - `seed.yaml`: a dedicated tenant with:
    - two first-party regular-web clients using `client_secret_basic`, with `authorization_code` and `refresh_token` grants;
    - callbacks and `allowed_logout_urls` pointing at the suite's fixed-alias URLs;
    - a test user with name and email claims.

    The seed is generated from a template for the hosted run, because the URLs differ and the secrets must be fresh.
  - `config/*.json`: one suite configuration per plan, modelled on the suite's own `.gitlab-ci/local-provider-oidcc-conformance-config.json`. Each holds the server's discovery URL, the two clients (`client` and `client2`, which several Basic tests need), a fixed suite alias so callback URLs are stable, and the `browser` steps for zeroauthy's pages.
  - **Browser automation:** the suite drives pages with its own built-in browser inside the suite server, an HtmlUnit-style engine, not Chromium. The steps reach elements by `name`, `id` or `class`.
    - zeroauthy's login, consent and logout-confirmation pages must therefore work as plain HTML forms without JavaScript. They are server-rendered today; the builder confirms this and adds stable `name` or `id` hooks if missing.
    - The steps cover login, consent (or a client set to skip it) and the `/oidc/logout` confirmation page, which shows when the `id_token_hint`'s session doesn't match the browser.
  - `expected-failures.json` and `expected-skips.json`, in the suite's own format.
  - A README.
- **The suite** runs from OIDF's prebuilt images (`registry.gitlab.com/openid/conformance-suite` and its nginx image) plus `mongo`, through its `docker-compose-prebuilt.yml`. The image tag is pinned to a released version tag of the suite's registry images, at least two weeks old, recorded in one place and bumped deliberately. Before the certification run, the pin is bumped to the version the hosted suite runs, and the local pass is repeated on it. `run-test-plan.py` comes from the same pinned version (a pinned checkout or download in a cache directory, not vendored).
- **Containers:** podman (docker here is podman emulation). In GitHub Actions, the runner's docker.
- **zeroauthy** is built from the working tree and run on the host with TLS and a fresh SQLite database, the same way `tests/e2e/run-browser.sh` does it.

### 4.2 Networking (both directions over HTTPS)

- The suite calls zeroauthy: discovery, JWKS, token, userinfo and logout.
- zeroauthy redirects the browser to the suite's callback URLs, and the suite's headless browser drives zeroauthy's hosted pages.
- zeroauthy therefore needs a hostname the suite container can resolve and a certificate the suite trusts. The suite also needs a base URL that zeroauthy's registered callbacks and post-logout URLs can name.
- **Host header:** zeroauthy resolves the tenant and derives the issuer from the Host header. So the hostname in the discovery URL, the issuer and the registered URIs must be one fixed name, for example a `conformance` tenant under a test base domain.
- **TLS:** a generated CA signs zeroauthy's certificate. The suite's JVM must trust it, not only nginx, for example through a truststore passed with `JAVA_TOOL_OPTIONS` or a thin image layer.
- **Wiring:** host networking, `host.containers.internal`, or zeroauthy in a container on the suite's network are all acceptable. Running zeroauthy in a container is fine if that is what makes the two directions work. The constraint is that it works under rootless podman locally and docker in GitHub Actions, without root-only host changes such as editing `/etc/hosts`.

### 4.3 Results

- `run.sh` runs the four plans one after another, then writes a summary: per plan, the counts of passed, failed, warning, review and skipped modules.
- It exits non-zero on any failure not listed in `expected-failures.json`, and on any listed expected failure that now passes. The second rule keeps the list honest.
- Modules that need a human to look at a screenshot (review status) do not fail the run.
- The suite's exported results (HTML and JSON) are written to a results directory. CI uploads it as an artifact.

### 4.4 CI

- A new workflow, `.github/workflows/conformance.yml`, triggered by `workflow_dispatch` only, runs `run.sh` on `ubuntu-latest`.
- The existing `ci.yml` is not changed.

## 5. Conflicts with Auth0 behaviour

The dry run will find failures. Claude classifies each one. Plain bugs and configuration problems are fixed without asking. Parity conflicts, and any case where it is unclear whether Auth0 behaves that way, go to the maintainer. Each failure is classified as one of:
- **A plain bug or gap** (zeroauthy does neither what Auth0 does nor what the spec says): fix it.
- **An Auth0-parity conflict** (zeroauthy copies documented or observed Auth0 behaviour that the spec forbids): **stop and flag it to the maintainer, one case at a time.**
  - The maintainer's stated leaning: the spec-compliant behaviour becomes the default, and the Auth0 behaviour stays available behind an opt-in **environment variable** whose name says plainly that it is not OpenID compliant.
  - Each ruling is recorded as a compat decision (D-0035 onward) and a matrix note.
  - If the maintainer chooses to keep Auth0 behaviour, the module goes into `expected-failures.json`, and that profile may be dropped from certification.
- **A suite configuration problem** (wrong client setup, missing browser step): fix the config.

**Scopes and claims the suite probes that zeroauthy may not support:** Basic includes `scope-address` and `scope-phone`, and discovery advertises neither scope. If these modules fail rather than skip, it is a gap to raise with the maintainer: implement the claims, or record an expected failure, depending on whether Auth0 supports them.

Switches added this way are server-wide, not per tenant:
- **Where they live:** a new `compat` config section, read by the existing config loader, so each switch can be set in `config.yaml` or through its environment variable (`ZEROAUTHY_COMPAT__<NAME>`). The loader already maps nested keys this way and rejects unknown `ZEROAUTHY_` variables.
- **Naming:** each switch carries a `noncompliant_` prefix (for example `compat.noncompliant_<behaviour>`, set with `ZEROAUTHY_COMPAT__NONCOMPLIANT_<BEHAVIOUR>=true`).
- **Default:** off, meaning spec-compliant. That is a behaviour change for existing deployments that relied on the Auth0 behaviour, so each one is listed in the changelog and in `docs/conformance.md` with its switch.
- **At startup:** the server logs a warning naming every non-compliant switch that is on.
- **Conformance run:** it uses the defaults, all switches off.

## 6. Certification run

1. **Local pass:** all four plans pass locally with empty expected-failure lists, or with lists the maintainer has approved entry by entry.
2. **Public deployment** (done by hand; the deploy pipeline comes later):
   - The maintainer deploys zeroauthy to a DigitalOcean droplet on a subdomain with a valid public TLS certificate.
   - It is seeded with the conformance tenant: fresh throwaway client secrets, a throwaway signing key and a throwaway test user.
   - The plan provides the deployment notes (binary, config, seed, TLS, firewall) as `docs/conformance.md`, not automation.
3. **Hosted run:** the four plans run on www.certification.openid.net against the public deployment, using the same configs with the public URLs.
   - Modules needing screenshots or human review are completed by the maintainer in the suite's UI.
   - Every module must reach FINISHED. Warnings are acceptable.
4. **Packages:** one package per profile. Each holds the exported logs and the signed "OpenID Certification of Conformance" document, which needs the maintainer's signature.
5. **Waiver and submission:**
   - The maintainer emails certification@oidf.org asking for the open-source fee waiver.
   - The email asserts that zeroauthy's primary maintainers are not paid by an employer for the project.
   - Submission follows OIDF's instructions once the waiver is answered.
6. **Teardown:**
   - The clients are deactivated, the signing key is rotated or removed, and the droplet is destroyed or wiped.
   - Nothing from the public run's seed is reused.

Steps 2–6 need the maintainer's hands: deploying, signing and emailing. The plan's tasks for them are checklists the maintainer follows with Claude's help. Before the hosted run, Claude confirms with OIDF's current instructions whether results from a locally run suite are acceptable. If they are, the hosted run is still preferred, because the submission pages name the hosted suite.

## 7. Testing this plan's own code

- `run.sh` exit-code logic (unexpected failure, stale expected failure, review status) is checked with a small fixture of fake suite results, not by running the suite.
- The seed is loaded by the existing seed tests.
- The suite run itself is the integration test.

## 8. Documentation

- `docs/conformance.md`:
  - running `make conformance` and the workflow
  - reading results
  - the expected-failure process
  - the certification checklist from §6, including teardown and secret hygiene
- README: an "OpenID conformance" section, and the certification mark once granted (following OIDF's usage rules).
- `docs/compat/matrix.md`: a row per profile with its status.
- `docs/superpowers/plan-1-followups.md`:
  - the release-pipeline gate (last milestone)
  - Implicit and Hybrid, Dynamic, and front-channel and back-channel logout as future profiles
  - recertification when the suite or zeroauthy changes significantly

## 9. Out of scope

- The release or deploy pipeline (the last milestone, after the management UI).
- Running the suite on every push.
- New OpenID features to unlock more profiles.
- Automated deployment to DigitalOcean.
- RP (client) certification.
