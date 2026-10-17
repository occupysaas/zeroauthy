# zeroauthy Plan 12: OpenID conformance testing and certification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `make conformance` runs the OIDF conformance suite against a seeded zeroauthy for the Basic OP, Config OP, Form Post OP and RP-Initiated OP plans, CI can run it on demand, every failure is fixed or ruled on, and zeroauthy is certified for those profiles.

**Architecture:**
- **`tests/conformance/`:**
  - Starts OIDF's prebuilt suite images (server, nginx, mongo) with podman, or docker in CI, next to a TLS zeroauthy built from the working tree.
  - Drives the four test plans with the suite's own `run-test-plan.py`, from the same pinned version.
  - Gates on the runner's exit status, using our expected-failures and expected-skips files, which start empty.
- **A dry run produces a triage file.** Plain bugs are fixed with unit tests reproducing the suite's check. Parity conflicts go to the maintainer one by one. A ruling for the spec adds a `compat.noncompliant_*` switch (env `ZEROAUTHY_COMPAT__NONCOMPLIANT_*`) that keeps the Auth0 behaviour available.
- **Certification:**
  - The four plans run on OIDF's hosted suite against a temporary public zeroauthy on the maintainer's DigitalOcean subdomain.
  - The maintainer signs and submits the packages, and asks OIDF for the open-source fee waiver.

**Tech Stack:**
- Bash, Python 3 with the suite's `scripts/requirements.txt` (httpx, pyparsing) in a venv under the cache directory.
- OIDF conformance suite images `registry.gitlab.com/openid/conformance-suite` and `…/nginx`, plus `mongo:6.0.13`.
- podman locally, docker on GitHub Actions. No new Go dependencies.

**Spec:** `docs/superpowers/specs/2026-10-17-zeroauthy-oidf-conformance-design.md` (approved 2026-10-17).

## Global Constraints

- **Plans and variants:**
  - `oidcc-basic-certification-test-plan`, `oidcc-config-certification-test-plan`, `oidcc-formpost-basic-certification-test-plan` and `oidcc-rp-initiated-logout-certification-test-plan`.
  - Variants: `server_metadata=discovery`, `client_registration=static_client`, `client_auth_type=client_secret_basic`. Nothing else.
- **Suite version:** one pinned release tag, at least two weeks old, in `tests/conformance/suite-version`. The images and `run-test-plan.py` come from that tag.
- **Expected failures and skips:** `tests/conformance/expected-failures.json` and `expected-skips.json` start as `[]`. Every entry needs a compat decision (D-0035 onward) approved by the maintainer.
- **Parity conflicts are never decided by the implementer.** A failure where zeroauthy follows documented or observed Auth0 behaviour, or where it is unclear whether it does, is written to the triage file and stops that item until the maintainer rules.
- **Non-compliant switches:**
  - Config key `compat.noncompliant_<behaviour>` (bool, default `false`), env `ZEROAUTHY_COMPAT__NONCOMPLIANT_<BEHAVIOUR>`.
  - Each switch that is on is logged as a warning at startup.
  - The conformance run uses all defaults.
- **No secrets in the repository:** local client secrets are fixed, not-for-production values, as in the E2E seed. The public run's secrets, signing key and user password are generated fresh and never committed.
- **Push CI stays as is:** `.github/workflows/ci.yml` is not changed. Conformance runs through `make conformance` and a `workflow_dispatch` workflow.
- **Earlier constraints:** `go test -race ./...`, `go vet ./...` and `gofmt -l .` stay clean, `go generate ./...` leaves no diff, and the browser E2E stays green. Never install databases on the host.

## Review Focus

1. **The suite's built-in browser on zeroauthy's pages.**
   - It is an HtmlUnit-style engine inside the suite server. The `form_post` response page auto-submits with a nonce'd script, and the login, consent and logout-confirmation pages are plain forms whose buttons have no class.
   - The browser steps must use `css` selectors that exist (`button[type=submit]`, `button[name=action][value=accept]`), and a form-post response must reach the suite's callback.
   - Pinned in Task 2's Form Post run. If HtmlUnit cannot run the auto-submit, the fix is a `<noscript>` submit button on `form_post.html`, with a ui test.
2. **The tenant comes from the Host header.**
   - The suite reaches zeroauthy under one fixed hostname. The issuer in discovery, the ID tokens' `iss` and the registered redirect URIs must all use exactly that host and port.
   - A mismatch shows up as issuer failures in every plan. Pinned by the Config plan passing in Task 1.
3. **The second client.** Basic's cross-client tests (a code issued to `client` presented by `client2`) need both clients in the seed with distinct secrets and callbacks. Pinned in Task 2.
4. **Logout confirmation.** `/oidc/logout` with an `id_token_hint` whose session differs from the browser's session shows a confirm page. The RP-initiated plan's browser steps must click through it, and `post_logout_redirect_uri` values must be registered per client. Pinned in Task 2.
5. **A stale run state.**
   - Mongo data from a previous run, or a zeroauthy left over from an earlier run, can make results lie.
   - `run.sh` uses a fresh compose project per run (a unique project name, no host-mounted Mongo volume) and tears everything down on exit, including on Ctrl-C.
   - Pinned in Task 1 by running `make conformance` twice in a row.

---

## File Structure

| File | Responsibility |
|---|---|
| `tests/conformance/run.sh` (new) | Entry point: certs, zeroauthy, suite containers, the four plans, teardown, exit status |
| `tests/conformance/suite-version` (new) | Pinned suite release tag |
| `tests/conformance/compose.yml` (new) | Suite services (derived from the suite's `docker-compose-prebuilt.yml`), no host volumes, truststore wiring |
| `tests/conformance/seed.yaml` (new) | Conformance tenant, `client` and `client2`, test user |
| `tests/conformance/config.yaml` (new) | zeroauthy server config for the run |
| `tests/conformance/configs/{basic,config,formpost,logout}.json` (new) | Suite configurations with `{BASEURL}` placeholders and browser steps |
| `tests/conformance/expected-failures.json`, `expected-skips.json` (new) | `[]` until rulings say otherwise |
| `tests/conformance/README.md` (new) | Short usage; points at `docs/conformance.md` |
| `tests/conformance/triage-2026-10.md` (new, Task 2) | Dry-run findings and their classification |
| `Makefile` | `conformance` target |
| `.github/workflows/conformance.yml` (new) | `workflow_dispatch` run, artifact upload |
| `internal/config/config.go`, test (Task 4, only if needed) | `Compat` section and startup warning |
| `docs/conformance.md` (new), `docs/compat/{matrix,decisions}.md`, `README.md`, `docs/superpowers/plan-1-followups.md` | Docs and records |

---

### Task 1: The harness, proven with the Config OP plan

**Files:**
- Create: `tests/conformance/run.sh`, `suite-version`, `compose.yml`, `seed.yaml`, `config.yaml`, `configs/config.json`, `expected-failures.json`, `expected-skips.json`, `README.md`
- Modify: `Makefile` (`conformance: ; ./tests/conformance/run.sh`), `.gitignore` (the cache and results directories)

**Interfaces:**
- Produces:
  - `./tests/conformance/run.sh [plan-name ...]`. With no arguments it runs all four plans; with arguments, only those (`basic`, `config`, `formpost`, `logout`).
  - Results go to `tests/conformance/results/<timestamp>/` (git-ignored). The exit status is `run-test-plan.py`'s.
  - Environment: `CONFORMANCE_RUNTIME` (`podman` by default, `docker` in CI) and `CONFORMANCE_KEEP=1` (leave the containers up for debugging).
- Fixed names used by later tasks:
  - zeroauthy host `zeroauthy.conformance.test`, tenant `conformance`.
  - Suite base URL `https://localhost.emobix.co.uk:8443/` (the suite's default, which resolves to 127.0.0.1 and is aliased inside the compose network).
  - Suite alias `zeroauthy`, so the callbacks are `https://localhost.emobix.co.uk:8443/test/a/zeroauthy/callback` and the post-logout URI is `…/test/a/zeroauthy/post_logout_redirect`.

- [ ] **Step 1: Pin the suite.** Pick the newest suite release tag at least two weeks old whose `registry.gitlab.com/openid/conformance-suite:<tag>` and `…/nginx:<tag>` images both exist. Write it to `suite-version`. `run.sh` downloads that tag's `scripts/run-test-plan.py` and `scripts/requirements.txt` into `tests/conformance/.cache/<tag>/` and builds a venv there.
- [ ] **Step 2: Networking and TLS.** Make both directions work over HTTPS without root:
  - **Certificates:** generate a CA and a certificate for `zeroauthy.conformance.test` per run (as `tests/e2e/run-browser.sh` does).
  - **zeroauthy:** runs with that certificate (on the host, or in a container on the compose network, whichever works under rootless podman and under docker in Actions).
  - **Suite → zeroauthy:** the suite's JVM and nginx resolve `zeroauthy.conformance.test` to zeroauthy (a compose `extra_hosts` or network alias) and trust the CA. The JVM gets a truststore, for example `JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=…` with the CA imported by `keytool` in an init step.
  - **zeroauthy → suite:** zeroauthy needs only to redirect browsers to the suite's URLs, which the suite's own browser follows, so no extra trust is needed in that direction.
  - **Verify:** `curl --cacert` from inside the suite server container to `https://zeroauthy.conformance.test:8443/.well-known/openid-configuration` returns 200.
- [ ] **Step 3: Seed and config.**
  - **`seed.yaml`:** tenant `conformance` with domain `zeroauthy.conformance.test`. Two first-party `regular_web` clients, `za-conformance-1` and `za-conformance-2`, with `client_secret_basic` and fixed `*-not-for-production` secrets. Grants `[authorization_code, refresh_token]`. Callbacks and `allowed_logout_urls` set to the suite URLs above. A database connection enabled for both clients.
  - **Test user:** `conformance@example.com`, password `Conformance-Horse-9`, `email_verified: true`, name "Conformance User".
  - **`config.yaml`:** like `tests/e2e/config.yaml`, with SQLite in the run directory and this seed.
- [ ] **Step 4: `configs/config.json`.** Description, `server.discoveryUrl` (`https://zeroauthy.conformance.test:8443/.well-known/openid-configuration`), `alias: zeroauthy`, and `client` and `client2` with `client_id` and `client_secret`, in the shape the suite's own static-client configs use. Browser steps are not needed for Config.
- [ ] **Step 5: `run.sh`.**
  1. Start a uniquely named compose project and wait for the suite's `/api/runner/available` to answer.
  2. Start zeroauthy and wait for its health check.
  3. Run the plans in this form, where `CONFORMANCE_SERVER` is the suite base URL with a trailing slash and the `--expected-*` flags take our two files:

     ```bash
     run-test-plan.py --export-dir <results> --expected-failures-file … --expected-skips-file … \
       'oidcc-config-certification-test-plan[server_metadata=discovery][client_registration=static_client]' configs/config.json
     ```

  4. Tear everything down in a trap (`compose down -v`, kill zeroauthy, remove the run directory unless `CONFORMANCE_KEEP=1`).
  5. Print a one-line summary per plan and exit with the runner's status.
  6. Stale entries (design §4.3): check whether the runner fails when an expected failure no longer happens (its `--verbose` output reports them).
     - If it does not, `run.sh` greps that report and exits non-zero. Test that logic with a recorded runner output in `tests/conformance/testdata/`; that covers design §7's fixture test.
     - If it does, rely on it and note that in the README.
- [ ] **Step 6: Run it twice.** `make conformance` with `config` only, two times in a row. Expected: both runs reach a verdict.
  - Failures that are configuration problems are fixed here.
  - Product failures in the Config plan are written down for Task 2's triage file, not fixed in this task.
- [ ] **Step 7: Commit** with `test(conformance): OIDF suite harness with the Config OP plan`.

---

### Task 2: The other three plans and the dry-run triage

**Files:**
- Create: `tests/conformance/configs/{basic,formpost,logout}.json`, `tests/conformance/triage-2026-10.md`
- Modify: `tests/conformance/run.sh` (the plan list)

**Interfaces:**
- Consumes: Task 1's harness and fixed names.
- Produces:
  - All four plans wired into `run.sh`.
  - A triage file with one row per failed or warning module: plan, module, condition, observed behaviour, spec clause, and a classification.
  - The classifications are **bug**, **config**, **parity conflict** (with the Auth0 source that documents or shows the behaviour), **unclear** (it is not known what Auth0 does), and **feature gap** (e.g. address and phone scopes).

- [ ] **Step 1: Browser steps.** In each config's `browser` block, match `https://zeroauthy.conformance.test:8443/authorize*` with these tasks:
  - **Login** (optional): match `*/u/login*`. Fill `id username` and `id password`, then click `css button[type=submit]`.
  - **Consent** (optional): match `*/u/consent*`, click `css button[name=action][value=accept]`.
  - **Verify Complete:** match `*/test/*/callback*`, wait for `id submission_complete`.
  - **Logout:** a second browser entry matching `*/oidc/logout*` clicks `css button[type=submit]` on the confirmation page.

  The step syntax follows the suite's `local-provider-oidcc-conformance-config.json`.
- [ ] **Step 2: Wire the plans:**
  - `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client][client_auth_type=client_secret_basic]`
  - `oidcc-formpost-basic-certification-test-plan[…same…]`
  - `oidcc-rp-initiated-logout-certification-test-plan` (the plan fixes its own variants)
- [ ] **Step 3: Dry run.** `make conformance`. Fix config problems and rerun until every remaining failure is a product behaviour. Keep the final results directory path in the triage file.
- [ ] **Step 4: Classify.** For each failure, read the condition in the exported log and the spec clause it cites, then check zeroauthy's code and docs/compat (observations and decisions) for Auth0 provenance. Classify per the Interfaces list. Do not change product code in this task.
- [ ] **Step 5: Commit** with `test(conformance): Basic, Form Post and RP-initiated logout plans; dry-run triage`.
- [ ] **Step 6: Maintainer checkpoint.** Bring every **parity conflict**, **unclear** and **feature gap** row to the maintainer, one at a time. For each: what the spec requires, what Auth0 does (with the source), what zeroauthy does, and the options:
  - spec by default, with a non-compliant switch;
  - keep Auth0 behaviour as an expected failure, possibly dropping that profile;
  - implement the missing feature.

  Record each ruling in the triage file. **Bug** rows need no ruling.

---

### Task 3: Fix the bugs

**Files:** decided by the triage file's **bug** rows. Each fix touches the package that owns the behaviour (`internal/oidc`, `internal/authz`, `internal/oauth`, `internal/login`, `internal/ui`).

**Interfaces:**
- Consumes: the triage file.
- Produces: bug rows marked fixed with their commit SHAs.

For each bug row, in this order:
- [ ] **Write a failing Go test** in the owning package that reproduces the suite's check: the same request and the same assertion the suite's condition makes.
- [ ] **Run it.** It must fail for the reason the suite gave.
- [ ] **Fix the code** minimally, consistent with the spec clause in the triage row.
- [ ] **Run** the package tests, then `go test -race ./...`. Expected: PASS.
- [ ] **Commit** with `fix(<pkg>): <spec behaviour> (OIDF <module-name>)`.

When every bug row is done:
- [ ] **Run** `make conformance` and `./tests/e2e/run-browser.sh`. Expected: the bug rows' modules pass, and the E2E is still 19/19. If a fix changed an E2E or Auth0-SDK expectation, stop. That fix was not a plain bug: move the row to **parity conflict** and take it to the maintainer.
- [ ] **Commit** the updated triage file.

---

### Task 4: Rulings: non-compliant switches, features, expected failures

Run this task only for rulings from Task 2's checkpoint. Skip it if there are none.

**Files:**
- Modify: `internal/config/config.go` and `config_test.go`; the owning package for each switch; `internal/app/app.go` (startup warning); `docs/compat/decisions.md`; `tests/conformance/expected-failures.json` and `expected-skips.json`.

**Interfaces:**
- Produces:

```go
// config: added once, the first time a switch is needed.
type Compat struct {
	// One bool per ruling, all defaulting to false (spec-compliant), e.g.:
	// NoncompliantFoo bool `koanf:"noncompliant_foo"`
}
// Config gains: Compat Compat `koanf:"compat"`
// app: at startup, log.Warn once per enabled switch: "non-compliant compatibility switch enabled", "switch", "compat.noncompliant_foo".
```

For each ruling:
- [ ] **Spec by default plus a switch.**
  - Tests: the default is spec behaviour, and with the switch on the behaviour matches Auth0. Add a config test that the env var `ZEROAUTHY_COMPAT__NONCOMPLIANT_<NAME>=true` sets it.
  - Implement both, and record decision D-0035+ (context, sources, the spec clause, what changes for existing deployments).
- [ ] **Keep Auth0 behaviour.** Add an `expected-failures.json` entry in the suite's format (`test-name`, `variant`, `configuration-filename`, `current-block`, `condition`, `expected-result`, `comment` naming the decision), and record the decision.
- [ ] **Implement a feature** (e.g. address and phone claims). Plan it as its own small TDD cycle within this task. If it grows past a few files, stop and ask the maintainer whether it becomes its own plan.
- [ ] **Run** `go test -race ./...`, `./tests/e2e/run-browser.sh` and `make conformance`. Expected: green, with only the approved expected failures.
- [ ] **Commit** each ruling separately: `feat(compat): <behaviour> follows the spec; ZEROAUTHY_COMPAT__NONCOMPLIANT_<NAME> keeps Auth0's` (or `test(conformance): expected failure for <module> (D-00xx)`).

---

### Task 5: The on-demand CI workflow

**Files:**
- Create: `.github/workflows/conformance.yml`

- [ ] **Step 1: Write the workflow.**
  - Trigger: `on: workflow_dispatch`, with an optional `plans` input (space-separated; default all four).
  - Steps:
    - checkout, `setup-go` (`go-version-file: go.mod`) and `setup-python` (3.12)
    - `CONFORMANCE_RUNTIME=docker ./tests/conformance/run.sh ${{ inputs.plans }}`
    - `actions/upload-artifact` of `tests/conformance/results/` with `if: always()`
  - Timeout: 60 minutes.
- [ ] **Step 2: Check it locally as far as possible.** Run `run.sh` with `CONFORMANCE_RUNTIME=docker` (docker here is podman emulation) to catch runtime-specific flags. Then run `actionlint` if available, or validate the YAML with `python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))'`.
- [ ] **Step 3: Commit** with `ci: on-demand OpenID conformance workflow`. After the next push, ask the maintainer to start it from the Actions tab once, and fix anything that differs on Actions (that run is the real test).

---

### Task 6: Documentation and records

**Files:**
- Create: `docs/conformance.md`
- Modify: `tests/conformance/README.md`, `docs/compat/matrix.md`, `README.md`, `docs/superpowers/plan-1-followups.md`, the design spec's status

- [ ] **Step 1: `docs/conformance.md`:**
  - What the suite is, and which profiles and variants zeroauthy targets.
  - Running `make conformance` (prerequisites: podman or docker, Python 3, about 2 GB of RAM, 10–20 minutes), `CONFORMANCE_KEEP`, and plan selection.
  - The workflow, and reading the results directory.
  - The expected-failure process (a maintainer-approved decision per entry).
  - The non-compliant switches (a table, empty if there are none).
  - The certification checklist from the design's §6, filled in by Task 7.
- [ ] **Step 2: Records.**
  - **Matrix:** one row per profile with its local status.
  - **README:** an "OpenID conformance" section.
  - **Follow-ups:**
    - the release-pipeline conformance gate (last milestone, after the management UI)
    - a `client_secret_post` variant run
    - Implicit and Hybrid, Dynamic, front-channel and back-channel logout as future profiles
    - recertification when the suite or zeroauthy changes significantly
- [ ] **Step 3: Verify.** Run `gofmt -l .`, `go vet ./...`, `go test -race ./...` and `make conformance`. Expected: clean.
- [ ] **Step 4: Commit** with `docs: OpenID conformance guide and records`.

---

### Task 7: Certification (with the maintainer)

This task needs the maintainer at every step: deploying, holding the OIDF account, signing, emailing. Claude prepares the files and checks each step. Nothing secret is committed.

**Files:**
- Create: `tests/conformance/public/seed.yaml.tmpl` and `tests/conformance/public/make-seed.sh`. The script fills in the public hostname, fresh random client secrets and a fresh user password, and writes the result outside the repository.
- Create: `tests/conformance/public/configs/*.json.tmpl`, the hosted-run configs with the public discovery URL and the hosted suite's callback URLs.
- Modify: `docs/conformance.md` (the certification section, with the exact steps used).

- [ ] **Step 1: Confirm the rules.** Read OIDF's current OP certification instructions and submission pages. Confirm:
  - the hosted suite is required, or at least preferred;
  - the hosted suite's version;
  - the callback URL shape for the hosted suite (`https://www.certification.openid.net/test/a/<alias>/callback`);
  - the package contents.

  Bump `suite-version` to the hosted version (if it is at least as new), rerun `make conformance`, and fix any new failures through Tasks 3 and 4.
- [ ] **Step 2: Deployment notes and seed.** Write the droplet steps in `docs/conformance.md`: the binary built with `make build`, `config.yaml`, the generated seed, a TLS certificate for the subdomain (e.g. Let's Encrypt via a reverse proxy, or zeroauthy's own TLS settings), and a firewall allowing 443. The maintainer deploys, and Claude verifies discovery from outside with `curl`.
- [ ] **Step 3: Hosted run.**
  - The maintainer creates the four test plans on www.certification.openid.net with the generated configs.
  - Claude helps work through failures; anything new goes back through Tasks 3 and 4 locally before rerunning.
  - Review-status modules (screenshots) are completed by the maintainer in the suite UI.
  - Done when every module is FINISHED, with no failures. Warnings are acceptable.
- [ ] **Step 4: Packages.** For each profile, export the logs and fill in "OpenID Certification of Conformance" (Claude drafts the field values; the maintainer signs). Before export, check the logs contain only throwaway secrets.
- [ ] **Step 5: Waiver and submission.** Claude drafts the email to certification@oidf.org:
  - project URL and license
  - the open-source policy URL
  - the statement that zeroauthy's primary maintainers are not paid by an employer for the project
  - the four profiles and the results

  The maintainer reviews and sends it, then submits as OIDF instructs.
- [ ] **Step 6: Teardown.** Deactivate the clients and delete the droplet or its data. Record in `docs/conformance.md` the date, the suite version and the zeroauthy commit that was certified.
- [ ] **Step 7: Commit** the templates, script and docs with `docs(conformance): certification run`. Once OIDF lists zeroauthy, a follow-up commit adds the certification mark to the README following OIDF's usage rules.
