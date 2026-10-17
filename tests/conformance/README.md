# OpenID conformance harness

Runs the OpenID Foundation conformance suite (https://gitlab.com/openid/conformance-suite) against a zeroauthy built from the working tree. It runs on demand, not on every push. The design is in `docs/superpowers/specs/2026-10-17-zeroauthy-oidf-conformance-design.md`.

```bash
make conformance                 # all four plans
make conformance PLANS=config    # only some: basic, config, formpost, logout
./tests/conformance/run.sh config logout
CONFORMANCE_RUNTIME=docker ./tests/conformance/run.sh   # docker instead of podman (CI)
CONFORMANCE_KEEP=1 ./tests/conformance/run.sh config    # leave everything up to debug
```

You need podman with `podman-compose`, or docker with the compose plugin. You also need `openssl`, `curl`, Go and Python 3. Nothing is installed system-wide.

## Files

| File | Purpose |
|---|---|
| `suite-version` | The pinned suite release tag (images and runner script). Bump it deliberately. |
| `suite-files.sha256` | The sha256 of each file downloaded from the suite. |
| `requirements.txt` | The runner's Python dependencies, pinned with hashes. |
| `run.sh` | The entry point. It builds zeroauthy, makes the certificates, starts the compose project, runs the plans and tears everything down. |
| `compose.yml` | The suite (mongodb, server, nginx) and zeroauthy on one network. |
| `seed.yaml`, `config.yaml` | The `conformance` tenant, and zeroauthy's config for the run. |
| `configs/<plan>.json` | One suite configuration per plan, in the suite's static-client format. |
| `expected-failures.json`, `expected-skips.json` | The suite's own format. Every entry needs a recorded decision. |
| `summarize.sh` | Turns the runner's output into one line per plan. |

## Pinned suite version

`suite-version` names a release tag of the suite. Both `registry.gitlab.com/openid/conformance-suite:<tag>` and `.../nginx:<tag>` must exist for it. Pick the newest such tag that is at least two weeks old.

`run.sh` downloads four files from that tag into `.cache/<tag>/scripts/`:
- `scripts/run-test-plan.py`;
- its two imported modules, `conformance.py` and `test_plan_parser.py`;
- `scripts/requirements.txt`.

Tags can move, so on every run each file is checked against `suite-files.sha256` with `sha256sum -c`. A mismatch stops the run before anything is executed.

The venv installs our own `requirements.txt`, not the suite's unpinned list. It holds exact versions with hashes and is installed with `pip install --require-hashes`. The suite's `requirements.txt` is downloaded and hashed only so that a pin bump shows when its dependencies change.

`.cache/<tag>/.ok` is written last. A cache without it is rebuilt from scratch.

**Bumping the pin:**
1. Change `suite-version`.
2. Delete `.cache/`.
3. Review the downloaded scripts.
4. Regenerate `suite-files.sha256`, from `.cache/<tag>/scripts`:

   ```bash
   sha256sum run-test-plan.py conformance.py test_plan_parser.py requirements.txt
   ```

5. If the suite's `requirements.txt` changed, regenerate our hashed `requirements.txt`, for example with `pip download` and `sha256sum`.
6. Before the certification run, bump the pin to the version the hosted suite runs, and repeat the local pass.

## Teardown and failures

- **Teardown:** an EXIT trap tears the run down after a normal end, an error, Ctrl-C (exit 130) or SIGTERM (exit 143). It runs `compose down -v` in its own session, so a second Ctrl-C cannot cut it short.
- **Startup failures:** if the suite or zeroauthy cannot start, `run.sh` prints:
  - the compose output;
  - the last container logs;
  - how to find and remove leftover `za-conformance-*` projects.
- **Port 8443:** a listener already on 127.0.0.1:8443, such as the e2e suite or a leftover run, is reported before anything starts.

## Networking and TLS

Everything runs in one compose project, named `za-conformance-<pid>` per run. zeroauthy runs inside it too.

- **zeroauthy runs in a container.** The suite's nginx publishes port 8443 on the host. The runner script, on the host, reaches it as `https://localhost.emobix.co.uk:8443/`, a public DNS name for 127.0.0.1. zeroauthy's URLs must also use port 8443, so it cannot also listen on the host. Instead:
  - the static binary (`CGO_ENABLED=0`) is mounted into a plain `alpine` container;
  - that container is on the compose network under the alias `zeroauthy.conformance.test`.
  - This works the same under rootless podman and under docker on GitHub's `ubuntu-latest`. It needs no host networking, no `host.containers.internal`, and no `/etc/hosts` edits.
- **Suite → zeroauthy.** The suite server resolves `zeroauthy.conformance.test` through the network alias.
  - `run.sh` makes a CA and a certificate for that name per run.
  - It builds a PKCS#12 truststore with `keytool` in a throwaway suite-image container. The truststore holds the JDK's default CAs plus ours.
  - The suite JVM loads it through `JAVA_TOOL_OPTIONS`.
  - The suite's own back-channel HTTP client accepts any certificate anyway. The truststore is there for every other TLS client in the JVM, including the HtmlUnit browser.
  - `run.sh` checks the whole path before running any plan: `curl --cacert` from inside the suite server container to zeroauthy's discovery document must return 200.
- **Browser → suite.** zeroauthy only redirects the suite's browser to the suite's URLs. nginx carries the network alias `localhost.emobix.co.uk`, so inside the network those URLs reach nginx rather than 127.0.0.1. zeroauthy needs no extra trust in this direction.
- **Host header.** The tenant's domain is `zeroauthy.conformance.test:8443`, so the issuer is `https://zeroauthy.conformance.test:8443/`.
- **Fixed names** used by the configs and the seed:
  - the suite alias is `zeroauthy`;
  - the callback is `https://localhost.emobix.co.uk:8443/test/a/zeroauthy/callback`;
  - the post-logout URI is `…/test/a/zeroauthy/post_logout_redirect`.
- **Compose tool.** `podman` uses `podman-compose`, which needs no daemon. `docker` uses `docker compose`.

## Results

Each run writes `results/<UTC timestamp>/`:
- `runner.log`: the full runner output;
- the suite's exported plan zips, with HTML and JSON logs;
- `zeroauthy.log` and `suite-server.log`.

`run.sh` ends with one summary line per plan: modules passed, failed, warning, review and skipped. Its exit status is `run-test-plan.py`'s. The runner exits non-zero when:
- a module did not finish;
- there is an unexpected failure, warning or skip;
- an expected failure or skip did not happen, or an entry matched no module at all.

So stale entries in the expected files already fail the run, and the harness has no check of its own for them. This was verified by adding a deliberately stale entry. Review-status modules do not fail the run.

## Expected failures and skips

The format is the suite's own (see its `.gitlab-ci/expected-failures-*.json`). `configuration-filename` is matched against the full path given to the runner, so use a glob such as `"*config.json"`. Start from the template that `--verbose` (always on) prints for unexpected failures. Add a `comment` that points at the decision behind the entry.
