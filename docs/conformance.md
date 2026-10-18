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

Port 8443 on 127.0.0.1 is shared with the browser E2E suite, so never run the two at once; `run.sh` reports a listener already there. `run.sh` passes through `run-test-plan.py`'s exit status; 0 means every module finished and nothing unexpected happened.

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

Spec-compliant behaviour is the default. Where the maintainer rules that Auth0's behaviour must stay available, it goes behind a server-wide environment variable `ZEROAUTHY_COMPAT__NONCOMPLIANT_<BEHAVIOUR>` (default off; a startup warning naming each switch that is on is planned, since no switches exist yet; the conformance run uses the defaults). Each case is decided by the maintainer.

| Switch | Auth0 behaviour it restores | Decision |
|---|---|---|
| (none) | | |

No such switch exists today.

## Certification

Steps 2 to 6 need the maintainer's hands (deploying, holding the OIDF account, signing, emailing). Claude prepares the files and checks each step from outside. Nothing secret is committed.

| Fact | Value |
|---|---|
| Hosted suite | https://www.certification.openid.net/ (log in with Google or GitLab) |
| Hosted suite version | `release-v5.3.3` (revision 7d420f7), pinned in `tests/conformance/suite-version` |
| Public host and issuer | `auth.turbojobapply.com`, issuer `https://auth.turbojobapply.com/` |
| Suite alias | `zeroauthy` (a parameter of `make-seed.sh`; change it if the hosted suite reports it in use) |
| Callback | `https://www.certification.openid.net/test/a/<alias>/callback` |
| Post-logout redirect | `https://www.certification.openid.net/test/a/<alias>/post_logout_redirect` (`CreatePostLogoutRedirectUri.java` at the tag) |
| Clients | `za-cert-1`, `za-cert-2` (`client_secret_basic`), `za-cert-post` (`client_secret_post`) |
| Result rule | Every module FINISHED. PASSED, REVIEW, WARNING and SKIPPED are acceptable; FAILED or INTERRUPTED blocks submission. |

OIDF publishes the submitted logs (https://openid.net/certification/op_submission/), so every secret in the public run is throwaway: client secrets, the user's password, the master key and the signing key exist only for this run.

### 1. Local pass

All four plans exit 0 locally on the hosted suite's version, with the approved expected lists. Last local pass: 2026-10-17, `release-v5.3.3`: Basic and Form Post 21 passed, 6 warning, 4 review, 4 skipped each; Config 1 passed; RP-initiated logout 3 passed, 8 review; no failures.

### 2. The kit

The templates live in `tests/conformance/public/`:
- `seed.yaml.tmpl`: the `certification` tenant on the public host, the three clients with the hosted callbacks and logout URLs, and the test user `conformance@example.com` (name, given and family name set);
- `configs/{basic,config,formpost,logout}.json.tmpl`: the local configs with the public discovery URL, the alias, the `za-cert-*` clients and browser steps matching `https://<host>/authorize*` and `https://<host>/oidc/logout*`;
- `make-seed.sh HOST ALIAS OUTDIR`: fills in the host and alias, generates fresh secrets and a fresh password with `openssl rand`, and writes `seed.yaml`, `configs/*.json` and `secrets.txt` (mode 600) to OUTDIR. It refuses an OUTDIR inside the repository and will not overwrite an existing kit.

```bash
./tests/conformance/public/make-seed.sh auth.turbojobapply.com zeroauthy ~/zeroauthy-cert-kit
```

`internal/seed` tests render the seed template and apply it, so it keeps passing seed validation.

### 3. Deployment (DigitalOcean Ubuntu droplet)

The simplest setup is Caddy in front for automatic Let's Encrypt certificates, with zeroauthy on plain HTTP on the loopback interface.

**Build and copy** (on the maintainer's machine, from the commit being certified):

```bash
make build                       # CGO_ENABLED=0: bin/zeroauthy is static
openssl rand -base64 32 > ~/zeroauthy-cert-kit/master.key
scp bin/zeroauthy root@<droplet-ip>:/usr/local/bin/zeroauthy
scp ~/zeroauthy-cert-kit/seed.yaml ~/zeroauthy-cert-kit/master.key root@<droplet-ip>:/root/
```

**DNS:** an `A` record for `auth.turbojobapply.com` pointing at the droplet's IPv4 address (and `AAAA` only if the droplet has IPv6 enabled). Wait until `dig +short auth.turbojobapply.com` returns the droplet IP before starting Caddy, so the ACME challenge succeeds.

**On the droplet** (as root):

```bash
useradd --system --home /var/lib/zeroauthy --shell /usr/sbin/nologin zeroauthy
install -d -o root -g zeroauthy -m 750 /etc/zeroauthy
install -o root -g zeroauthy -m 640 /root/seed.yaml /etc/zeroauthy/seed.yaml
install -o root -g zeroauthy -m 640 /root/master.key /etc/zeroauthy/master.key
shred -u /root/seed.yaml /root/master.key
chmod 755 /usr/local/bin/zeroauthy
```

`/etc/zeroauthy/config.yaml`:

```yaml
server:
  listen: "127.0.0.1:8080"     # loopback only: Caddy is the only client
  trust_proxy_headers: true    # Caddy sets X-Forwarded-Host and X-Forwarded-For
storage:
  dsn: sqlite:///var/lib/zeroauthy/zeroauthy.db
  auto_migrate: true
security:
  master_key_file: /etc/zeroauthy/master.key
seed: /etc/zeroauthy/seed.yaml
log:
  level: info
  format: json
```

**Issuer behind the proxy.** zeroauthy always builds the issuer as `https://` + the request host + `/` (`internal/tenant/context.go`); it does not look at the scheme of the incoming connection or at `X-Forwarded-Proto`. The host is the `Host` header, or the first `X-Forwarded-Host` entry when `server.trust_proxy_headers` is true (`internal/tenant/resolver.go`), normalized to lower case with a `:443` port removed (`internal/tenant/host.go`). The tenant is the one whose `domains` contains that host, so the seed lists `auth.turbojobapply.com` without a port. Caddy passes the original `Host` through unchanged and sets `X-Forwarded-Host` to it, so either setting gives `https://auth.turbojobapply.com/`. Use `trust_proxy_headers: true` anyway: the same switch makes the login throttles use the client address from `X-Forwarded-For` (its rightmost entry, which Caddy writes) instead of 127.0.0.1 for everyone. Turn it on only while zeroauthy listens on the loopback interface, so nobody can reach it without going through Caddy.

`/etc/systemd/system/zeroauthy.service`:

```ini
[Unit]
Description=zeroauthy (OpenID certification run)
After=network-online.target
Wants=network-online.target

[Service]
User=zeroauthy
Group=zeroauthy
ExecStart=/usr/local/bin/zeroauthy serve --config /etc/zeroauthy/config.yaml
Restart=on-failure
StateDirectory=zeroauthy
StateDirectoryMode=0700
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now zeroauthy
journalctl -u zeroauthy -n 20          # expect "listening" with addr 127.0.0.1:8080
```

**Caddy** (Ubuntu 24.04 ships it in `universe`; otherwise use Caddy's apt repository):

```bash
apt update && apt install -y caddy
cat > /etc/caddy/Caddyfile <<'EOF'
auth.turbojobapply.com {
	reverse_proxy 127.0.0.1:8080
}
EOF
systemctl reload caddy
```

**Firewall:** allow 22 (SSH), 80 (Let's Encrypt HTTP-01 challenge and Caddy's redirect to HTTPS) and 443; nothing else. With `ufw`: `ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable`. A DigitalOcean cloud firewall with the same inbound rules works too.

**Alternative without Caddy:** obtain a certificate (for example `certbot certonly --standalone -d auth.turbojobapply.com`, which needs port 80 open during issuance), set `server.listen: ":443"`, `server.tls_cert_file` and `server.tls_key_file`, leave `trust_proxy_headers` false, and add `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the unit. The `zeroauthy` user must be able to read the key, and zeroauthy has to be restarted after each renewal. Caddy avoids both.

**Verify from outside** (the maintainer's machine, not the droplet):

```bash
curl -s https://auth.turbojobapply.com/.well-known/openid-configuration | jq -r .issuer
# https://auth.turbojobapply.com/
curl -s https://auth.turbojobapply.com/.well-known/openid-configuration \
  | jq -r '.authorization_endpoint, .token_endpoint, .jwks_uri, .end_session_endpoint'
# every URL starts with https://auth.turbojobapply.com/ and has no port
curl -s -o /dev/null -w '%{http_code}\n' "$(curl -s https://auth.turbojobapply.com/.well-known/openid-configuration | jq -r .jwks_uri)"
# 200
```

### 4. Hosted run

On https://www.certification.openid.net/ (logged in as the maintainer), for each plan:

1. **Create a new test plan** and pick the plan and variants. They are the ones `run.sh` uses (see the variant table in `tests/conformance/README.md`):

   | Plan | Variants to select | Config to paste |
   |---|---|---|
   | `oidcc-basic-certification-test-plan` (Basic OP) | server metadata `discovery`, client registration `static_client` | `configs/basic.json` |
   | `oidcc-config-certification-test-plan` (Config OP) | none | `configs/config.json` |
   | `oidcc-formpost-basic-certification-test-plan` (Form Post OP) | server metadata `discovery`, client registration `static_client` | `configs/formpost.json` |
   | `oidcc-rp-initiated-logout-certification-test-plan` (RP-Initiated OP) | response type `code`, client registration `static_client` | `configs/logout.json` |

2. Paste the rendered config from the kit into the JSON tab, replacing the form contents, and create the plan. The `alias` in the config must match the seed's callbacks; if the suite reports the alias as in use, rerun `make-seed.sh` with another alias into a new OUTDIR, redeploy the seed (`systemctl restart zeroauthy` applies it) and start again.
3. Run every module. The browser steps in the config log in, consent and log out without help.
4. **REVIEW modules.** The config's `override` steps upload the page as the module's screenshot (the redirect URI error pages, the second login page of `oidcc-prompt-login` and `oidcc-max-age-1`, and the logout error and logged-out pages). Open each REVIEW module and check that its image is attached and shows the expected page; for any placeholder still empty, take a screenshot of the page in the log and upload it there.
5. Done when every module is FINISHED with no FAILED or INTERRUPTED result. A failure goes back through triage locally (expected-failures process above) before the plan is rerun.

Plan IDs: Basic TBD, Config TBD, Form Post TBD, RP-Initiated TBD. Run date: TBD.

### 5. Packages and submission

1. Before publishing, search each plan's exported logs for anything that is not throwaway (only the kit's generated secrets and test user may appear).
2. Publish each plan for certification from its plan page, and export its logs (the plan zip).
3. One package per profile: the exported logs and the signed "OpenID Certification of Conformance" (Claude drafts the field values, the maintainer signs), as described at https://openid.net/certification/op_submission/.
4. **Waiver.** The maintainer emails certification@oidf.org (draft by Claude) with the project URL and licence, the open-source policy URL (https://openid.net/certification/open-source-project-certification-policy/), the statement that zeroauthy's primary maintainers are not paid by an employer for the project, and the four profiles with their results.
5. Submit per https://openid.net/certification/instructions/ once OIDF answers.

Package status: TBD. Waiver email date: TBD. Submission date: TBD.

### 6. Teardown

1. `systemctl disable --now zeroauthy caddy`, then `rm -rf /var/lib/zeroauthy /etc/zeroauthy` (the database holds the clients, the user and the signing key).
2. Destroy the droplet and remove the `A` record.
3. Delete the local kit (`rm -rf ~/zeroauthy-cert-kit`). Reuse nothing from it.
4. Record below the date, the suite version and the zeroauthy commit that was certified.

Certified: date TBD, suite `release-v5.3.3`, zeroauthy commit TBD. Teardown date: TBD.
