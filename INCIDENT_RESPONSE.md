# Incident response plan

What the maintainers do when something goes wrong with zeroauthy's
security: a vulnerability report, a tampered release, a compromised
maintainer account, a leaked token, a hijacked workflow or a malicious
dependency. [SECURITY.md](SECURITY.md) tells reporters how to reach us and
what to expect; this file is for the people handling the incident.

Keep incident details (unfixed vulnerabilities, logs, affected
deployments) in the private security advisory, never in this public file.

Last reviewed: 2026-11-15

## Roles

- **Incident lead:** TODO(maintainer): name the maintainer who leads, and
  how to reach them outside GitHub.
- **Backup:** TODO(maintainer): name a second person with admin access to
  `occupysaas/zeroauthy` and the `occupysaas` organization, who acts when
  the lead can't.

The lead sets the severity, coordinates the fix and the release, and
publishes the advisory. They can hand any step to someone else but stay
responsible for it. Reports arrive through GitHub private vulnerability
reporting (**Security** tab, **Report a vulnerability**) or the email
address in SECURITY.md; whoever sees a report first makes sure the lead
has it.

## Severity

| Severity | Examples | What it triggers |
| --- | --- | --- |
| Critical | Active exploitation; a tampered release archive or container image; a compromised maintainer account or release workflow | Start the matching playbook below at once, with every maintainer available |
| High | An exploitable vulnerability with no known exploitation: authentication bypass, token forgery, broken tenant isolation, escaping the isolation documented for Actions and custom-database scripts | Fix in a temporary private fork and release within the SECURITY.md target |
| Medium / Low | Hard to exploit, limited impact, or only in a configuration that SECURITY.md lists as out of scope | Fix in a normal release; publish an advisory when users need to act |

Score vulnerabilities with CVSS in the advisory form.

## Vulnerability reports

1. **Acknowledge** the report (SECURITY.md target: 3 working days).
   A private vulnerability report is already a draft advisory. For an
   emailed report, create one (**Security → Advisories → New draft security
   advisory**) and add the reporter if they have a GitHub account.
2. **Assess** (target: 10 working days): reproduce on the latest release
   and on `main`, set the severity and the affected versions (SECURITY.md
   lists the supported ones), and tell the reporter.
3. **Fix** in the advisory's temporary private fork (**Start a temporary
   private fork**), with a regression test. CI and status checks don't run
   in a temporary private fork, and branch rules aren't enforced when you
   merge from the advisory, so run the checks yourself before merging:
   `go test -race ./...`, `make test-sql`, the affected `make e2e-*`
   suites, `make console` for console changes, and
   `scripts/check-dco.sh` for sign-offs.
4. **Request a CVE** from the advisory (GitHub is a CVE numbering
   authority).
5. **Merge and release.** Merge from the advisory, then release by
   [RELEASING.md](RELEASING.md) (on a `release/**` line for an older
   version). The release workflow runs every gate again before the
   `production` approval.
6. **Publish the advisory** once the release is out, with the fixed
   version, any workaround and credit for the reporter (unless they
   decline), and mention it in the release's CHANGELOG section.
   TODO(maintainer): decide which package advisories name. Users run the
   release archives and the GHCR image; `go.mod` names the module
   `github.com/zeroauthy/zeroauthy`, which isn't this repository's path.
7. **Notify** the downstream projects and deployments listed under
   Contacts.
8. **Review** within two weeks: a short write-up of what happened, the
   timeline and what changes.

## Playbooks for incidents that aren't bug reports

### Compromised maintainer account

1. From a clean device: change the password, sign out other sessions,
   revoke personal access tokens, SSH keys and authorized OAuth and GitHub
   Apps, and re-enroll two-factor authentication. If you can't get in,
   contact GitHub Support.
2. An organization owner removes or reduces the account's access to
   `occupysaas` until it is secured.
3. Find out what the account did, from its security log and the
   organization audit log: pushes to `main`, `release`, `release/**` and
   tags; changes under `.github/`; changes to rulesets, environments
   (including the `production` reviewers), Actions settings, secrets,
   webhooks, deploy keys and collaborators; new releases and image
   versions.
4. Treat anything the account published as suspect: if a release or
   image might be affected, follow "Tampered release".

### Leaked token or secret

- The workflows use only the job's `GITHUB_TOKEN`, which expires when
  the job ends; no repository or organization secrets are referenced. If
  one appears in a log, delete the log and check what that job's
  `permissions:` allowed.
- A maintainer's personal token or SSH key: revoke it, then check the
  account as in "Compromised maintainer account".
- Rotate first, then close any secret scanning alert in the **Security**
  tab.
- When the project adds secrets (repository, organization or outside
  GitHub), list each one here with how to rotate it.

### Tampered release

Signs: an archive or image that doesn't match `SHA256SUMS` or its
provenance (`gh attestation verify <archive> --repo occupysaas/zeroauthy`;
for the image, `gh attestation verify oci://ghcr.io/occupysaas/zeroauthy:<version> --repo occupysaas/zeroauthy`),
a release or image version that nobody approved, or a report of unexpected
behaviour from a downloaded build.

1. **Contain:** cancel running release workflows and reject pending
   `production` approvals. Record the digests and checksums, then take the
   artifacts down: delete the image version from the organization's
   `zeroauthy` package and remove the release assets, or mark the release
   with a warning while you investigate.
2. **Investigate:** the provenance attestation names the workflow run that
   built the artifact. Check that run's commit, logs and action versions.
   If our release workflow built it, also follow "Hijacked workflow".
3. **Recover:** release a new version from a verified commit. Never reuse
   a version number or move a published tag (RELEASING.md). Publish an
   advisory naming the affected versions, digests and checksums and what
   users must do.

### Hijacked workflow

Signs: unexpected workflow runs or changes under `.github/`, a release
built from a commit that isn't on `main`, unexpected artifacts or caches,
or an advisory for an action we use.

1. Disable the workflow (`gh workflow disable <workflow> -R occupysaas/zeroauthy`)
   and cancel its runs.
2. Delete the Actions caches (`gh cache delete --all -R occupysaas/zeroauthy`);
   release runs don't use caches, but the other workflows do.
3. Review the history of `.github/` and the runs' logs, compare the
   pinned action SHAs with the upstream advisory, and revert to a
   known-good commit.
4. If the release workflow was affected, follow "Tampered release".

### Malicious or vulnerable dependency

- **Go:** `go.sum` pins module hashes and govulncheck runs in CI. Find
  which commits and releases include the bad version.
- **npm:** the console's build output, `console/dist`, is committed and
  embedded in the binary, so a malicious package that ran during a console
  build could have changed it. Review `console/dist` diffs since the bad
  version arrived.
- **Container images:** the Dockerfile's `golang` and `node` base images
  are referenced by tag.
- Downgrade or replace the dependency, release, and publish an advisory
  if released builds were affected.

## Contacts

- GitHub Support (account recovery, abuse, GHCR): https://support.github.com
- GitHub security: https://github.com/contact
- Registries: releases go only to GitHub Releases and GHCR
  (RELEASING.md), so GitHub Support covers both.
- Downstream projects and deployments to notify: TODO(maintainer).

Check these contacts whenever maintainers change.

## Practice

TODO(maintainer): run a one-hour drill once a year, such as a leaked
token or a tampered image, and record the date here.
