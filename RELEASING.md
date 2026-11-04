# Releasing zeroauthy

Nothing is released automatically. Merging to `main` only runs CI. A release
happens when a maintainer deliberately pushes a tagged commit to the `release`
branch **and** then approves the `production` environment in GitHub Actions.

- [Short method](#short-method): the checklist, for when you have done this before.
- [Long method](#long-method): every step explained, including checks and
  what to do when something fails.

Versions follow [Semantic Versioning](https://semver.org/): `1.2.3` for a
release, `1.2.3-rc.1` (or `-beta.N`) for a prerelease. Tags are the version
with a `v` prefix: `v1.2.3`.

## Short method

```sh
V=1.0.0-rc.1                      # the version you are releasing

# 1. On main: move CHANGELOG "Unreleased" entries under "## [$V]", fix the
#    links at the bottom, then commit, push, and wait for CI to pass.
git switch main && git pull
$EDITOR CHANGELOG.md
git commit -am "docs: changelog for $V" && git push

# 2. Tag the commit and push the tag (this alone starts nothing).
git tag -a "v$V" -m "zeroauthy v$V"
git push origin "v$V"

# 3. Point the release branch at the tag (this starts the release workflow).
git push origin "v$V^{commit}:refs/heads/release"
```

4. Open the **release** run in the repository's **Actions** tab. When the gates
   are green it pauses at **approve**: click **Review deployments**, tick
   `production`, **Approve and deploy**.
5. When the run is green, check the [Releases](https://github.com/occupysaas/zeroauthy/releases)
   page and pull `ghcr.io/occupysaas/zeroauthy:$V`.

## Long method

### What a release publishes

- `zeroauthy_<version>_<os>_<arch>.tar.gz` for linux/amd64, linux/arm64 and
  darwin/arm64, plus `SHA256SUMS`, attached to a GitHub release. Each archive
  holds the static binary, `LICENSE`, `NOTICE`, `README.md` and
  `CHANGELOG.md`.
- A multi-arch (amd64, arm64) image at `ghcr.io/occupysaas/zeroauthy`, tagged
  `<version>`, plus `<major>.<minor>` and `latest` for non-prerelease
  versions only.
- Release notes: the version's `CHANGELOG.md` section, followed by the
  "Run it with Docker" section from [`.github/release-docker.md`](.github/release-docker.md)
  (image, essential environment variables, links to the configuration
  reference and testing guide).
- Build provenance attestations for the archives and the image.

Prereleases are marked as prereleases on GitHub and never move `latest`.

### One-time setup

1. **Production environment.** In the repository's **Settings → Environments**,
   create an environment named `production`. Under **Deployment protection
   rules**, enable **Required reviewers** and add the maintainers allowed to
   approve releases. Optionally restrict **Deployment branches** to
   `release` and `release/**`. Without this environment the `approve` job
   fails, so nothing can be published by accident.
2. **Package visibility.** After the first release, open the `zeroauthy`
   package under the organisation's **Packages** and set it to public so
   people can pull the image without logging in.
3. **Branch protection (recommended).** Protect `release` and `release/**`:
   allow pushes only by maintainers, and disallow force pushes and deletion.

### Step 1: prepare the changelog on `main`

1. `git switch main && git pull`.
2. In `CHANGELOG.md`, move the entries under `## [Unreleased]` to a new
   `## [X.Y.Z]` section below it (keep `Unreleased` empty), and update the
   links at the bottom:

   ```md
   [Unreleased]: https://github.com/occupysaas/zeroauthy/compare/vX.Y.Z...HEAD
   [X.Y.Z]: https://github.com/occupysaas/zeroauthy/releases/tag/vX.Y.Z
   ```

   The section becomes the release notes, so write it for users: what's new,
   what changed, upgrade notes, known limitations.
3. Commit (`docs: changelog for X.Y.Z`), push, and wait for **CI** on `main`
   to pass. Do not tag a commit whose CI is red: the release workflow runs
   the same checks and will stop.

### Step 2: tag

```sh
git tag -a vX.Y.Z -m "zeroauthy vX.Y.Z"
git push origin vX.Y.Z
```

Pushing a tag does not start a release. The tag only names the commit; you
can still delete it (`git push origin :refs/tags/vX.Y.Z`) before step 3.

### Step 3: push the release branch

```sh
git push origin vX.Y.Z^{commit}:refs/heads/release
```

This fast-forwards `release` to the tagged commit and starts the **release**
workflow. Before doing any work it checks that:

- the commit carries a `v*` tag that is valid semver;
- `CHANGELOG.md` has a `## [X.Y.Z]` section;
- for `release`, the commit is on `main` (a release is always a fast-forward
  of `main`).

If the push is rejected as non-fast-forward, `release` has a commit that is
not on `main`; investigate instead of forcing.

### Step 4: gates, then approval

The workflow runs, in order:

1. **test**: the full CI workflow: gofmt, vet, the Go race suite,
   `govulncheck`, the console checks, the SQL drivers and the E2E lanes.
2. **conformance**: the OpenID conformance plans.
3. **binaries**: the reproducible archives and `SHA256SUMS`.
4. **approve**: pauses for a required reviewer of the `production`
   environment. Open the run, click **Review deployments**, tick
   `production` and **Approve and deploy**. Reject it to stop the release;
   nothing has been published at this point.
5. **image**: builds and pushes the multi-arch image, with provenance and SBOM.
6. **publish**: verifies the checksums, attests the archives, and creates the
   GitHub release with the notes.

A failure in any gate stops the run before anything is published.

### Step 5: check the result

- The release page shows the notes, three archives and `SHA256SUMS`, marked
  as prerelease for `-rc`/`-beta` versions.
- `docker pull ghcr.io/occupysaas/zeroauthy:X.Y.Z` works and
  `docker run --rm ghcr.io/occupysaas/zeroauthy:X.Y.Z version` prints the version.
- Downloads verify: `sha256sum -c SHA256SUMS` and
  `gh attestation verify <archive> --repo occupysaas/zeroauthy`.

### Promoting a release candidate

When `X.Y.Z-rc.N` has been tried and is good, release `X.Y.Z` from the same
commit or a later one: add a `## [X.Y.Z]` changelog section (it can say
"Same as rc.N" plus any fixes), then repeat steps 2–5 with the final version.
Only a non-prerelease version moves `latest`.

### Dry run

Pushing an untagged commit to `release` (for example
`git push origin main:release` before tagging) runs every gate and builds
every artefact without publishing or asking for approval. Use it to rehearse
a release. The `release` branch then sits on that commit, and the real
release in step 3 fast-forwards it.

### Patch releases for an older line

To fix `1.0.x` after `main` has moved on to `1.1` work:

```sh
git switch -c release/1.0 v1.0.0       # once per line, from its last tag
git cherry-pick <fix-commit>
$EDITOR CHANGELOG.md                   # add ## [1.0.1]
git commit -am "docs: changelog for 1.0.1"
git tag -a v1.0.1 -m "zeroauthy v1.0.1"
git push origin v1.0.1 release/1.0
```

`release/**` branches skip the "on `main`" check; the other checks and the
approval still apply. Also add the fix and its changelog entry to `main`.

### When something goes wrong

- **A gate fails before approval:** nothing is published. Fix on `main`,
  delete the tag (`git push origin :refs/tags/vX.Y.Z` and `git tag -d vX.Y.Z`),
  and start again from step 1. Never move a published tag.
- **Approval was rejected:** nothing is published. Same as above, or rerun
  the workflow from the Actions tab once ready.
- **Published, but broken:** do not delete or retag. Mark the GitHub release
  as a prerelease or edit its notes with a warning, and ship `X.Y.Z+1`
  (or the next `-rc.N`) with the fix.

### Building locally

`scripts/dist.sh X.Y.Z` builds the same archives into `dist/`. With the same
commit and Go toolchain the output is byte-identical (the timestamp is the
commit time). `docker build --build-arg VERSION=X.Y.Z -t zeroauthy .` builds
the image.
