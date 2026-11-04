# Releasing zeroauthy

Releases are built and published by
[`.github/workflows/release.yml`](.github/workflows/release.yml). It runs only
on pushes to the `release` branch (or a `release/X.Y` patch line), never on
`main`. Merging to `main` runs only CI.

## What a release publishes

- `zeroauthy_<version>_<os>_<arch>.tar.gz` for linux/amd64, linux/arm64 and
  darwin/arm64, plus `SHA256SUMS`, on the GitHub release. Each archive holds
  the static binary, `LICENSE`, `NOTICE`, `README.md` and `CHANGELOG.md`.
- A multi-arch (amd64, arm64) image at `ghcr.io/occupysaas/zeroauthy`, tagged
  `<version>` and `<major>.<minor>`; `latest` only for non-prerelease
  versions.
- Build provenance attestations for the archives and the image
  (`gh attestation verify <file> --repo occupysaas/zeroauthy`).

Prereleases (`-rc.N`, `-beta.N`) are marked as prereleases and never move
`latest`.

## Gates

Before anything is published, the workflow runs the full CI workflow (Go race
suite, SQL drivers, console and the E2E lanes) and then the OpenID conformance
plans. A failed gate publishes nothing.

## Steps

1. On `main`, add the version's section to `CHANGELOG.md` (move the
   `Unreleased` entries under `## [X.Y.Z]` and update the links at the end),
   commit and push. Wait for CI on `main` to pass.
2. Tag that commit and push the tag. Pushing a tag alone starts nothing.

   ```sh
   git tag -a v1.0.0-rc.1 -m "zeroauthy v1.0.0-rc.1"
   git push origin v1.0.0-rc.1
   ```

3. Fast-forward `release` to the tagged commit and push it. This starts the
   release workflow.

   ```sh
   git push origin v1.0.0-rc.1^{commit}:refs/heads/release
   ```

   The workflow refuses a `release` commit that is not on `main`, a tag that is
   not semver, or a version with no `CHANGELOG.md` section.
4. Watch the run under the repository's Actions tab. When it finishes, check
   the release page, the image tags and the checksums.

A push to `release` without a `v*` tag on its commit runs every gate and
builds every artefact without publishing anything. Use it as a dry run.

### Patch releases

For a fix to an older line, branch `release/X.Y` from that line's last tag,
cherry-pick the fix, update `CHANGELOG.md`, tag `vX.Y.Z` and push the tag and
then the branch.

## Building locally

`scripts/dist.sh 1.0.0-rc.1` builds the same archives into `dist/`. With the
same commit and Go toolchain the output is byte-identical (the timestamp is the
commit time). `docker build --build-arg VERSION=1.0.0-rc.1 -t zeroauthy .`
builds the image.
