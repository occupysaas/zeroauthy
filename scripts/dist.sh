#!/usr/bin/env bash
# scripts/dist.sh VERSION [OUTDIR]: build reproducible release archives.
#
# Produces zeroauthy_<version>_<os>_<arch>.tar.gz for each supported
# platform plus SHA256SUMS. The binaries are static (CGO_ENABLED=0), built
# with -trimpath and an empty build ID, and the archives use fixed ownership,
# ordering and timestamps, so the same commit and Go toolchain give the same
# bytes. The timestamp is the commit time (SOURCE_DATE_EPOCH overrides it).
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:?usage: scripts/dist.sh VERSION [OUTDIR]}"
out="${2:-dist}"
version="${version#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "dist.sh: version must be semver (got $version)" >&2; exit 1; }
platforms=(linux/amd64 linux/arm64 darwin/arm64)

epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH="$epoch"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for p in "${platforms[@]}"; do
  os="${p%/*}" arch="${p#*/}"
  name="zeroauthy_${version}_${os}_${arch}"
  dir="$work/$name"
  mkdir -p "$dir"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.version=$version" \
    -o "$dir/zeroauthy" ./cmd/zeroauthy
  cp LICENSE NOTICE README.md CHANGELOG.md "$dir/"
  find "$dir" -exec touch -h -d "@$epoch" {} +
  chmod 0755 "$dir/zeroauthy"
  chmod 0644 "$dir"/LICENSE "$dir"/NOTICE "$dir"/README.md "$dir"/CHANGELOG.md
  tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
    --mtime="@$epoch" -C "$work" -cf - "$name" | gzip -9n > "$out/$name.tar.gz"
done

(cd "$out" && sha256sum zeroauthy_"${version}"_*.tar.gz > SHA256SUMS)
cat "$out/SHA256SUMS"
