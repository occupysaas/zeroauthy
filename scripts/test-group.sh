#!/usr/bin/env bash
# scripts/test-group.sh: run the Go tests of one area of zeroauthy.
#
# CI runs one job per group (and per store shard) under the race detector;
# the job list comes from --json, so every group here is tested there. Use it
# locally to run the area you are working on:
#
#   scripts/test-group.sh --list                  groups and their packages
#   scripts/test-group.sh protocol                one group
#   scripts/test-group.sh store-sqlite:2 -race    one shard, extra go test flags
#
# Groups are package lists. "rest" is every package no other group names, so
# a new package is always tested. A package named by two groups, or a pattern
# that matches nothing, is an error.
#
# The two store groups are split further. Shards 1-3 run the shared
# pkg/storetest conformance suite (TestConformance*) by area through
# ZA_STORETEST_AREAS / ZA_STORETEST_SKIP_AREAS; shard 3 skips the areas of
# shards 1 and 2, so it also picks up any area added later. Shard "other"
# runs the package's remaining tests. The group name alone runs everything.
set -euo pipefail
cd "$(dirname "$0")/.."

order=(protocol mgmt tenant-code store-sqlite store-grpc rest)
declare -A patterns=(
  [protocol]="internal/oauth/... internal/oidc/... internal/authz/... internal/login/... internal/loginid/... internal/hostedlogin/... internal/webauthn/... internal/webauthnrules/..."
  [mgmt]="internal/mgmt/... internal/server/... internal/app/... internal/seed/... api/..."
  [tenant-code]="internal/actions/... internal/actionsrules/... internal/noderunner/... internal/customdb/... internal/dbconn/... internal/federation/..."
  [store-sqlite]="internal/store/sqlstore/..."
  [store-grpc]="internal/store/grpcstore/..."
)
sharded=(store-sqlite store-grpc)
shards=(1 2 3 other)
shard1_areas=identity,orgs
shard2_areas=oauth,tenancy
conformance_tests='^(TestConformance|TestConformanceSQLite)$'

die() { echo "test-group.sh: $*" >&2; exit 2; }

module="$(go list -m)"
mapfile -t all < <(go list ./...)
declare -A owner=()
declare -A members=()

for g in "${order[@]}"; do
  [ "$g" = rest ] && continue
  for p in ${patterns[$g]}; do
    base="$module/${p%/...}"
    hit=0
    for pkg in "${all[@]}"; do
      if [ "$pkg" = "$base" ] || { [ "$p" != "${p%/...}" ] && [[ "$pkg" == "$base"/* ]]; }; then
        hit=1
        if [ -n "${owner[$pkg]:-}" ] && [ "${owner[$pkg]}" != "$g" ]; then
          die "$pkg is in groups ${owner[$pkg]} and $g"
        fi
        owner[$pkg]=$g
      fi
    done
    [ "$hit" = 1 ] || die "group $g: pattern $p matches no package"
  done
done
for pkg in "${all[@]}"; do
  g="${owner[$pkg]:-rest}"
  members[$g]+="$pkg "
done

# jobs prints the CI job names: plain groups and the store shards.
jobs() {
  for g in "${order[@]}"; do
    if [[ " ${sharded[*]} " == *" $g "* ]]; then
      for s in "${shards[@]}"; do echo "$g:$s"; done
    else
      echo "$g"
    fi
  done
}

case "${1:-}" in
  "" | -h | --help)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  --list)
    for g in "${order[@]}"; do
      echo "$g:"
      for pkg in ${members[$g]:-}; do echo "  ${pkg#"$module"/}"; done
    done
    exit 0 ;;
  --jobs)
    jobs
    exit 0 ;;
  --json)
    jobs | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))'
    exit 0 ;;
esac

job="$1"; shift
group="${job%%:*}"
shard=""
[ "$job" != "$group" ] && shard="${job#*:}"
[ -n "${members[$group]+x}" ] || die "unknown group $group (try --list)"
# shellcheck disable=SC2206 # package paths have no spaces
pkgs=(${members[$group]})

if [ -z "$shard" ]; then
  exec go test "$@" "${pkgs[@]}"
fi
[[ " ${sharded[*]} " == *" $group "* ]] || die "group $group has no shards"
case "$shard" in
  1) ZA_STORETEST_AREAS="$shard1_areas" exec go test "$@" -run "$conformance_tests" "${pkgs[@]}" ;;
  2) ZA_STORETEST_AREAS="$shard2_areas" exec go test "$@" -run "$conformance_tests" "${pkgs[@]}" ;;
  3) ZA_STORETEST_SKIP_AREAS="$shard1_areas,$shard2_areas" exec go test "$@" -run "$conformance_tests" "${pkgs[@]}" ;;
  other) exec go test "$@" -skip "$conformance_tests" "${pkgs[@]}" ;;
  *) die "unknown shard $shard (shards: ${shards[*]})" ;;
esac
