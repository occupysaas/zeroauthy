#!/usr/bin/env bash
# Usage: scripts/check-dco.sh <base> <head>
# Fails if any non-merge commit in base..head lacks a Signed-off-by line
# naming the commit author's email (Developer Certificate of Origin 1.1).
set -euo pipefail

base=${1:?usage: check-dco.sh <base> <head>}
head=${2:?usage: check-dco.sh <base> <head>}

missing=0
checked=0
for c in $(git rev-list --no-merges "$base..$head"); do
	checked=$((checked + 1))
	email=$(git log -1 --format='%ae' "$c")
	trailers=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$c")
	if ! grep -qiF "<$email>" <<<"$trailers"; then
		echo "::error::commit $(git log -1 --format='%h %s' "$c") has no Signed-off-by for its author <$email>"
		missing=$((missing + 1))
	fi
done

if [ "$missing" -gt 0 ]; then
	echo
	echo "$missing of $checked commit(s) lack a matching Signed-off-by line."
	echo "Sign off with 'git commit -s'; to fix existing commits run"
	echo "'git rebase --signoff $base' and force-push the branch."
	echo "See CONTRIBUTING.md, \"Licence and sign-off (DCO)\"."
	exit 1
fi
echo "All $checked commit(s) are signed off."
