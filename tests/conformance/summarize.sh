#!/usr/bin/env bash
# tests/conformance/summarize.sh RUNNER_LOG: one line per test plan with the
# number of modules per result, from run-test-plan.py's output.
set -euo pipefail
sed -E 's/\x1b\[[0-9;]*m//g; s/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8} //' "$1" | awk '
  /^Results for \[[0-9]+\] / { plan = $4; order[++n] = plan; next }
  plan != "" && /^Test \[[0-9]+:[0-9]+\] .* - result [A-Z_]+\./ {
    match($0, / - result [A-Z_]+\./)
    r = substr($0, RSTART + 10, RLENGTH - 11)
    count[plan, r]++; total[plan]++
  }
  END {
    if (n == 0) { print "  no plan results (see the runner output above)"; exit }
    for (i = 1; i <= n; i++) {
      p = order[i]
      printf "  %s: %d modules: %d passed, %d failed, %d warning, %d review, %d skipped", p, total[p],
        count[p, "PASSED"], count[p, "FAILED"], count[p, "WARNING"], count[p, "REVIEW"], count[p, "SKIPPED"]
      other = total[p] - count[p, "PASSED"] - count[p, "FAILED"] - count[p, "WARNING"] - count[p, "REVIEW"] - count[p, "SKIPPED"]
      if (other) printf ", %d other", other
      printf "\n"
    }
  }'
