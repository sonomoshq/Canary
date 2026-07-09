#!/usr/bin/env bash
# test-corpus.sh — Score the regex detector engine against the labeled
# benchmark (tests/corpus.json) via tests/score.py, and enforce the
# recall / false-positive baseline recorded in tests/baseline.json.
# Usage: bash tests/test-corpus.sh
# Exit code 0 = passed (or skipped, see below), 1 = failed baseline.
#
# If python3 isn't available, this suite skips cleanly (exit 0) rather
# than failing — score.py is the only thing here that needs it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 not available — skipping corpus benchmark (tests/test-corpus.sh)"
  exit 0
fi

PASS=0
FAIL=0

SCORE_OUTPUT=$(python3 "$SCRIPT_DIR/tests/score.py")
echo "$SCORE_OUTPUT"

RECALL=$(echo "$SCORE_OUTPUT" | grep '^RECALL=' | cut -d= -f2)
VIOLATIONS=$(echo "$SCORE_OUTPUT" | grep '^PRESERVE_VIOLATIONS=' | cut -d= -f2)

if [[ -z "$RECALL" || -z "$VIOLATIONS" ]]; then
  echo "  FAIL: could not parse RECALL/PRESERVE_VIOLATIONS from score.py output"
  exit 1
fi

# Read the baseline (recall_min, max_preserve_violations) in one python3
# call — bash has no JSON parser and no float arithmetic of its own.
read -r RECALL_MIN MAX_VIOLATIONS <<< "$(python3 -c "
import json
b = json.load(open('$SCRIPT_DIR/tests/baseline.json'))
print(b['recall_min'], b['max_preserve_violations'])
")"

echo ""
echo "=== Baseline Comparison ==="

if python3 -c "exit(0 if float('$RECALL') >= float('$RECALL_MIN') else 1)"; then
  PASS=$((PASS + 1))
  echo "  PASS: recall $RECALL >= baseline recall_min $RECALL_MIN"
else
  FAIL=$((FAIL + 1))
  echo "  FAIL: recall $RECALL is below baseline recall_min $RECALL_MIN"
fi

if [[ "$VIOLATIONS" -le "$MAX_VIOLATIONS" ]]; then
  PASS=$((PASS + 1))
  echo "  PASS: preserve violations $VIOLATIONS <= baseline max_preserve_violations $MAX_VIOLATIONS"
else
  FAIL=$((FAIL + 1))
  echo "  FAIL: preserve violations $VIOLATIONS exceeds baseline max_preserve_violations $MAX_VIOLATIONS"
fi

echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
