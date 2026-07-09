#!/usr/bin/env bash
# test-redact.sh — Verify redaction function preserves first/last 2 chars.
# Usage: bash tests/test-redact.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DETECTORS="$SCRIPT_DIR/canary/scripts/detectors.sh"

PASS=0
FAIL=0

# Extract the redact function from detectors.sh and test it directly.
# redact() depends on the pre-built DOT_MASKS array (bug #10 fix — a
# lookup table instead of spawning seq/printf per hit), so that
# initialization block has to be sourced first too.
source <(sed -n '/^DOT_MASKS=/,/^unset _dm _i/p' "$DETECTORS")
source <(sed -n '/^redact()/,/^}/p' "$DETECTORS")

assert_redact() {
  local label="$1"
  local input="$2"
  local expected="$3"

  local result
  result=$(redact "$input")

  if [[ "$result" == "$expected" ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: $label → $result"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $label"
    echo "        expected: $expected"
    echo "        got:      $result"
  fi
}

echo "=== Redaction Tests ==="
assert_redact "Standard value" "4532015112830366" "45••••••••••••66"
assert_redact "Short value" "12345" "••••"
assert_redact "Email-length" "john@example.com" "jo••••••••••••om"
assert_redact "Six chars" "123456" "12••56"
assert_redact "SSN digits" "078051120" "07•••••20"

echo ""
echo "=== Cap and Truncation (bug #10) ==="
# 62-char value: mid = len-4 = 58, which is > 20, so the dot run is capped
# at 20 with a "…" marker — but the value itself is under the 64-char
# truncation threshold, so the true last 2 chars ("YZ") are preserved.
assert_redact "20-dot cap with ellipsis (62 chars, under truncation limit)" \
  "AB3456789012345678901234567890123456789012345678901234567890YZ" \
  "AB••••••••••••••••••••…YZ"
# 70-char value: over the 64-char truncation threshold, so it's truncated
# to the first 64 chars *before* redacting. The last 2 chars shown ("34")
# are chars 63-64 of the original — not the true last 2 chars ("YZ") —
# which is exactly what proves truncation happened, not just capping.
assert_redact "64-char truncation (70-char input)" \
  "AB345678901234567890123456789012345678901234567890123456789012345678YZ" \
  "AB••••••••••••••••••••…34"

echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
