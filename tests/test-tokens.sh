#!/usr/bin/env bash
# test-tokens.sh — Verify Canary Tokens (mint / plant / detect / trip).
# Usage: bash tests/test-tokens.sh
# Exit code 0 = all passed, 1 = failures
#
# Canary Tokens are fake-but-realistic decoys Canary mints itself, so a
# "trip" is a CERTAIN literal match (grep -F), not a probabilistic
# shape guess. These tests exercise the whole loop in an isolated
# $HOME/$SONOMOS_DIR so they never touch a real leaks.jsonl.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$SCRIPT_DIR/canary/scripts/canary-tokens.sh"
CLI="$SCRIPT_DIR/canary/bin/canary-token"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() {
  FAIL=$((FAIL + 1))
  echo "  FAIL: $1"
  [[ -n "${2:-}" ]] && echo "        $2"
}

# ── Isolated sandbox ────────────────────────────────────────────────
# Fresh temp HOME so $SONOMOS_DIR (=$HOME/.sonomos) is empty and private.
# CLAUDE_PLUGIN_DATA is unset so the code takes the $HOME/.sonomos path.
TEST_HOME="$(mktemp -d "${TMPDIR:-/tmp}/canary-tokens-test.XXXXXX")"
export HOME="$TEST_HOME"
unset CLAUDE_PLUGIN_DATA 2>/dev/null || true
SONOMOS_DIR="$HOME/.sonomos"
CANARIES_FILE="$SONOMOS_DIR/canaries.jsonl"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
WORKDIR="$TEST_HOME/work"
mkdir -p "$WORKDIR"

cleanup() { rm -rf "$TEST_HOME" 2>/dev/null || true; }
trap cleanup EXIT

# reset_state — wipe the sandbox's plugin dir between independent tests
# so registry/leaks counts start clean each block.
reset_state() {
  rm -rf "$SONOMOS_DIR" 2>/dev/null || true
  mkdir -p "$SONOMOS_DIR" 2>/dev/null || true
}

# jq is optional for the product; skip the JSON-shape asserts that need
# it but still run everything else.
HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# grep -F helper for "value present in file"
value_in_file() { grep -qF -- "$2" "$1" 2>/dev/null; }

# count canary_tripped lines in leaks.jsonl
count_trips() {
  [[ -f "$LEAKS_FILE" ]] || { echo 0; return; }
  grep -cF '"type":"canary_tripped"' "$LEAKS_FILE" 2>/dev/null || echo 0
}

# ════════════════════════════════════════════════════════════════════
echo "=== Mint: each type registers a canary line ==="
# ════════════════════════════════════════════════════════════════════
for t in aws card ssn env dburl; do
  reset_state
  val="$(bash "$CLI" new "$t" "test $t label" 2>/dev/null | awk -F': ' '/^  Value:/{print $2; exit}')"
  if [[ -f "$CANARIES_FILE" ]] && [[ "$(wc -l < "$CANARIES_FILE" | tr -d ' ')" == "1" ]]; then
    pass "mint $t registers exactly one registry line"
  else
    fail "mint $t registers exactly one registry line" "lines=$(wc -l < "$CANARIES_FILE" 2>/dev/null)"
  fi
  if grep -qF "\"type\":\"$t\"" "$CANARIES_FILE" 2>/dev/null; then
    pass "mint $t registry line carries type=$t"
  else
    fail "mint $t registry line carries type=$t"
  fi
  if [[ -n "$val" ]] && value_in_file "$CANARIES_FILE" "$val"; then
    pass "mint $t stores the minted value in the registry"
  else
    fail "mint $t stores the minted value in the registry" "value='$val'"
  fi
done

# freeform separately (value slot is the decoy string, not a label)
reset_state
ff_val="Project Nightjar $$"
bash "$CLI" new freeform "$ff_val" >/dev/null 2>&1 || true
if [[ -f "$CANARIES_FILE" ]] && grep -qF "\"type\":\"freeform\"" "$CANARIES_FILE" 2>/dev/null && value_in_file "$CANARIES_FILE" "$ff_val"; then
  pass "mint freeform registers the supplied decoy string"
else
  fail "mint freeform registers the supplied decoy string"
fi

# ════════════════════════════════════════════════════════════════════
echo ""
echo "=== Mint invariants (Luhn card, 900-999 SSN, not a placeholder) ==="
# ════════════════════════════════════════════════════════════════════

# Pull luhn_valid from the library for an independent check.
eval "$(sed -n '/^declare -f luhn_valid.*|| luhn_valid() {/,/^}/p' "$LIB" 2>/dev/null | sed '1s/.*|| //')" 2>/dev/null || true
if ! declare -f luhn_valid >/dev/null 2>&1; then
  # Fall back to the canonical one in detectors.sh.
  eval "$(sed -n '/^luhn_valid()/,/^}/p' "$SCRIPT_DIR/canary/scripts/detectors.sh" 2>/dev/null)" 2>/dev/null || true
fi

reset_state
card_val="$(bash "$CLI" new card 2>/dev/null | awk -F': ' '/^  Value:/{print $2; exit}')"
if [[ "$card_val" =~ ^[0-9]{16}$ ]]; then
  pass "mint card produces a 16-digit number ($card_val)"
else
  fail "mint card produces a 16-digit number" "got '$card_val'"
fi
if declare -f luhn_valid >/dev/null 2>&1 && luhn_valid "$card_val"; then
  pass "mint card value is Luhn-valid"
else
  fail "mint card value is Luhn-valid" "value '$card_val'"
fi
# Cross-check: Canary's own credit_card detector must catch it.
if bash "$SCRIPT_DIR/canary/scripts/detectors.sh" "card $card_val" 2>/dev/null | grep -qF '"type":"credit_card"'; then
  pass "mint card double-signals via the credit_card regex detector"
else
  fail "mint card double-signals via the credit_card regex detector"
fi

reset_state
ssn_val="$(bash "$CLI" new ssn 2>/dev/null | awk -F': ' '/^  Value:/{print $2; exit}')"
ssn_area="${ssn_val%%-*}"
if [[ "$ssn_val" =~ ^[0-9]{3}-[0-9]{2}-[0-9]{4}$ ]] && [[ "$ssn_area" =~ ^[0-9]+$ ]] && [[ "$ssn_area" -ge 900 && "$ssn_area" -le 999 ]]; then
  pass "mint ssn is in the reserved 900-999 area ($ssn_val)"
else
  fail "mint ssn is in the reserved 900-999 area" "got '$ssn_val' area '$ssn_area'"
fi

# Not-a-placeholder: mint many cards, none may equal an is_placeholder literal.
eval "$(sed -n '/^is_repeated_digit()/,/^}/p' "$SCRIPT_DIR/canary/scripts/detectors.sh" 2>/dev/null)" 2>/dev/null || true
eval "$(sed -n '/^is_placeholder()/,/^}/p' "$SCRIPT_DIR/canary/scripts/detectors.sh" 2>/dev/null)" 2>/dev/null || true
placeholder_hit=0
if declare -f is_placeholder >/dev/null 2>&1; then
  for _ in 1 2 3 4 5 6 7 8; do
    reset_state
    v="$(bash "$CLI" new card 2>/dev/null | awk -F': ' '/^  Value:/{print $2; exit}')"
    if is_placeholder "$v"; then placeholder_hit=1; break; fi
  done
  if [[ $placeholder_hit -eq 0 ]]; then
    pass "minted card values are never is_placeholder() literals (8 samples)"
  else
    fail "minted card values are never is_placeholder() literals" "hit '$v'"
  fi
else
  echo "  SKIP: could not load is_placeholder() from detectors.sh"
fi

# ════════════════════════════════════════════════════════════════════
echo ""
echo "=== Plant: writes a file containing the minted value ==="
# ════════════════════════════════════════════════════════════════════
reset_state
plant_out="$(cd "$WORKDIR" && bash "$CLI" plant env 2>/dev/null)"
planted_file="$(printf '%s\n' "$plant_out" | awk -F': ' '/^Planted:/{print $2; exit}')"
planted_val="$(grep -F "\"type\":\"env\"" "$CANARIES_FILE" 2>/dev/null | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)"
if [[ -n "$planted_file" && -f "$planted_file" ]]; then
  pass "plant env creates the decoy file ($planted_file)"
else
  fail "plant env creates the decoy file" "planted_file='$planted_file'"
fi
if [[ -n "$planted_val" ]] && value_in_file "$planted_file" "$planted_val"; then
  pass "planted file contains the minted value"
else
  fail "planted file contains the minted value" "val='$planted_val'"
fi
if grep -qF "\"planted_path\":\"$planted_file\"" "$CANARIES_FILE" 2>/dev/null; then
  pass "plant records planted_path in the registry"
else
  fail "plant records planted_path in the registry"
fi

# ════════════════════════════════════════════════════════════════════
echo ""
echo "=== Detect: scanning a planted value trips exactly once (idempotent) ==="
# ════════════════════════════════════════════════════════════════════
reset_state
# source the library so we can call check_text_for_trips directly
# (mirrors exactly what scan.sh / scan-file.sh do).
# shellcheck source=/dev/null
source "$LIB"

env_val="$(mint_token env "detect test" 2>/dev/null)"
armed_before="$(grep -cF '"status":"armed"' "$CANARIES_FILE" 2>/dev/null || echo 0)"
blob="here is a leaked config: API_KEY=$env_val trailing text"

printf '%s' "$blob" | check_text_for_trips - "file:/tmp/detect.env" "sess-detect" "$WORKDIR" >/dev/null 2>&1 || true
t1="$(count_trips)"
if [[ "$t1" == "1" ]]; then
  pass "first scan records exactly one canary_tripped"
else
  fail "first scan records exactly one canary_tripped" "count=$t1"
fi
if grep -qF '"detector":"canary"' "$LEAKS_FILE" 2>/dev/null && grep -qF '"confidence":"certain"' "$LEAKS_FILE" 2>/dev/null; then
  pass "trip is recorded at detector=canary confidence=certain"
else
  fail "trip is recorded at detector=canary confidence=certain"
fi
# trip 'value' must be the LABEL, never the raw token.
if grep -qF '"value":"detect test"' "$LEAKS_FILE" 2>/dev/null && ! value_in_file "$LEAKS_FILE" "$env_val"; then
  pass "trip logs the label, never the raw token value"
else
  fail "trip logs the label, never the raw token value"
fi
if grep -qF '"status":"tripped"' "$CANARIES_FILE" 2>/dev/null; then
  pass "canary status flips to tripped"
else
  fail "canary status flips to tripped"
fi

# Idempotency: scanning the same text again must not add a second trip.
printf '%s' "$blob" | check_text_for_trips - "file:/tmp/detect.env" "sess-detect" "$WORKDIR" >/dev/null 2>&1 || true
t2="$(count_trips)"
if [[ "$t2" == "1" ]]; then
  pass "re-scanning the same value does not duplicate the trip (idempotent)"
else
  fail "re-scanning the same value does not duplicate the trip" "count=$t2"
fi

# ════════════════════════════════════════════════════════════════════
echo ""
echo "=== grep -F correctness: regex/shell metacharacters match literally ==="
# ════════════════════════════════════════════════════════════════════
reset_state
# shellcheck source=/dev/null
source "$LIB"
# A value that would be a broken/greedy regex AND contains a shell-ish
# token — must be matched as a literal string, never interpreted.
meta_val='a.b*c[x]$secret+(y)|z\q'
mint_token freeform "$meta_val" >/dev/null 2>&1 || true

# A non-matching blob that a REGEX interpretation of meta_val might
# still match (e.g. "abbc" matches a.b*c as a regex) must NOT trip.
printf '%s' "abbbc xyz nothing here" | check_text_for_trips - "test" "s" "$WORKDIR" >/dev/null 2>&1 || true
if [[ "$(count_trips)" == "0" ]]; then
  pass "regex-shaped value does not trip on a merely regex-matching blob"
else
  fail "regex-shaped value does not trip on a merely regex-matching blob" "count=$(count_trips)"
fi
# The literal string present -> must trip exactly once.
printf '%s' "leak: $meta_val done" | check_text_for_trips - "test" "s" "$WORKDIR" >/dev/null 2>&1 || true
if [[ "$(count_trips)" == "1" ]]; then
  pass "literal metacharacter value matches via grep -F and trips once"
else
  fail "literal metacharacter value matches via grep -F and trips once" "count=$(count_trips)"
fi

# ════════════════════════════════════════════════════════════════════
echo ""
echo "=== Revoke: disarms/removes the canary ==="
# ════════════════════════════════════════════════════════════════════
reset_state
# shellcheck source=/dev/null
source "$LIB"
rv_val="$(mint_token env "revoke me" 2>/dev/null)"
rid="$(grep -F '"label":"revoke me"' "$CANARIES_FILE" 2>/dev/null | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)"
before_lines="$(wc -l < "$CANARIES_FILE" | tr -d ' ')"
revoke "$rid" >/dev/null 2>&1 || true
after_lines="$(wc -l < "$CANARIES_FILE" 2>/dev/null | tr -d ' ' || echo 0)"
if ! grep -qF "\"id\":\"$rid\"" "$CANARIES_FILE" 2>/dev/null; then
  pass "revoke removes the canary from the registry ($before_lines -> $after_lines lines)"
else
  fail "revoke removes the canary from the registry"
fi
# A revoked canary can never trip again.
printf '%s' "API_KEY=$rv_val" | check_text_for_trips - "test" "s" "$WORKDIR" >/dev/null 2>&1 || true
if [[ "$(count_trips)" == "0" ]]; then
  pass "revoked canary no longer trips when its value reappears"
else
  fail "revoked canary no longer trips when its value reappears" "count=$(count_trips)"
fi

# ════════════════════════════════════════════════════════════════════
echo ""
echo "=== Empty registry: no-op, no error, exit 0 ==="
# ════════════════════════════════════════════════════════════════════
reset_state
# shellcheck source=/dev/null
source "$LIB"
set +e
printf '%s' "a totally unrelated blob AKIAEXAMPLE1234567890" | check_text_for_trips - "test" "s" "$WORKDIR" >/dev/null 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  pass "check_text_for_trips with no registry exits 0"
else
  fail "check_text_for_trips with no registry exits 0" "rc=$rc"
fi
if [[ ! -f "$LEAKS_FILE" ]] || [[ "$(count_trips)" == "0" ]]; then
  pass "empty-registry scan records nothing"
else
  fail "empty-registry scan records nothing" "count=$(count_trips)"
fi
# list on an empty registry must not error either.
set +e
bash "$CLI" list >/dev/null 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  pass "list on empty registry exits 0"
else
  fail "list on empty registry exits 0" "rc=$rc"
fi

# ════════════════════════════════════════════════════════════════════
echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
