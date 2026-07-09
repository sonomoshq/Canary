#!/usr/bin/env bash
# test-rotation.sh — Verify session-start.sh's leaks.jsonl log rotation:
# below-threshold files are left alone, an over-threshold file gets
# archived (gzip'd when available, plain when not) with a fresh empty
# 0600 leaks.jsonl left behind, the per-type/per-detector rollup ledger
# and leaks-rollup.json accumulate correctly (including across repeated
# rotations), malformed lines don't break counting, and the live+rollup
# total always equals the pre-rotation total.
# Usage: bash tests/test-rotation.sh
#
# Extracts rotate_leaks_if_needed() (and the constants it depends on)
# straight out of session-start.sh via eval "$(sed ...)" — the same
# technique test-redact.sh / test-checksums.sh use to unit-test a
# function without invoking the whole hook (process substitution as a
# source target is unreliable on macOS's bash 3.2, which is why it's
# eval+sed rather than `source <(...)`).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION_START="$SCRIPT_DIR/canary/scripts/session-start.sh"

PASS=0
FAIL=0

ROTATE_CONSTS=$(sed -n '/^ROTATE_THRESHOLD_LINES=/,/^ROLLUP_JSON=/p' "$SESSION_START")
ROTATE_FUNC=$(sed -n '/^rotate_leaks_if_needed()/,/^}/p' "$SESSION_START")

if [[ -z "$ROTATE_CONSTS" || -z "$ROTATE_FUNC" ]]; then
  echo "FAIL: could not extract rotate_leaks_if_needed() / its constants from session-start.sh"
  exit 1
fi

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/canary-rotation-test.XXXXXX")
cleanup() { rm -rf "$TMP_ROOT" 2>/dev/null || true; }
trap cleanup EXIT

# ── Portable file-mode reader (BSD stat -f / GNU stat -c dual path, same
# idiom statusline.sh uses for mtime+size) ──────────────────────────────
file_mode() {
  local f="$1" m
  m=$(stat -f '%Lp' "$f" 2>/dev/null) || m=""
  if [[ ! "$m" =~ ^[0-7]+$ ]]; then
    m=$(stat -c '%a' "$f" 2>/dev/null) || m=""
  fi
  printf '%s' "$m"
}

# ── Fresh isolated SONOMOS_DIR per test case, with the rotation function
# (re-)bound to it. A real temp HOME too, per the task's "isolated temp
# HOME" instruction, even though the extracted function itself only
# looks at SONOMOS_DIR/LEAKS_FILE (it doesn't read $HOME directly). ────
setup_env() {
  TEST_HOME=$(mktemp -d "$TMP_ROOT/home.XXXXXX")
  export HOME="$TEST_HOME"
  SONOMOS_DIR="$TEST_HOME/.sonomos"
  LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
  mkdir -p "$SONOMOS_DIR"
  eval "$ROTATE_CONSTS"
  eval "$ROTATE_FUNC"
}

# ── Deterministic synthetic leaks.jsonl generator ───────────────────────
# type = credit_card on every 3rd line (n/3 lines), email otherwise;
# detector = llm on every even line (n/2 lines), regex otherwise. Both
# split evenly for n divisible by 6, so expected counts are exact
# arithmetic, not estimates.
gen_leaks() {
  local n="$1" out="$2"
  awk -v n="$n" '
    BEGIN {
      for (i = 1; i <= n; i++) {
        t = (i % 3 == 0) ? "credit_card" : "email"
        d = (i % 2 == 0) ? "llm" : "regex"
        printf "{\"type\":\"%s\",\"detector\":\"%s\",\"confidence\":\"high\",\"timestamp\":\"2026-01-01T00:00:00Z\",\"session_id\":\"s1\",\"value_id\":\"v%d\",\"source\":\"transcript\",\"cwd\":\"/tmp\"}\n", t, d, i
      }
    }
  ' > "$out"
}

# ── Ledger reader (KEY=VALUE, defensive — mirrors session-start.sh's own
# never-source parsing contract) ────────────────────────────────────────
ledger_get() {
  local file="$1" key="$2" v="" k line
  [[ -f "$file" ]] || { printf ''; return; }
  while IFS='=' read -r k line; do
    [[ "$k" == "$key" ]] && v="$line"
  done < "$file"
  printf '%s' "$v"
}

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

# ═════════════════════════════════════════════════════════════════════
echo "=== Below-threshold file is left untouched ==="
# ═════════════════════════════════════════════════════════════════════
setup_env
gen_leaks 120 "$LEAKS_FILE"
BEFORE_COPY="$TMP_ROOT/before.jsonl"
cp "$LEAKS_FILE" "$BEFORE_COPY"

rotate_leaks_if_needed

if cmp -s "$LEAKS_FILE" "$BEFORE_COPY"; then
  pass "leaks.jsonl byte-identical after a below-threshold call"
else
  fail "leaks.jsonl was modified even though it's below both thresholds"
fi
if [[ ! -d "$ARCHIVE_DIR" || -z "$(ls -A "$ARCHIVE_DIR" 2>/dev/null)" ]]; then
  pass "archive/ was not populated"
else
  fail "archive/ unexpectedly contains files"
fi
if [[ ! -f "$LEDGER_FILE" ]]; then
  pass "no rollup ledger was created"
else
  fail "rollup ledger was created for a below-threshold file"
fi

# ═════════════════════════════════════════════════════════════════════
echo ""
echo "=== Synthetic >50k-line file IS rotated ==="
# ═════════════════════════════════════════════════════════════════════
setup_env
N=60000
gen_leaks "$N" "$LEAKS_FILE"
PRE_TOTAL=$(wc -l < "$LEAKS_FILE" | tr -d ' ')

rotate_leaks_if_needed

ARCHIVED=$(ls "$ARCHIVE_DIR"/leaks-*.jsonl* 2>/dev/null | head -1 || true)
if [[ -n "$ARCHIVED" && -f "$ARCHIVED" ]]; then
  pass "archive file created: $(basename "$ARCHIVED")"
else
  fail "no archive file found under $ARCHIVE_DIR"
fi

if command -v gzip >/dev/null 2>&1; then
  case "$ARCHIVED" in
    *.gz) pass "archive was gzip'd (gzip is available)" ;;
    *)    fail "gzip is available but archive wasn't compressed" ;;
  esac
  if [[ "$ARCHIVED" == *.gz ]] && gzip -t "$ARCHIVED" 2>/dev/null; then
    pass "archived .gz is a valid gzip stream"
  elif [[ "$ARCHIVED" == *.gz ]]; then
    fail "archived .gz failed gzip -t integrity check"
  fi
fi

if [[ -f "$LEAKS_FILE" && ! -s "$LEAKS_FILE" ]]; then
  pass "fresh leaks.jsonl exists and is empty"
else
  fail "leaks.jsonl is missing or non-empty after rotation"
fi

MODE=$(file_mode "$LEAKS_FILE")
if [[ "$MODE" == "600" ]]; then
  pass "fresh leaks.jsonl is 0600"
else
  fail "fresh leaks.jsonl mode is '$MODE', expected 600"
fi

ARCHIVE_MODE=$(file_mode "$ARCHIVE_DIR")
if [[ "$ARCHIVE_MODE" == "700" ]]; then
  pass "archive/ directory is 0700"
else
  fail "archive/ mode is '$ARCHIVE_MODE', expected 700"
fi

# Expected exact counts from gen_leaks' i%3/i%2 split over 60000 lines.
EXP_CREDIT=20000; EXP_EMAIL=40000; EXP_LLM=30000; EXP_REGEX=30000

LEDGER_TOTAL=$(ledger_get "$LEDGER_FILE" TOTAL)
LEDGER_ROTATIONS=$(ledger_get "$LEDGER_FILE" ROTATIONS)
LEDGER_CC=$(ledger_get "$LEDGER_FILE" "TYPE:credit_card")
LEDGER_EMAIL=$(ledger_get "$LEDGER_FILE" "TYPE:email")
LEDGER_LLM=$(ledger_get "$LEDGER_FILE" "DETECTOR:llm")
LEDGER_REGEX=$(ledger_get "$LEDGER_FILE" "DETECTOR:regex")

[[ "$LEDGER_TOTAL" == "$N" ]] && pass "ledger TOTAL == $N" || fail "ledger TOTAL == '$LEDGER_TOTAL', expected $N"
[[ "$LEDGER_ROTATIONS" == "1" ]] && pass "ledger ROTATIONS == 1" || fail "ledger ROTATIONS == '$LEDGER_ROTATIONS', expected 1"
[[ "$LEDGER_CC" == "$EXP_CREDIT" ]] && pass "ledger TYPE:credit_card == $EXP_CREDIT" || fail "ledger TYPE:credit_card == '$LEDGER_CC', expected $EXP_CREDIT"
[[ "$LEDGER_EMAIL" == "$EXP_EMAIL" ]] && pass "ledger TYPE:email == $EXP_EMAIL" || fail "ledger TYPE:email == '$LEDGER_EMAIL', expected $EXP_EMAIL"
[[ "$LEDGER_LLM" == "$EXP_LLM" ]] && pass "ledger DETECTOR:llm == $EXP_LLM" || fail "ledger DETECTOR:llm == '$LEDGER_LLM', expected $EXP_LLM"
[[ "$LEDGER_REGEX" == "$EXP_REGEX" ]] && pass "ledger DETECTOR:regex == $EXP_REGEX" || fail "ledger DETECTOR:regex == '$LEDGER_REGEX', expected $EXP_REGEX"

if [[ -f "$ROLLUP_JSON" ]]; then
  pass "leaks-rollup.json was written"
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$ROLLUP_JSON" "$N" "$EXP_CREDIT" "$EXP_EMAIL" "$EXP_LLM" "$EXP_REGEX" <<'PYEOF'
import json, sys
path, n, cc, email, llm, regex = sys.argv[1:7]
with open(path) as f:
    data = json.load(f)
assert data["total"] == int(n), data
assert data["rotations"] == 1, data
assert data["types"]["credit_card"] == int(cc), data
assert data["types"]["email"] == int(email), data
assert data["detectors"]["llm"] == int(llm), data
assert data["detectors"]["regex"] == int(regex), data
PYEOF
    then
      pass "leaks-rollup.json is valid JSON with matching total/types/detectors"
    else
      fail "leaks-rollup.json content did not match expected counts"
    fi
  else
    echo "  SKIP: python3 not available — skipping leaks-rollup.json content check"
  fi
else
  fail "leaks-rollup.json was not written"
fi

ROLLUP_JSON_MODE=$(file_mode "$ROLLUP_JSON")
[[ "$ROLLUP_JSON_MODE" == "600" ]] && pass "leaks-rollup.json is 0600" || fail "leaks-rollup.json mode is '$ROLLUP_JSON_MODE', expected 600"

# ═════════════════════════════════════════════════════════════════════
echo ""
echo "=== Lifetime total (rollup + live) survives rotation, including a second rotation ==="
# ═════════════════════════════════════════════════════════════════════
# Continuing the environment from the previous block: leaks.jsonl is
# fresh/empty, ledger TOTAL=60000. Live total right now must equal the
# pre-rotation total exactly (nothing lost, nothing double-counted).
LIVE_NOW=$(wc -l < "$LEAKS_FILE" | tr -d ' ')
LIFETIME_NOW=$((LIVE_NOW + LEDGER_TOTAL))
if [[ "$LIFETIME_NOW" -eq "$PRE_TOTAL" ]]; then
  pass "live($LIVE_NOW) + rollup($LEDGER_TOTAL) == pre-rotation total ($PRE_TOTAL)"
else
  fail "live($LIVE_NOW) + rollup($LEDGER_TOTAL) == $LIFETIME_NOW, expected $PRE_TOTAL"
fi

# Fill the (now-fresh) live file past the threshold again with a second,
# differently-sized batch and rotate a second time — the ledger must
# accumulate on top of the first rotation's counts, not replace them.
N2=51000
gen_leaks "$N2" "$LEAKS_FILE"
rotate_leaks_if_needed

LEDGER_TOTAL_2=$(ledger_get "$LEDGER_FILE" TOTAL)
LEDGER_ROTATIONS_2=$(ledger_get "$LEDGER_FILE" ROTATIONS)
LIVE_AFTER_2=$(wc -l < "$LEAKS_FILE" | tr -d ' ')
EXPECTED_CUMULATIVE=$((N + N2))

[[ "$LEDGER_ROTATIONS_2" == "2" ]] && pass "ledger ROTATIONS accumulated to 2" || fail "ledger ROTATIONS == '$LEDGER_ROTATIONS_2', expected 2"
if [[ "$LEDGER_TOTAL_2" == "$EXPECTED_CUMULATIVE" ]]; then
  pass "ledger TOTAL accumulated across two rotations ($N + $N2 = $EXPECTED_CUMULATIVE)"
else
  fail "ledger TOTAL == '$LEDGER_TOTAL_2', expected cumulative $EXPECTED_CUMULATIVE"
fi
ARCHIVE_COUNT=$(ls "$ARCHIVE_DIR"/leaks-*.jsonl* 2>/dev/null | wc -l | tr -d ' ')
[[ "$ARCHIVE_COUNT" -eq 2 ]] && pass "two archive files now present" || fail "expected 2 archive files, found $ARCHIVE_COUNT"
LIFETIME_AFTER_2=$((LIVE_AFTER_2 + LEDGER_TOTAL_2))
[[ "$LIFETIME_AFTER_2" -eq "$EXPECTED_CUMULATIVE" ]] && pass "lifetime total still exact after 2nd rotation" || fail "lifetime total $LIFETIME_AFTER_2 != $EXPECTED_CUMULATIVE"

# ═════════════════════════════════════════════════════════════════════
echo ""
echo "=== Malformed lines don't break rollup counting ==="
# ═════════════════════════════════════════════════════════════════════
setup_env
{
  gen_leaks 50000 /dev/stdout
  echo 'not json at all {{{'
  echo ''
  printf '{"type":"email","detector":"regex","confidence":"high"'   # truncated, no closing brace
  echo ''
  echo '   '
} > "$LEAKS_FILE"
TOTAL_LINES=$(wc -l < "$LEAKS_FILE" | tr -d ' ')

rotate_leaks_if_needed

LEDGER_TOTAL_M=$(ledger_get "$LEDGER_FILE" TOTAL)
if [[ "$LEDGER_TOTAL_M" == "$TOTAL_LINES" ]]; then
  pass "rotation didn't crash on malformed lines, and TOTAL == raw line count ($TOTAL_LINES)"
else
  fail "TOTAL == '$LEDGER_TOTAL_M', expected raw line count $TOTAL_LINES"
fi
# The 50000 well-formed lines still contribute their exact type counts
# (25000 credit_card is wrong for n=50000/i%3 split, so recompute the
# real expected value the same way gen_leaks does: floor(50000/3)).
EXP_CC_M=$(( (50000) / 3 ))
LEDGER_CC_M=$(ledger_get "$LEDGER_FILE" "TYPE:credit_card")
if [[ "$LEDGER_CC_M" == "$EXP_CC_M" ]]; then
  pass "well-formed lines' type counts unaffected by the malformed lines mixed in ($EXP_CC_M credit_card)"
else
  fail "TYPE:credit_card == '$LEDGER_CC_M', expected $EXP_CC_M"
fi
if [[ -f "$LEAKS_FILE" && ! -s "$LEAKS_FILE" ]]; then
  pass "fresh leaks.jsonl is empty after a rotation with malformed input"
else
  fail "leaks.jsonl not left empty after rotating malformed input"
fi

# ═════════════════════════════════════════════════════════════════════
echo ""
echo "=== gzip-absent path still archives (uncompressed) ==="
# ═════════════════════════════════════════════════════════════════════
setup_env
gen_leaks 50000 "$LEAKS_FILE"

# Build a PATH containing everything rotate_leaks_if_needed needs EXCEPT
# gzip, so `command -v gzip` genuinely fails — a shell-function override
# wouldn't fool `command -v`, which only looks at PATH.
FAKEBIN="$TMP_ROOT/fakebin"
mkdir -p "$FAKEBIN"
for tool in awk date mv cp rm mkdir chmod wc cksum tr cat sed grep ls; do
  TPATH=$(command -v "$tool" 2>/dev/null) || continue
  ln -sf "$TPATH" "$FAKEBIN/$tool" 2>/dev/null || true
done

(
  export PATH="$FAKEBIN"
  if command -v gzip >/dev/null 2>&1; then
    echo "  FAIL: test setup bug — gzip is still reachable in the restricted PATH"
    exit 1
  fi
  rotate_leaks_if_needed
) 2>/dev/null
SUBSHELL_RC=$?

ARCHIVED_NOGZ=$(ls "$ARCHIVE_DIR"/leaks-*.jsonl 2>/dev/null | head -1 || true)
ARCHIVED_GZ=$(ls "$ARCHIVE_DIR"/leaks-*.jsonl.gz 2>/dev/null | head -1 || true)

if [[ $SUBSHELL_RC -eq 0 && -n "$ARCHIVED_NOGZ" && -z "$ARCHIVED_GZ" ]]; then
  pass "archived without compression when gzip is unavailable"
else
  fail "expected an uncompressed archive with gzip absent (rc=$SUBSHELL_RC, plain='$ARCHIVED_NOGZ', gz='$ARCHIVED_GZ')"
fi
if [[ -f "$LEAKS_FILE" && ! -s "$LEAKS_FILE" ]]; then
  pass "fresh leaks.jsonl still left behind without gzip"
else
  fail "leaks.jsonl not reset correctly in the gzip-absent path"
fi

echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
