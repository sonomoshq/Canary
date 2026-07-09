#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# session-start.sh — Prints PII counter summary on every session start.
# Output goes to stdout → injected as context visible to Claude and user.
# Also installs the HUD statusline script to $SONOMOS_DIR/ for persistence,
# and writes .current_session / config.json for other hooks to read.

set -euo pipefail
umask 0077

SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
STATE_FILE="$SONOMOS_DIR/.state"

mkdir -p "$SONOMOS_DIR"
chmod 700 "$SONOMOS_DIR" 2>/dev/null || true
[[ -f "$LEAKS_FILE" ]] && { chmod 600 "$LEAKS_FILE" 2>/dev/null || true; }

# Read stdin synchronously (the old `cat > /dev/null &` backgrounded drain
# raced the rest of the script instead of actually waiting on it).
INPUT=$(cat 2>/dev/null || true)

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# Best-effort "extract a JSON string field" without jq. Not a full JSON
# parser — matches "key":"value" and doesn't handle embedded escaped
# quotes, but that's fine for session ids and cwd paths.
json_field() {
  local json="$1" key="$2"
  printf '%s' "$json" | \
    grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" 2>/dev/null | \
    head -1 | sed -E 's/.*:[[:space:]]*"//; s/"$//' 2>/dev/null || true
}

if [[ "$HAVE_JQ" -eq 1 ]]; then
  SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)
else
  SESSION_ID=$(json_field "$INPUT" "session_id")
fi

# Persist the session id for record-llm-hit.sh's fallback (it can't
# always get a real session id passed as an argument). Atomic temp+mv.
if [[ -n "$SESSION_ID" ]]; then
  CS_TMP="$SONOMOS_DIR/.current_session.tmp.$$"
  if printf '%s\n' "$SESSION_ID" > "$CS_TMP" 2>/dev/null; then
    mv -f "$CS_TMP" "$SONOMOS_DIR/.current_session" 2>/dev/null || rm -f "$CS_TMP" 2>/dev/null || true
  fi
  chmod 600 "$SONOMOS_DIR/.current_session" 2>/dev/null || true
fi

# Write config.json from the userConfig env var so the dashboard can
# reflect the current llm_scan_enabled setting. Pure printf — no jq
# dependency, since this must work even when jq is absent.
LLM_OPT="${CLAUDE_PLUGIN_OPTION_LLM_SCAN_ENABLED:-true}"
case "$LLM_OPT" in
  false|0) LLM_JSON_BOOL="false" ;;
  *)       LLM_JSON_BOOL="true" ;;
esac
CFG_TMP="$SONOMOS_DIR/config.json.tmp.$$"
if printf '{"llm_scan_enabled": %s}\n' "$LLM_JSON_BOOL" > "$CFG_TMP" 2>/dev/null; then
  mv -f "$CFG_TMP" "$SONOMOS_DIR/config.json" 2>/dev/null || rm -f "$CFG_TMP" 2>/dev/null || true
fi
chmod 600 "$SONOMOS_DIR/config.json" 2>/dev/null || true

# Always keep the statusline script up to date. Best-effort — a copy
# failure here (read-only fs, disk full, ...) must never take down the
# rest of this hook, whose main job (the PII counter) matters more.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || true)"
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/statusline.sh" ]]; then
  cp "$SCRIPT_DIR/statusline.sh" "$SONOMOS_DIR/statusline.sh" 2>/dev/null || true
  chmod +x "$SONOMOS_DIR/statusline.sh" 2>/dev/null || true
fi

# ── First run: show welcome ─────────────────────────────────────────────
if [[ ! -f "$SONOMOS_DIR/.initialized" ]]; then
  touch "$SONOMOS_DIR/.initialized" 2>/dev/null || true

  cat << WELCOME
━━━ 🐤 CANARY — Installed ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Sonomos is now monitoring your conversations for PII exposure.

  Detectors:
  ✓ Regex   16 pattern detectors with checksum validation
            (credit cards, SSNs, emails, crypto addresses, ...)
  ✓ LLM     70+ semantic categories scanned automatically
            (names, addresses, legal IDs, medical records, ...)
            No API key needed. Zero extra cost.

  Commands:
  /canary:leaked [stats|reset]   Dashboard · quick stats · reset
  /canary:scan                   Deep scan of full conversation

  HUD (always-visible status bar):
  Add to ~/.claude/settings.json:
  "statusLine": {"type":"command","command":"bash ${SONOMOS_DIR}/statusline.sh"}

  Tip: say "set up the Canary statusline" and Claude will wire
  the HUD into your settings.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WELCOME
  exit 0
fi

# ── jq missing: minimal, crash-free counter ─────────────────────────────
if [[ "$HAVE_JQ" -ne 1 ]]; then
  TOTAL=0
  if [[ -f "$LEAKS_FILE" ]]; then
    TOTAL=$(wc -l < "$LEAKS_FILE" 2>/dev/null | tr -d ' ')
    [[ "$TOTAL" =~ ^[0-9]+$ ]] || TOTAL=0
  fi
  echo "━━━ 🐤 CANARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ${TOTAL} PII items recorded (basic count — jq not found)"
  echo "  Install jq for full stats: breakdown, sessions, streaks."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 0
fi

# ── Returning user: load prior state ─────────────────────────────────────
LAST_TOTAL=0
CLEAN_STREAK=0
LAST_SESSION_ID=""
if [[ -f "$STATE_FILE" ]]; then
  while IFS='=' read -r k v; do
    case "$k" in
      LAST_TOTAL)      [[ "$v" =~ ^[0-9]+$ ]] && LAST_TOTAL="$v" ;;
      CLEAN_STREAK)    [[ "$v" =~ ^[0-9]+$ ]] && CLEAN_STREAK="$v" ;;
      LAST_SESSION_ID) LAST_SESSION_ID="$v" ;;
    esac
  done < "$STATE_FILE" 2>/dev/null || true
fi

# No leaks yet
if [[ ! -f "$LEAKS_FILE" || ! -s "$LEAKS_FILE" ]]; then
  TOTAL=0
  HIGH_CONF=0; REGEX_COUNT=0; LLM_COUNT=0; SESSIONS=0; NUM_TYPES=0; BREAKDOWN=""
else
  # ── Single awk pass over leaks.jsonl (was ~6 separate jq passes) ───────
  # Same string-index technique as statusline.sh: no JSON parsing, just
  # substring search on each line. Line 1 of output is the tab-separated
  # summary; remaining lines are the pre-formatted top-8 breakdown.
  AWK_OUT=$(awk '
    {
      total++
      if (index($0, "\"confidence\":\"high\"")) high++
      if (index($0, "\"detector\":\"regex\"")) regex++
      else if (index($0, "\"detector\":\"llm\"")) llm++

      ti = index($0, "\"type\":\"")
      if (ti > 0) {
        rest = substr($0, ti + 8)
        te = index(rest, "\"")
        if (te > 0) { t = substr(rest, 1, te - 1); types[t]++ }
      }

      si = index($0, "\"session_id\":\"")
      if (si > 0) {
        rest2 = substr($0, si + 15)
        se = index(rest2, "\"")
        if (se > 0) { s = substr(rest2, 1, se - 1); sessions[s] = 1 }
      }
    }
    END {
      num_types = 0
      for (t in types) num_types++
      num_sessions = 0
      for (s in sessions) num_sessions++
      printf "%d\t%d\t%d\t%d\t%d\t%d\n", total+0, high+0, regex+0, llm+0, num_sessions+0, num_types+0

      for (pass = 1; pass <= 8; pass++) {
        best = ""; best_ct = 0
        for (t in types) {
          if (types[t] > best_ct) { best = t; best_ct = types[t] }
        }
        if (best == "") break
        printf "    %-22s %d\n", best, best_ct
        delete types[best]
      }
    }
  ' "$LEAKS_FILE" 2>/dev/null || true)

  SUMMARY_LINE=$(printf '%s\n' "$AWK_OUT" | head -1)
  BREAKDOWN=$(printf '%s\n' "$AWK_OUT" | tail -n +2)
  IFS=$'\t' read -r TOTAL HIGH_CONF REGEX_COUNT LLM_COUNT SESSIONS NUM_TYPES <<< "$SUMMARY_LINE"
  TOTAL=${TOTAL:-0}; HIGH_CONF=${HIGH_CONF:-0}; REGEX_COUNT=${REGEX_COUNT:-0}
  LLM_COUNT=${LLM_COUNT:-0}; SESSIONS=${SESSIONS:-0}; NUM_TYPES=${NUM_TYPES:-0}
fi

# ── Streak + milestone bookkeeping ───────────────────────────────────────
# Skip the streak/milestone recompute if this is a repeat SessionStart
# firing for the SAME session (e.g. /compact, /clear, resume) so those
# don't inflate or reset the streak, or re-announce a milestone.
IS_NEW_SESSION=1
if [[ -n "$LAST_SESSION_ID" && -n "$SESSION_ID" && "$SESSION_ID" == "$LAST_SESSION_ID" ]]; then
  IS_NEW_SESSION=0
fi

MILESTONE_LINE=""
milestone_text() {
  case "$1" in
    10)   echo "10+ PII items — the leaks add up fast" ;;
    50)   echo "50+ PII items — time for a privacy check-in" ;;
    100)  echo "100+ PII items — welcome to the Century Club" ;;
    500)  echo "500+ PII items — that's a serious exposure trail" ;;
    1000) echo "1000+ PII items — quadruple digits, seriously" ;;
  esac
}

if [[ "$IS_NEW_SESSION" -eq 1 ]]; then
  if [[ "$TOTAL" -eq "$LAST_TOTAL" ]]; then
    CLEAN_STREAK=$((CLEAN_STREAK + 1))
  else
    CLEAN_STREAK=0
  fi
  for M in 10 50 100 500 1000; do
    if [[ "$LAST_TOTAL" -lt "$M" && "$TOTAL" -ge "$M" ]]; then
      MILESTONE_LINE="  🏆 Milestone: $(milestone_text "$M"). /canary:leaked to see the damage."
    fi
  done
fi

STREAK_LINE=""
[[ "$CLEAN_STREAK" -ge 2 ]] && STREAK_LINE="  🟢 clean streak: ${CLEAN_STREAK} sessions"

# Persist state (atomic temp+mv). LAST_TOTAL/LAST_SESSION_ID always
# refresh to the current values; only CLEAN_STREAK's evolution is gated
# above by IS_NEW_SESSION.
STATE_TMP="${STATE_FILE}.tmp.$$"
{
  printf 'LAST_TOTAL=%s\n' "$TOTAL"
  printf 'CLEAN_STREAK=%s\n' "$CLEAN_STREAK"
  printf 'LAST_SESSION_ID=%s\n' "$SESSION_ID"
} > "$STATE_TMP" 2>/dev/null
if [[ -s "$STATE_TMP" ]]; then
  mv -f "$STATE_TMP" "$STATE_FILE" 2>/dev/null || rm -f "$STATE_TMP" 2>/dev/null || true
fi
chmod 600 "$STATE_FILE" 2>/dev/null || true

# ── Render banner ─────────────────────────────────────────────────────────
if [[ "$TOTAL" -eq 0 ]]; then
  echo "━━━ 🐤 CANARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  0 PII items detected. Clean so far."
  [[ -n "$STREAK_LINE" ]] && echo "$STREAK_LINE"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 0
fi

# Dashboard status — use the real data dir, not a hardcoded ~/.sonomos
# (CLAUDE_PLUGIN_DATA may point elsewhere).
DASH_STATUS=""
if [[ -f "$SONOMOS_DIR/dashboard.html" ]]; then
  DASH_STATUS="📊 dashboard: $SONOMOS_DIR/dashboard.html"
else
  DASH_STATUS="📊 /canary:leaked → generate dashboard"
fi

echo "━━━ 🐤 CANARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ${TOTAL} PII items exposed across ${SESSIONS} session(s)"
echo "  ${HIGH_CONF} high-confidence │ ${NUM_TYPES} types │ regex: ${REGEX_COUNT} │ llm: ${LLM_COUNT}"
[[ -n "$STREAK_LINE" ]] && echo "$STREAK_LINE"
[[ -n "$MILESTONE_LINE" ]] && echo "$MILESTONE_LINE"
echo ""
echo "  Top categories:"
echo "${BREAKDOWN}"
echo ""
echo "  ${DASH_STATUS}"
echo "  /canary:leaked → dashboard │ /canary:scan → deep audit"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit 0
