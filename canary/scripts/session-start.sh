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

# ── Log rotation (opportunistic, best-effort, NEVER blocks the banner) ──
# Keeps leaks.jsonl fast forever. Runs here — before the jq-availability
# branch further down — so both the full-stats path and the jq-missing
# minimal path (which leans on `wc -l` the most) benefit from a bounded
# file. Threshold: >=50000 lines OR >=5MiB. Pure awk, no jq dependency —
# rotation must work even when jq is absent.
#
# On trip: (i) fold the current file's per-type/per-detector counts into
# a cumulative ledger ($SONOMOS_DIR/.rollup_ledger, KEY=VALUE — parsed
# defensively, never sourced, same convention as .state) and regenerate
# leaks-rollup.json from that ledger, (ii) archive+gzip (if available)
# the rotated-out file to archive/, (iii) leave a fresh empty 0600
# leaks.jsonl behind.
#
# DATA MODEL NOTE: canary-stats / statusline.sh / dashboard.py currently
# read only the live leaks.jsonl, so their totals/breakdowns would still
# dip across a rotation boundary — they'd need to add the rollup ledger's
# counts to stay fully lifetime-accurate. That's flagged as follow-up
# work; THIS hook's own TOTAL already adds the rollup's grand total back
# in (see ROLLUP_TOTAL below) so the banner's number never drops.
ROTATE_THRESHOLD_LINES=50000
ROTATE_THRESHOLD_BYTES=5242880   # 5 MiB
ARCHIVE_DIR="$SONOMOS_DIR/archive"
LEDGER_FILE="$SONOMOS_DIR/.rollup_ledger"
ROLLUP_JSON="$SONOMOS_DIR/leaks-rollup.json"

rotate_leaks_if_needed() {
  [[ -f "$LEAKS_FILE" ]] || return 0

  local nlines nbytes
  nlines=$(wc -l < "$LEAKS_FILE" 2>/dev/null | tr -d ' ') || nlines=""
  [[ "$nlines" =~ ^[0-9]+$ ]] || nlines=0
  # cksum (not stat) for a portable byte count: its 2nd field is the size,
  # avoiding the GNU `stat -c`/BSD `stat -f` split seen elsewhere in this
  # plugin. read's trailing "_" swallows the filename even if it has
  # spaces, so only the checksum/size fields are actually captured.
  nbytes=""
  read -r _ nbytes _ <<< "$(cksum "$LEAKS_FILE" 2>/dev/null)" || nbytes=""
  [[ "$nbytes" =~ ^[0-9]+$ ]] || nbytes=0

  if [[ "$nlines" -lt "$ROTATE_THRESHOLD_LINES" && "$nbytes" -lt "$ROTATE_THRESHOLD_BYTES" ]]; then
    return 0
  fi

  mkdir -p "$ARCHIVE_DIR" 2>/dev/null || return 0
  chmod 700 "$ARCHIVE_DIR" 2>/dev/null || true

  local rot_id="$$.${RANDOM:-0}"
  local rotating="$SONOMOS_DIR/.rotating.$rot_id"

  # Swap the live file out (atomic rename) and put a fresh empty one back
  # FIRST, before the slower counting/gzip work below, to minimize the
  # window where a concurrent detector write would find no leaks.jsonl.
  # Any writer that already had the old inode open keeps appending to it
  # harmlessly — that data still lands in the archive, just isn't counted
  # in this rotation's rollup (best-effort, not a correctness guarantee).
  mv -f "$LEAKS_FILE" "$rotating" 2>/dev/null || return 0
  : > "$LEAKS_FILE" 2>/dev/null || true
  chmod 600 "$LEAKS_FILE" 2>/dev/null || true

  local ts rotated_iso
  ts=$(date -u +%Y-%m-%dT%H%M%S 2>/dev/null) || ts="unknown-$$"
  rotated_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || rotated_iso=""

  local ledger_tmp="${LEDGER_FILE}.tmp.$rot_id"
  local json_tmp="${ROLLUP_JSON}.tmp.$rot_id"

  awk -v OLD_LEDGER="$LEDGER_FILE" -v LEDGER_TMP="$ledger_tmp" \
      -v JSON_TMP="$json_tmp" -v ROTATED_TS="$rotated_iso" '
    BEGIN {
      old_total = 0; old_rotations = 0
      while ((getline line < OLD_LEDGER) > 0) {
        eq = index(line, "=")
        if (eq <= 0) continue
        k = substr(line, 1, eq - 1)
        v = substr(line, eq + 1)
        if (k == "TOTAL") old_total = v + 0
        else if (k == "ROTATIONS") old_rotations = v + 0
        else if (index(k, "TYPE:") == 1) type_ct[substr(k, 6)] = v + 0
        else if (index(k, "DETECTOR:") == 1) det_ct[substr(k, 10)] = v + 0
      }
      close(OLD_LEDGER)
    }
    {
      cur_total++
      ti = index($0, "\"type\":\"")
      if (ti > 0) {
        rest = substr($0, ti + 8); te = index(rest, "\"")
        if (te > 0) type_ct[substr(rest, 1, te - 1)]++
      }
      di = index($0, "\"detector\":\"")
      if (di > 0) {
        restd = substr($0, di + 12); de = index(restd, "\"")
        if (de > 0) det_ct[substr(restd, 1, de - 1)]++
      }
    }
    END {
      new_total = old_total + cur_total
      new_rotations = old_rotations + 1

      ledger = sprintf("TOTAL=%d\nROTATIONS=%d\nLAST_ROTATED=%s\n", new_total, new_rotations, ROTATED_TS)
      for (k in type_ct)  ledger = ledger sprintf("TYPE:%s=%d\n", k, type_ct[k])
      for (k in det_ct)   ledger = ledger sprintf("DETECTOR:%s=%d\n", k, det_ct[k])
      printf "%s", ledger > LEDGER_TMP
      close(LEDGER_TMP)

      types_json = ""
      for (k in type_ct) {
        if (k !~ /^[A-Za-z0-9_]+$/) continue
        if (types_json != "") types_json = types_json ","
        types_json = types_json sprintf("\n    \"%s\": %d", k, type_ct[k])
      }
      dets_json = ""
      for (k in det_ct) {
        if (k !~ /^[A-Za-z0-9_]+$/) continue
        if (dets_json != "") dets_json = dets_json ","
        dets_json = dets_json sprintf("\n    \"%s\": %d", k, det_ct[k])
      }
      json = sprintf("{\n  \"total\": %d,\n  \"rotations\": %d,\n  \"last_rotated\": \"%s\",\n  \"types\": {%s\n  },\n  \"detectors\": {%s\n  }\n}\n", \
                      new_total, new_rotations, ROTATED_TS, types_json, dets_json)
      printf "%s", json > JSON_TMP
      close(JSON_TMP)
    }
  ' "$rotating" 2>/dev/null || true

  if [[ -s "$ledger_tmp" ]]; then
    mv -f "$ledger_tmp" "$LEDGER_FILE" 2>/dev/null || rm -f "$ledger_tmp" 2>/dev/null || true
    chmod 600 "$LEDGER_FILE" 2>/dev/null || true
  else
    rm -f "$ledger_tmp" 2>/dev/null || true
  fi
  if [[ -s "$json_tmp" ]]; then
    mv -f "$json_tmp" "$ROLLUP_JSON" 2>/dev/null || rm -f "$json_tmp" 2>/dev/null || true
    chmod 600 "$ROLLUP_JSON" 2>/dev/null || true
  else
    rm -f "$json_tmp" 2>/dev/null || true
  fi

  local archive_dest="$ARCHIVE_DIR/leaks-${ts}.jsonl"
  if [[ -e "$archive_dest" || -e "${archive_dest}.gz" ]]; then
    # Same-second collision — e.g. two rotations back to back in a burst.
    # Disambiguate with this rotation's own pid.random suffix instead of
    # silently overwriting an earlier archive.
    archive_dest="$ARCHIVE_DIR/leaks-${ts}-${rot_id}.jsonl"
  fi
  if mv -f "$rotating" "$archive_dest" 2>/dev/null; then
    chmod 600 "$archive_dest" 2>/dev/null || true
    if command -v gzip >/dev/null 2>&1; then
      gzip -f "$archive_dest" 2>/dev/null || true
    fi
  elif [[ ! -s "$LEAKS_FILE" ]]; then
    # Couldn't move into archive/ — put the data back rather than lose it,
    # but only if the fresh file is still empty (don't clobber anything a
    # concurrent writer already appended to it in the meantime).
    mv -f "$rotating" "$LEAKS_FILE" 2>/dev/null || true
    chmod 600 "$LEAKS_FILE" 2>/dev/null || true
  else
    rm -f "$rotating" 2>/dev/null || true
  fi
}

rotate_leaks_if_needed 2>/dev/null || true

# Lifetime total base carried across rotations. Added into TOTAL below so
# the banner's PII count only ever goes up, even right after a rotation
# emptied the live file. Parsed defensively — .rollup_ledger is KEY=VALUE
# like .state, never sourced.
ROLLUP_TOTAL=0
if [[ -f "$LEDGER_FILE" ]]; then
  while IFS='=' read -r rk rv; do
    case "$rk" in
      TOTAL) [[ "$rv" =~ ^[0-9]+$ ]] && ROLLUP_TOTAL="$rv" ;;
    esac
  done < "$LEDGER_FILE" 2>/dev/null || true
fi

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

# ── HUD auto-install (idempotent, jq-gated, NEVER clobbers) ─────────────
# The #1 audit opportunity: today the welcome message only PRINTS a
# settings.json snippet and hopes the user copies it by hand. Instead,
# merge a statusLine command into ~/.claude/settings.json for them —
# but ONLY when jq is available (a safe structural merge, never string-
# splicing JSON by hand) AND the user has no statusLine configured yet.
# An existing statusLine — Canary's own or anyone else's — is NEVER
# touched. Sets HUD_LINES for the welcome banner below; never fails.
CLAUDE_SETTINGS="${HOME:-}/.claude/settings.json"
HUD_LINES="  HUD (always-visible status bar):
  Add to ~/.claude/settings.json:
  \"statusLine\": {\"type\":\"command\",\"command\":\"bash ${SONOMOS_DIR}/statusline.sh\"}

  Tip: say \"set up the Canary statusline\" and Claude will wire
  the HUD into your settings."

hud_autoinstall() {
  [[ "$HAVE_JQ" -eq 1 ]] || return 0
  [[ -n "${HOME:-}" ]] || return 0

  mkdir -p "$(dirname "$CLAUDE_SETTINGS")" 2>/dev/null || return 0

  if [[ ! -f "$CLAUDE_SETTINGS" ]]; then
    local init_tmp="${CLAUDE_SETTINGS}.tmp.$$"
    printf '{}\n' > "$init_tmp" 2>/dev/null || return 0
    chmod 644 "$init_tmp" 2>/dev/null || true
    mv -f "$init_tmp" "$CLAUDE_SETTINGS" 2>/dev/null || { rm -f "$init_tmp" 2>/dev/null || true; return 0; }
  fi
  [[ -f "$CLAUDE_SETTINGS" && -r "$CLAUDE_SETTINGS" ]] || return 0

  local has_sl
  has_sl=$(jq -r 'if (has("statusLine") and .statusLine != null) then "yes" else "no" end' \
             "$CLAUDE_SETTINGS" 2>/dev/null || true)
  [[ -z "$has_sl" ]] && has_sl="error"

  if [[ "$has_sl" == "yes" ]]; then
    HUD_LINES="  HUD: you already have a statusLine configured, so Canary left it
  alone. Say \"switch to the Canary statusline\" any time to enable the
  PII HUD instead."
    return 0
  fi

  if [[ "$has_sl" != "no" ]]; then
    # Couldn't confidently parse the existing file (malformed JSON, read
    # error, ...) — leave it alone and fall back to the manual snippet
    # rather than risk a bad merge.
    return 0
  fi

  # Back up ONCE, before the very first modification we ever make — never
  # overwrite an existing backup on a later run.
  if [[ ! -f "${CLAUDE_SETTINGS}.canary-bak" ]]; then
    cp "$CLAUDE_SETTINGS" "${CLAUDE_SETTINGS}.canary-bak" 2>/dev/null || true
  fi

  local hud_cmd="bash ${SONOMOS_DIR}/statusline.sh"
  local merge_tmp="${CLAUDE_SETTINGS}.tmp.$$"
  if jq --arg cmd "$hud_cmd" '.statusLine = {"type":"command","command":$cmd}' \
       "$CLAUDE_SETTINGS" > "$merge_tmp" 2>/dev/null && [[ -s "$merge_tmp" ]]; then
    if mv -f "$merge_tmp" "$CLAUDE_SETTINGS" 2>/dev/null; then
      chmod 644 "$CLAUDE_SETTINGS" 2>/dev/null || true
      HUD_LINES="  🐤 Canary HUD installed to your status bar."
    else
      rm -f "$merge_tmp" 2>/dev/null || true
    fi
  else
    rm -f "$merge_tmp" 2>/dev/null || true
  fi
}

# ── First run: show welcome ─────────────────────────────────────────────
if [[ ! -f "$SONOMOS_DIR/.initialized" ]]; then
  touch "$SONOMOS_DIR/.initialized" 2>/dev/null || true

  hud_autoinstall 2>/dev/null || true

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
  /canary:audit                  Scan your plugins/skills for leaked secrets

${HUD_LINES}

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
  TOTAL=$((TOTAL + ROLLUP_TOTAL))
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
LAST_WEEK=""
LAST_WEEK_TOTAL=0
if [[ -f "$STATE_FILE" ]]; then
  while IFS='=' read -r k v; do
    case "$k" in
      LAST_TOTAL)      [[ "$v" =~ ^[0-9]+$ ]] && LAST_TOTAL="$v" ;;
      CLEAN_STREAK)    [[ "$v" =~ ^[0-9]+$ ]] && CLEAN_STREAK="$v" ;;
      LAST_SESSION_ID) LAST_SESSION_ID="$v" ;;
      LAST_WEEK)       LAST_WEEK="$v" ;;
      LAST_WEEK_TOTAL) [[ "$v" =~ ^[0-9]+$ ]] && LAST_WEEK_TOTAL="$v" ;;
    esac
  done < "$STATE_FILE" 2>/dev/null || true
fi

# No leaks yet
if [[ ! -f "$LEAKS_FILE" || ! -s "$LEAKS_FILE" ]]; then
  TOTAL=0
  HIGH_CONF=0; REGEX_COUNT=0; LLM_COUNT=0; SESSIONS=0; NUM_TYPES=0; BREAKDOWN=""
  REPEAT_MAX=0; REPEAT_TYPE="NONE"
else
  # ── Single awk pass over leaks.jsonl (was ~6 separate jq passes) ───────
  # Same string-index technique as statusline.sh: no JSON parsing, just
  # substring search on each line. Line 1 of output is the tab-separated
  # summary (now also carrying the biggest value_id repeat-count + the
  # type it belongs to, for the "you've exposed the same X N times"
  # callout); remaining lines are the pre-formatted top-8 breakdown.
  AWK_OUT=$(awk '
    {
      total++
      t = ""; vid = ""
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

      vidi = index($0, "\"value_id\":\"")
      if (vidi > 0) {
        rest3 = substr($0, vidi + 12)
        vide = index(rest3, "\"")
        if (vide > 0) {
          vid = substr(rest3, 1, vide - 1)
          if (vid != "") {
            vidcount[vid]++
            if (t != "") vidtype[vid] = t
          }
        }
      }
    }
    END {
      num_types = 0
      for (t in types) num_types++
      num_sessions = 0
      for (s in sessions) num_sessions++

      repeat_max = 0; repeat_type = ""
      for (v in vidcount) {
        if (vidcount[v] > repeat_max) {
          repeat_max = vidcount[v]
          repeat_type = (v in vidtype) ? vidtype[v] : ""
        }
      }

      printf "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", total+0, high+0, regex+0, llm+0, \
        num_sessions+0, num_types+0, repeat_max+0, (repeat_type == "" ? "NONE" : repeat_type)

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
  IFS=$'\t' read -r TOTAL HIGH_CONF REGEX_COUNT LLM_COUNT SESSIONS NUM_TYPES REPEAT_MAX REPEAT_TYPE <<< "$SUMMARY_LINE"
  TOTAL=${TOTAL:-0}; HIGH_CONF=${HIGH_CONF:-0}; REGEX_COUNT=${REGEX_COUNT:-0}
  LLM_COUNT=${LLM_COUNT:-0}; SESSIONS=${SESSIONS:-0}; NUM_TYPES=${NUM_TYPES:-0}
  REPEAT_MAX=${REPEAT_MAX:-0}; REPEAT_TYPE=${REPEAT_TYPE:-NONE}
fi

# Lifetime total survives rotation: fold the rollup base in here too (this
# is the full-stats path; the jq-missing path above does the same thing).
TOTAL=$((TOTAL + ROLLUP_TOTAL))

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

# ── Repeat-value callout ─────────────────────────────────────────────────
# REPEAT_MAX/REPEAT_TYPE come from the awk pass above (max times any one
# value_id repeats, and the type it was detected as). >=3 repeats of the
# exact same value is worth calling out once — it's the highest-leverage
# single fix a user can make.
REPEAT_LINE=""
if [[ "$REPEAT_MAX" -ge 3 && "$REPEAT_TYPE" != "NONE" && -n "$REPEAT_TYPE" ]]; then
  REPEAT_LINE="  ↻ you've exposed the same ${REPEAT_TYPE} ${REPEAT_MAX} times — /canary:leaked"
fi

# ── Weekly digest (jq + taxonomy required; degrades to a silent no-op
# without either — this is a nice-to-have, never worth failing over) ────
# Fires once per ISO year-week (date +%G-%V), the first returning-user
# session after the week rolls over, and only when there's data. Compact
# by design: <=6 lines, one action tip, no repeat spam within the week.
CUR_WEEK=$(date +%G-%V 2>/dev/null) || CUR_WEEK=""
NEW_LAST_WEEK="$LAST_WEEK"
NEW_LAST_WEEK_TOTAL="$LAST_WEEK_TOTAL"
DIGEST_LINES=""
TAXONOMY_FILE="$SCRIPT_DIR/taxonomy.json"

if [[ -n "$CUR_WEEK" ]]; then
  if [[ -z "$LAST_WEEK" ]]; then
    # First time we've ever tracked a week — seed silently, no digest yet
    # (there is no "last week" to compare against).
    NEW_LAST_WEEK="$CUR_WEEK"
  elif [[ "$CUR_WEEK" != "$LAST_WEEK" ]]; then
    NEW_LAST_WEEK="$CUR_WEEK"
    if [[ "$TOTAL" -gt 0 && -f "$TAXONOMY_FILE" && -r "$TAXONOMY_FILE" ]]; then
      # Start-of-this-ISO-week epoch (local midnight, Monday). GNU `date -d`
      # first, BSD `date -j -f` fallback — same dual-path idiom statusline.sh
      # uses for its last-hit-age conversion. DOW: 1=Monday..7=Sunday.
      TODAY_MID=$(date "+%Y-%m-%d" 2>/dev/null) || TODAY_MID=""
      DOW=$(date +%u 2>/dev/null) || DOW=""
      WEEK_START_EPOCH=""
      if [[ -n "$TODAY_MID" && "$DOW" =~ ^[0-9]+$ ]]; then
        TODAY_EPOCH=$(date -d "$TODAY_MID" +%s 2>/dev/null || \
                      date -j -f "%Y-%m-%d" "$TODAY_MID" +%s 2>/dev/null || true)
        if [[ "$TODAY_EPOCH" =~ ^[0-9]+$ ]]; then
          WEEK_START_EPOCH=$((TODAY_EPOCH - (DOW - 1) * 86400))
        fi
      fi

      if [[ -n "$WEEK_START_EPOCH" ]]; then
        # jq does the heavy lifting: filter this week's records by parsed
        # timestamp, weight them per taxonomy.json's own _scoring contract
        # (same algorithm canary-badge implements), and emit one TSV line.
        # `def band(...)` deliberately avoids the $-param sugar (jq 1.6+
        # only) for wider jq-version compatibility.
        JQ_PROGRAM=$(cat <<'JQEOF'
def band(bands; fb; s): (([ bands[] | select(.max >= s) ] | .[0].grade) // fb);
($TAXO[0] // {}) as $tx
| ($tx.confidence_multiplier // {"high":1,"medium":0.6,"low":0.3,"certain":1}) as $cm
| ($tx.types // {}) as $types
| (($tx.default // {}).risk_weight // 3) as $defw
| ($tx.grade_bands // [{"grade":"A+","max":0},{"grade":"A","max":8},{"grade":"B","max":25},{"grade":"C","max":75},{"grade":"D","max":250}]) as $bands
| ($tx.grade_fallback // "F") as $fb
| [ inputs
    | select(type=="object" and (.timestamp? != null) and (.type? != null))
    | . as $r
    | ($r.timestamp | try (strptime("%Y-%m-%dT%H:%M:%SZ") | mktime) catch null) as $ep
    | select($ep != null and $ep >= $wstart)
    | { type: $r.type, w: ( ((($types[$r.type].risk_weight)) // $defw) * ($cm[$r.confidence] // 1) ) }
  ] as $week
| ($week | length) as $total
| ($week | map(.w) | add // 0) as $score
| ($week | group_by(.type) | map({type: .[0].type, count: length, w: (map(.w) | add)}) | sort_by(-.count)) as $groups
| ($groups[0]) as $g1
| ($groups[1]) as $g2
| ($groups[2]) as $g3
| ($score - (($g1.w) // 0)) as $score_wo
| [ ($total|tostring), band($bands; $fb; $score),
    (($g1.type) // ""), ((($g1.count) // 0) | tostring),
    (($g2.type) // ""), ((($g2.count) // 0) | tostring),
    (($g3.type) // ""), ((($g3.count) // 0) | tostring),
    band($bands; $fb; $score_wo) ]
| @tsv
JQEOF
        )
        DIGEST_TSV=$(jq -nr --argjson wstart "$WEEK_START_EPOCH" \
                       --slurpfile TAXO "$TAXONOMY_FILE" \
                       "$JQ_PROGRAM" "$LEAKS_FILE" 2>/dev/null) || DIGEST_TSV=""

        if [[ -n "$DIGEST_TSV" ]]; then
          IFS=$'\t' read -r D_TOTAL D_GRADE D_T1 D_C1 D_T2 D_C2 D_T3 D_C3 D_GRADE_WO <<< "$DIGEST_TSV"
          if [[ "$D_TOTAL" =~ ^[0-9]+$ ]]; then
            DELTA=$((D_TOTAL - LAST_WEEK_TOTAL))
            if   [[ "$DELTA" -gt 0 ]]; then DELTA_TXT="+${DELTA}"
            elif [[ "$DELTA" -lt 0 ]]; then DELTA_TXT="${DELTA}"
            else DELTA_TXT="±0"
            fi

            TOP_TXT=""
            for PAIR in "${D_T1}:${D_C1}" "${D_T2}:${D_C2}" "${D_T3}:${D_C3}"; do
              TY="${PAIR%%:*}"
              [[ -z "$TY" ]] && continue
              CT="${PAIR#*:}"
              if [[ -n "$TOP_TXT" ]]; then TOP_TXT="${TOP_TXT} ${TY}(${CT})"; else TOP_TXT="${TY}(${CT})"; fi
            done

            DIGEST_LINES="━━━ 📅 Weekly digest ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  This week: ${D_TOTAL} exposure(s) · grade ${D_GRADE} (${DELTA_TXT} vs last week)"
            [[ -n "$TOP_TXT" ]] && DIGEST_LINES="${DIGEST_LINES}
  Top: ${TOP_TXT}"
            if [[ -n "$D_T1" ]]; then
              if [[ -n "$D_GRADE_WO" && "$D_GRADE_WO" != "$D_GRADE" ]]; then
                DIGEST_LINES="${DIGEST_LINES}
  ↳ Most exposed: ${D_T1}. Stop pasting it and your grade rises to ${D_GRADE_WO}."
              else
                DIGEST_LINES="${DIGEST_LINES}
  ↳ Most exposed: ${D_T1}. That's the one to cut first."
              fi
            fi
            DIGEST_LINES="${DIGEST_LINES}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

            NEW_LAST_WEEK_TOTAL="$D_TOTAL"
          fi
        fi
      fi
    fi
  fi
fi

# Persist state (atomic temp+mv). LAST_TOTAL/LAST_SESSION_ID always
# refresh to the current values; only CLEAN_STREAK's evolution is gated
# above by IS_NEW_SESSION. LAST_WEEK/LAST_WEEK_TOTAL drive the weekly
# digest above.
STATE_TMP="${STATE_FILE}.tmp.$$"
{
  printf 'LAST_TOTAL=%s\n' "$TOTAL"
  printf 'CLEAN_STREAK=%s\n' "$CLEAN_STREAK"
  printf 'LAST_SESSION_ID=%s\n' "$SESSION_ID"
  printf 'LAST_WEEK=%s\n' "$NEW_LAST_WEEK"
  printf 'LAST_WEEK_TOTAL=%s\n' "$NEW_LAST_WEEK_TOTAL"
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
[[ -n "$REPEAT_LINE" ]] && echo "$REPEAT_LINE"
echo ""
echo "  Top categories:"
echo "${BREAKDOWN}"
echo ""
echo "  ${DASH_STATUS}"
echo "  /canary:leaked → dashboard │ /canary:scan → deep audit │ /canary:audit → check extensions"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[[ -n "$DIGEST_LINES" ]] && echo "$DIGEST_LINES"

exit 0
