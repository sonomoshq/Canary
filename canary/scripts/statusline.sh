#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# statusline.sh — Rich HUD for Claude Code status bar.
# Displays a persistent, auto-updating PII dashboard below the input line.
# Reads $SONOMOS_DIR/leaks.jsonl on every render cycle for real-time counts,
# with an mtime+size keyed cache so steady-state renders are O(1).
#
# Configure in settings.json:
#   "statusLine": {"type":"command","command":"bash ~/.sonomos/statusline.sh"}
#
# Layout modes (env CANARY_HUD_MODE):
#   full     — framed 4-5 line HUD (default)
#   compact  — single line, no frame
#   If COLUMNS is set and < 80, full auto-degrades to compact.
#
# HUD elements:
#   - PII counter (severity color + colorblind glyph: ✓ 0 / ▲ 1-9 / ‼ 10+)
#   - High-confidence count, session delta (▲N), type diversity, last-hit age
#   - Detection breakdown (regex / llm / audit) + file-sourced hits (files:N)
#   - Top 3 exposure categories
#   - Claude Code superset segments from stdin JSON: model name, git branch
#     (read from .git/HEAD as a file — no git subprocess), context-window
#     bar (green <70 / yellow <85 / red ≥85), session cost
#   - Clean-streak segment (🟢 streak:N) from $SONOMOS_DIR/.state
#   - Dashboard file link + skill shortcuts (/canary:leaked, /canary:scan)
#
# Robustness contract: this script must NEVER exit non-zero or print an
# error — every external command is guarded. jq is OPTIONAL; without it the
# HUD gracefully degrades (see the aggregation section for the limitation).

set -euo pipefail
umask 0077
export LC_ALL=C

# ${HOME:-/tmp} guard: a missing HOME must degrade (empty zero-state HUD),
# never crash under set -u.
SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-${HOME:-/tmp}/.sonomos}"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
DASHBOARD_FILE="$SONOMOS_DIR/dashboard.html"
CACHE_FILE="$SONOMOS_DIR/.hud_cache"
STATE_FILE="$SONOMOS_DIR/.state"

# ── ANSI escape codes ($'...' for real escape bytes) ───────────
DIM=$'\033[2m'
RST=$'\033[0m'
B=$'\033[1m'
RED=$'\033[31m'
GRN=$'\033[32m'
YLW=$'\033[33m'
CYN=$'\033[36m'
MAG=$'\033[35m'
BRED=$'\033[1;31m'
BGRN=$'\033[1;32m'
BYLW=$'\033[1;33m'
BCYN=$'\033[1;36m'

# ── Colorblind-safe severity glyphs (paired with color) ────────
G_OK="✓"      # 0 detections
G_WARN="▲"    # 1-9
G_CRIT="‼"    # 10+

# ── Separators ─────────────────────────────────────────────────
BAR="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
FULL_BAR="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Validation regexes (kept in vars — bash 3.2 [[ =~ ]] quirk) ─
NUM_RE='^[0-9]+$'
PCT_RE='^[0-9]+(\.[0-9]+)?$'
COST_RE='^[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$'
HEX_RE='^[0-9a-fA-F]{40}'
KEY_RE='^[0-9]+:[0-9]+$'
# Cached stats: 9 numeric fields (total high regex llm audit files sess
# types last_epoch) followed by the top-types remainder:
STATS_RE='^[0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ .'
# Raw awk output: field 9 is an ISO timestamp or NONE:
RAWSTATS_RE='^[0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [^ ]+ .'

# ── Layout mode ────────────────────────────────────────────────
MODE="full"
if [[ "${CANARY_HUD_MODE:-}" == "compact" ]]; then
  MODE="compact"
fi
# Narrow terminals can't fit the frame — auto-degrade full → compact.
if [[ "$MODE" == "full" && -n "${COLUMNS:-}" ]]; then
  if [[ "$COLUMNS" =~ $NUM_RE ]] && [[ "$COLUMNS" -lt 80 ]]; then
    MODE="compact"
  fi
fi

HAS_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAS_JQ=1
fi

# ── Read stdin (session JSON from Claude Code) ─────────────────
# Builtin read (no subprocess); non-zero at EOF is expected.
INPUT=""
IFS= read -r -d '' INPUT || true

SESSION_ID=""
MODEL_NAME=""
CWD_DIR=""
COST_USD=""
CTX_PCT=""
if [[ -n "$INPUT" ]]; then
  PARSED=""
  # Fields are joined with the ASCII unit separator (\037): unlike tab it
  # is not IFS whitespace, so empty middle fields survive the read below
  # (consecutive tabs would collapse and shift values left).
  if [[ "$HAS_JQ" -eq 1 ]]; then
    # Trailing '?' suppresses type errors (e.g. .model is a string);
    # a hard parse failure just leaves every field empty.
    PARSED=$(printf '%s' "$INPUT" | jq -r '[
        (.session_id? // ""),
        (.model.display_name? // ""),
        (.workspace.current_dir? // .cwd? // ""),
        (.cost.total_cost_usd? // ""),
        (.context_window.used_percentage? // "")
      ] | map(tostring) | join("\u001f")' 2>/dev/null) || PARSED=""
  else
    # No jq: naive single-pass awk field grabber. Good enough for the
    # compact machine-generated JSON Claude Code pipes in; values that
    # contain escaped quotes are truncated at the first quote.
    PARSED=$(printf '%s' "$INPUT" | awk '
      { buf = buf $0 " " }
      END {
        cwd = gstr(buf, "\"current_dir\"")
        if (cwd == "") cwd = gstr(buf, "\"cwd\"")
        printf "%s\037%s\037%s\037%s\037%s", \
          gstr(buf, "\"session_id\""), gstr(buf, "\"display_name\""), \
          cwd, gnum(buf, "\"total_cost_usd\""), gnum(buf, "\"used_percentage\"")
      }
      function gstr(s, k,   i, r, j) {
        i = index(s, k); if (!i) return ""
        r = substr(s, i + length(k))
        if (match(r, /^[ \t]*:[ \t]*"/)) {
          r = substr(r, RLENGTH + 1)
          j = index(r, "\"")
          if (j) return substr(r, 1, j - 1)
        }
        return ""
      }
      function gnum(s, k,   i, r) {
        i = index(s, k); if (!i) return ""
        r = substr(s, i + length(k))
        if (match(r, /^[ \t]*:[ \t]*/)) {
          r = substr(r, RLENGTH + 1)
          if (match(r, /^[0-9][0-9.eE+-]*/)) return substr(r, 1, RLENGTH)
        }
        return ""
      }
    ' 2>/dev/null) || PARSED=""
  fi
  IFS=$'\037' read -r SESSION_ID MODEL_NAME CWD_DIR COST_USD CTX_PCT <<< "$PARSED" || true
fi

# Sanitize anything we print or embed (strip ESC/CR, bound length).
SESSION_ID=${SESSION_ID//[^a-zA-Z0-9._-]/}
SESSION_ID=${SESSION_ID:0:64}
MODEL_NAME=${MODEL_NAME//$'\033'/}
MODEL_NAME=${MODEL_NAME//$'\r'/}
MODEL_NAME=${MODEL_NAME:0:24}

# ── Superset segment: git branch (file read only — no subprocess)
GIT_BRANCH=""
if [[ -n "$CWD_DIR" && -d "$CWD_DIR" ]]; then
  HEAD_FILE=""
  if [[ -d "$CWD_DIR/.git" ]]; then
    HEAD_FILE="$CWD_DIR/.git/HEAD"
  elif [[ -f "$CWD_DIR/.git" && -r "$CWD_DIR/.git" ]]; then
    # Worktree/submodule: .git is a pointer file "gitdir: <path>".
    GD_LINE=""
    IFS= read -r GD_LINE 2>/dev/null < "$CWD_DIR/.git" || true
    case "$GD_LINE" in
      gitdir:*)
        GD_PATH="${GD_LINE#gitdir:}"
        GD_PATH="${GD_PATH# }"
        if [[ "$GD_PATH" != /* ]]; then GD_PATH="$CWD_DIR/$GD_PATH"; fi
        HEAD_FILE="$GD_PATH/HEAD"
        ;;
    esac
  fi
  if [[ -n "$HEAD_FILE" && -f "$HEAD_FILE" && -r "$HEAD_FILE" ]]; then
    HEAD_LINE=""
    IFS= read -r HEAD_LINE 2>/dev/null < "$HEAD_FILE" || true
    case "$HEAD_LINE" in
      "ref: refs/heads/"*) GIT_BRANCH="${HEAD_LINE#ref: refs/heads/}" ;;
      *)  # Detached HEAD: bare commit hash → first 7 chars.
        if [[ "$HEAD_LINE" =~ $HEX_RE ]]; then GIT_BRANCH="${HEAD_LINE:0:7}"; fi
        ;;
    esac
    GIT_BRANCH=${GIT_BRANCH//$'\033'/}
    GIT_BRANCH=${GIT_BRANCH//$'\r'/}
    GIT_BRANCH=${GIT_BRANCH:0:40}
  fi
fi

# ── Superset segment: context-window bar (6 chars + percent) ───
CTX_SEG=""
if [[ -n "$CTX_PCT" ]] && [[ "$CTX_PCT" =~ $PCT_RE ]]; then
  CTX_INT="${CTX_PCT%%.*}"
  if [[ ! "$CTX_INT" =~ $NUM_RE ]]; then CTX_INT=0; fi
  if [[ "$CTX_INT" -gt 100 ]]; then CTX_INT=100; fi
  CTX_FILL=$(( (CTX_INT * 6 + 50) / 100 ))
  if [[ "$CTX_FILL" -gt 6 ]]; then CTX_FILL=6; fi
  case "$CTX_FILL" in
    0) CTX_BAR="░░░░░░" ;;
    1) CTX_BAR="█░░░░░" ;;
    2) CTX_BAR="██░░░░" ;;
    3) CTX_BAR="███░░░" ;;
    4) CTX_BAR="████░░" ;;
    5) CTX_BAR="█████░" ;;
    *) CTX_BAR="██████" ;;
  esac
  if   [[ "$CTX_INT" -lt 70 ]]; then CTX_COLOR="$GRN"
  elif [[ "$CTX_INT" -lt 85 ]]; then CTX_COLOR="$YLW"
  else                               CTX_COLOR="$RED"
  fi
  CTX_SEG="${CTX_COLOR}${CTX_BAR} ${CTX_INT}%${RST}"
fi

# ── Superset segment: session cost ($X.XX when > 0) ────────────
COST_TXT=""
if [[ -n "$COST_USD" ]] && [[ "$COST_USD" =~ $COST_RE ]]; then
  COST_FMT=""
  if printf -v COST_FMT '%.2f' "$COST_USD" 2>/dev/null; then
    if [[ -n "$COST_FMT" && "$COST_FMT" != "0.00" ]]; then
      COST_TXT="\$${COST_FMT}"
    fi
  fi
fi

# ── Superset segments: model / branch text ─────────────────────
MODEL_TXT=""
if [[ -n "$MODEL_NAME" ]]; then
  MODEL_TXT="✳ ${MODEL_NAME}"
fi
GIT_TXT=""
if [[ -n "$GIT_BRANCH" ]]; then
  GIT_TXT="⎇ ${GIT_BRANCH}"
fi

# ── Clean streak from $SONOMOS_DIR/.state (parsed, never sourced)
# Pure-bash KEY=VALUE scan: equivalent to grep/cut but fork-free — the two
# extra processes would blow the <15ms cached-render budget. First match
# wins; scan is bounded to 64 lines.
STREAK_TXT=""
if [[ -f "$STATE_FILE" && -r "$STATE_FILE" ]]; then
  STREAK_VAL=""
  SL_N=0
  while IFS= read -r SL_LINE || [[ -n "$SL_LINE" ]]; do
    case "$SL_LINE" in
      CLEAN_STREAK=*) STREAK_VAL="${SL_LINE#CLEAN_STREAK=}"; break ;;
    esac
    SL_N=$((SL_N + 1))
    if [[ "$SL_N" -ge 64 ]]; then break; fi
  done 2>/dev/null < "$STATE_FILE" || true
  STREAK_VAL=${STREAK_VAL//\"/}
  STREAK_VAL=${STREAK_VAL//\'/}
  STREAK_VAL=${STREAK_VAL//$'\r'/}
  STREAK_VAL=${STREAK_VAL:0:9}
  if [[ "$STREAK_VAL" =~ $NUM_RE ]] && [[ "$STREAK_VAL" -ge 2 ]]; then
    STREAK_TXT="🟢 streak:${STREAK_VAL}"
  fi
fi

# ── Segment joiner (bash 3.2 friendly — no arrays) ─────────────
JOINED=""
jadd() {
  if [[ -z "$1" ]]; then return 0; fi
  if [[ -n "$JOINED" ]]; then JOINED="${JOINED} │ $1"; else JOINED="$1"; fi
}

# Model / git / context / cost, dim-wrapped (bar keeps its own color).
# Sets EXTRAS_LINE (no subshell — keeps the hot path fork-free).
EXTRAS_LINE=""
build_extras() {
  JOINED=""
  if [[ -n "$MODEL_TXT" ]]; then jadd "${DIM}${MODEL_TXT}${RST}"; fi
  if [[ -n "$GIT_TXT" ]]; then jadd "${DIM}${GIT_TXT}${RST}"; fi
  jadd "$CTX_SEG"
  if [[ -n "$COST_TXT" ]]; then jadd "${DIM}${COST_TXT}${RST}"; fi
  EXTRAS_LINE="$JOINED"
}
build_extras

# ── Dashboard indicator (actual data dir — not hardcoded) ──────
DASH_DISPLAY="$SONOMOS_DIR/dashboard.html"
if [[ -n "${HOME:-}" && "$DASH_DISPLAY" == "$HOME"/* ]]; then
  DASH_DISPLAY="~${DASH_DISPLAY#"$HOME"}"
fi
if [[ -f "$DASHBOARD_FILE" ]]; then
  DASH_SEG="${DIM}📊 ${DASH_DISPLAY}${RST}"
else
  DASH_SEG="${DIM}📊 /canary:leaked → generate${RST}"
fi

# ── Zero-state renderer (pretty output, both modes) ────────────
render_zero() {
  local streak_full=""
  if [[ -n "$STREAK_TXT" ]]; then
    streak_full=" │ ${DIM}${STREAK_TXT}${RST}"
  fi
  if [[ "$MODE" == "compact" ]]; then
    JOINED=""
    jadd "🐤 ${BGRN}0 PII ${G_OK}${RST}"
    if [[ -n "$MODEL_TXT" ]]; then jadd "${DIM}${MODEL_TXT}${RST}"; fi
    if [[ -n "$GIT_TXT" ]]; then jadd "${DIM}${GIT_TXT}${RST}"; fi
    jadd "$CTX_SEG"
    if [[ -n "$COST_TXT" ]]; then jadd "${DIM}${COST_TXT}${RST}"; fi
    if [[ -n "$STREAK_TXT" ]]; then jadd "${DIM}${STREAK_TXT}${RST}"; fi
    printf '%s' "$JOINED"
  else
    printf '%s━━━ %s🐤 CANARY%s %s%s%s\n' "$DIM" "$BGRN" "$RST" "$DIM" "$BAR" "$RST"
    printf ' %s0 PII %s%s │ monitoring active │ %s/canary:leaked%s · %s/canary:scan%s%s\n' \
      "$BGRN" "$G_OK" "$RST" "$DIM" "$RST" "$DIM" "$RST" "$streak_full"
    if [[ -n "$EXTRAS_LINE" ]]; then
      printf ' %s\n' "$EXTRAS_LINE"
    fi
    printf '%s%s%s' "$DIM" "$FULL_BAR" "$RST"
  fi
  exit 0
}

# ── Zero-detection state (no data file yet) ────────────────────
if [[ ! -f "$LEAKS_FILE" || ! -s "$LEAKS_FILE" ]]; then
  render_zero
fi

# ── Cache key: leaks mtime + size + session id ─────────────────
# stat -f %m/%z (BSD) first, stat -c %Y/%s (GNU) fallback. The result is
# validated because GNU's stat -f "succeeds" with FILESYSTEM info (its %m
# is the mount point) — a numeric check routes GNU boxes to stat -c.
FS_KEY=$(stat -f '%m:%z' "$LEAKS_FILE" 2>/dev/null) || FS_KEY=""
if [[ ! "$FS_KEY" =~ $KEY_RE ]]; then
  FS_KEY=$(stat -c '%Y:%s' "$LEAKS_FILE" 2>/dev/null) || FS_KEY=""
fi
if [[ ! "$FS_KEY" =~ $KEY_RE ]]; then
  FS_KEY="0:0"
fi
CACHE_KEY="${FS_KEY}:${SESSION_ID}"

# ── Cache probe: line 1 = key, line 2 = stats ──────────────────
# Hit ⇒ skip the whole aggregation pass (O(1) render).
STATS_LINE=""
if [[ "$FS_KEY" != "0:0" && -f "$CACHE_FILE" && -r "$CACHE_FILE" ]]; then
  C_KEY=""
  C_STATS=""
  { IFS= read -r C_KEY && IFS= read -r C_STATS; } 2>/dev/null < "$CACHE_FILE" || true
  if [[ "$C_KEY" == "$CACHE_KEY" ]] && [[ "$C_STATS" =~ $STATS_RE ]]; then
    STATS_LINE="$C_STATS"
  fi
fi

# ── Cache miss: single-pass awk aggregation ────────────────────
if [[ -z "$STATS_LINE" ]]; then
  # Shared aggregator. Exact when input is ONE compact JSON object per
  # line. Computes: total, high-confidence, detector counts (regex/llm/
  # audit), file-sourced hits (source:"file:…"), this-session hits,
  # distinct types, top 3 types, last record timestamp.
  #
  # It also emits a leading canonical flag (0/1): 0 means every record
  # line already had the canonical compact shape — starts "{", ends "}",
  # no whitespace around a key colon — i.e. the file is byte-stable under
  # jq -c for matching purposes, so its stats are exact without a jq
  # normalization pass. Anything suspicious sets 1 (a value string that
  # merely CONTAINS a spaced colon can false-positive the flag — that
  # only costs the jq pass below, never correctness).
  AGG='
  BEGIN { bad=0; total=0; high=0; rgx=0; llm=0; aud=0; fsrc=0; sess=0; last_ts="" }
  {
    # Blank lines are ignored; non-object lines (JSON scalars, garbage,
    # pretty-print fragments) are dropped and mark the file non-canonical.
    if ($0 ~ /^[[:space:]]*$/) next
    if ($0 !~ /^[[:space:]]*\{/) { bad=1; next }
    if ($0 !~ /\}[[:space:]]*$/) bad=1
    else if (index($0, "\": ") || index($0, "\":\t") || index($0, "\" :")) bad=1
    total++

    # confidence
    if (index($0, "\"confidence\":\"high\"")) high++

    # detector
    if      (index($0, "\"detector\":\"regex\"")) rgx++
    else if (index($0, "\"detector\":\"llm\""))   llm++
    else if (index($0, "\"detector\":\"audit\"")) aud++

    # per-source split: hits recorded from written/edited files
    if (index($0, "\"source\":\"file:")) fsrc++

    # session
    if (sid != "" && index($0, "\"session_id\":\"" sid "\"")) sess++

    # type — extract with simple string ops
    ti = index($0, "\"type\":\"")
    if (ti > 0) {
      rest = substr($0, ti + 8)
      te = index(rest, "\"")
      if (te > 0) types[substr(rest, 1, te - 1)]++
    }

    # timestamp — overwritten each record, final value wins
    tsi = index($0, "\"timestamp\":\"")
    if (tsi > 0) {
      rest2 = substr($0, tsi + 13)
      tse = index(rest2, "\"")
      if (tse > 0) last_ts = substr(rest2, 1, tse - 1)
    }
  }
  END {
    # Count distinct types
    num_types = 0
    for (t in types) num_types++

    # Top 3 types by count (simple selection sort for 3 elements)
    top = ""
    for (pass = 1; pass <= 3; pass++) {
      best = ""; best_ct = 0
      for (t in types) {
        if (types[t] > best_ct) { best = t; best_ct = types[t] }
      }
      if (best != "") {
        if (top != "") top = top " "
        top = top best "(" best_ct ")"
        delete types[best]
      }
    }

    printf "%d %d %d %d %d %d %d %d %d %s %s\n", \
      bad, total, high, rgx, llm, aud, fsrc, sess, num_types, \
      (last_ts != "" ? last_ts : "NONE"), \
      (top != "" ? top : "NONE")
  }'

  # Pass A: one raw awk pass over the file. If the canonical flag comes
  # back 0 these stats are exact and no jq work is needed at all — this is
  # the overwhelmingly common case (our own writers only append jq -c
  # output) and keeps a 10k-row cold render ~3x under its time budget.
  PROBE=$(awk -v sid="$SESSION_ID" "$AGG" "$LEAKS_FILE" 2>/dev/null) || PROBE=""
  PROBE_FLAG="${PROBE%% *}"
  RAW_STATS="${PROBE#* }"

  if [[ "$PROBE_FLAG" != "0" && "$HAS_JQ" -eq 1 ]]; then
    # Non-canonical file: normalize to compact JSON so string matching is
    # exact even for pretty-printed / re-saved files (fixes the 110→886
    # count inflation and zeroed stats). Two tiers:
    #   1) jq -c .             — whole-stream parse; reassembles multi-line
    #      (pretty-printed) records, but aborts at the first malformed byte;
    #   2) jq -cR "fromjson?"  — line-oriented rescue when tier 1 exits
    #      non-zero: skips garbage lines, never aborts (multi-line records
    #      are lost, acceptable for an already-corrupted file).
    # Direct pipelines (not a captured variable): buffering ~1.5MB through
    # a bash variable costs ~35ms at 10k rows. pipefail is set, so a
    # mid-stream jq abort fails the assignment even though awk consumed
    # the partial stream — the partial result is discarded, tier 2 reruns.
    RAW_STATS=$(jq -c . "$LEAKS_FILE" 2>/dev/null | \
                awk -v sid="$SESSION_ID" "$AGG" 2>/dev/null) || RAW_STATS=""
    RAW_STATS="${RAW_STATS#* }"
    if [[ -z "$RAW_STATS" ]]; then
      RAW_STATS=$(jq -cR 'fromjson? // empty' "$LEAKS_FILE" 2>/dev/null | \
                  awk -v sid="$SESSION_ID" "$AGG" 2>/dev/null) || RAW_STATS=""
      RAW_STATS="${RAW_STATS#* }"
    fi
  fi
  # LIMITATION (no-jq path): without jq a non-canonical file keeps the
  # pass-A stats — raw per-line string matching assumes the canonical
  # compact one-object-per-line format our writers append. On a
  # pretty-printed / re-saved file the total stays correct (each record
  # contributes exactly one "{" opener line) but the field-level stats
  # read as zero, because fields land on fragment lines with
  # "key": "value" spacing that the compact matchers don't recognize.
  if [[ ! "$RAW_STATS" =~ $RAWSTATS_RE ]]; then
    RAW_STATS="0 0 0 0 0 0 0 0 NONE NONE"
  fi

  read -r A_TOT A_HIGH A_RGX A_LLM A_AUD A_FSRC A_SESS A_NT A_TS A_TOP <<< "$RAW_STATS" || true

  # Convert the last-hit timestamp to epoch once (GNU date -d first,
  # BSD date -j fallback, pinned to UTC) so cached renders never
  # re-parse ISO time.
  LAST_EPOCH=0
  if [[ -n "$A_TS" && "$A_TS" != "NONE" ]]; then
    LAST_EPOCH=$(date -d "$A_TS" +%s 2>/dev/null || \
                 TZ=UTC0 date -j -f "%Y-%m-%dT%H:%M:%SZ" "$A_TS" +%s 2>/dev/null || echo 0)
    if [[ ! "$LAST_EPOCH" =~ $NUM_RE ]]; then LAST_EPOCH=0; fi
  fi

  STATS_LINE="$A_TOT $A_HIGH $A_RGX $A_LLM $A_AUD $A_FSRC $A_SESS $A_NT $LAST_EPOCH $A_TOP"

  # Persist cache (0600, atomic rename). Skip caching a zero result for a
  # non-empty file — that usually means a transient read failure.
  LEAKS_SIZE="${FS_KEY#*:}"
  if [[ "$FS_KEY" != "0:0" ]] && [[ "$A_TOT" != "0" || "$LEAKS_SIZE" == "0" ]]; then
    CACHE_TMP="${CACHE_FILE}.$$"
    if { printf '%s\n%s\n' "$CACHE_KEY" "$STATS_LINE" > "$CACHE_TMP" && \
         chmod 600 "$CACHE_TMP" && \
         mv -f "$CACHE_TMP" "$CACHE_FILE"; } 2>/dev/null; then
      :
    else
      rm -f "$CACHE_TMP" 2>/dev/null || true
    fi
  fi
fi

# ── Unpack stats (defensive defaults keep printf %s safe) ──────
TOTAL=0; HIGH=0; REGEX_CT=0; LLM_CT=0; AUDIT_CT=0; FILESRC_CT=0
SESS_CT=0; NUM_TYPES=0; LAST_EPOCH=0; TOP_TYPES_RAW="NONE"
read -r TOTAL HIGH REGEX_CT LLM_CT AUDIT_CT FILESRC_CT SESS_CT NUM_TYPES LAST_EPOCH TOP_TYPES_RAW <<< "$STATS_LINE" || true
TOTAL=${TOTAL:-0}; HIGH=${HIGH:-0}; REGEX_CT=${REGEX_CT:-0}; LLM_CT=${LLM_CT:-0}
AUDIT_CT=${AUDIT_CT:-0}; FILESRC_CT=${FILESRC_CT:-0}; SESS_CT=${SESS_CT:-0}
NUM_TYPES=${NUM_TYPES:-0}; LAST_EPOCH=${LAST_EPOCH:-0}; TOP_TYPES_RAW=${TOP_TYPES_RAW:-NONE}

# File exists but holds no valid records → same pretty zero state.
if [[ "$TOTAL" == "0" ]]; then
  render_zero
fi

TOP_TYPES=""
if [[ "$TOP_TYPES_RAW" != "NONE" && -n "$TOP_TYPES_RAW" ]]; then
  TOP_TYPES=${TOP_TYPES_RAW//$'\033'/}
fi

# ── Last-hit relative age (epoch math only — cache-friendly) ───
LAST_AGO=""
if [[ "$LAST_EPOCH" -gt 0 ]]; then
  NOW="${EPOCHSECONDS:-}"
  if [[ ! "$NOW" =~ $NUM_RE ]]; then NOW=$(date +%s 2>/dev/null) || NOW=0; fi
  if [[ "$NOW" =~ $NUM_RE ]] && [[ "$NOW" -ge "$LAST_EPOCH" ]]; then
    D=$((NOW - LAST_EPOCH))
    if   [[ $D -lt 60 ]];    then LAST_AGO="${D}s ago"
    elif [[ $D -lt 3600 ]];  then LAST_AGO="$((D/60))m ago"
    elif [[ $D -lt 86400 ]]; then LAST_AGO="$((D/3600))h ago"
    else                          LAST_AGO="$((D/86400))d ago"
    fi
  fi
fi

# ── Severity color + glyph (0 ✓ green / 1-9 ▲ yellow / 10+ ‼ red)
# TOTAL is ≥ 1 here (0 rendered above as zero state).
if   [[ "$TOTAL" -lt 10 ]]; then SC="$BYLW"; HC="$YLW"; GLYPH="$G_WARN"
else                             SC="$BRED"; HC="$RED"; GLYPH="$G_CRIT"
fi

# ── Session delta segment ──────────────────────────────────────
SESS_SEG=""
if [[ "$SESS_CT" -gt 0 ]]; then
  SESS_SEG=" │ ${MAG}▲${SESS_CT} session${RST}"
fi

# ── Streak segment (only when this session is clean) ───────────
STREAK_SEG=""
if [[ -n "$STREAK_TXT" && "$SESS_CT" -eq 0 ]]; then
  STREAK_SEG=" │ ${DIM}${STREAK_TXT}${RST}"
fi

# ── Detector breakdown (regex · llm · audit · files) ───────────
DET_PARTS=""
dadd() {
  if [[ -n "$DET_PARTS" ]]; then DET_PARTS="${DET_PARTS} · $1"; else DET_PARTS="$1"; fi
}
if [[ "$REGEX_CT" -gt 0 ]]; then dadd "regex:${REGEX_CT}"; fi
if [[ "$LLM_CT" -gt 0 ]]; then dadd "llm:${LLM_CT}"; fi
if [[ "$AUDIT_CT" -gt 0 ]]; then dadd "audit:${AUDIT_CT}"; fi
if [[ "$FILESRC_CT" -gt 0 ]]; then dadd "files:${FILESRC_CT}"; fi

# ── Last-hit segment ───────────────────────────────────────────
LAST_SEG=""
if [[ -n "$LAST_AGO" ]]; then
  LAST_SEG=" │ ${DIM}last: ${LAST_AGO}${RST}"
fi

# ══════════════════════════════════════════════════════════════
#  RENDER HUD
# ══════════════════════════════════════════════════════════════

if [[ "$MODE" == "compact" ]]; then
  # Single line, no frame: pack only non-empty segments.
  COMPACT="🐤 ${SC}${TOTAL} PII ${GLYPH}${RST}"
  if [[ "$SESS_CT" -gt 0 ]]; then
    COMPACT="${COMPACT} ${MAG}▲${SESS_CT}${RST}"
  fi
  JOINED="$COMPACT"
  jadd "$MODEL_TXT"
  jadd "$GIT_TXT"
  jadd "$CTX_SEG"
  jadd "$COST_TXT"
  if [[ -n "$TOP_TYPES" ]]; then
    TOP1="${TOP_TYPES%% *}"
    TOP1="${TOP1%%(*}"
    if [[ -n "$TOP1" ]]; then jadd "${DIM}top: ${TOP1}${RST}"; fi
  fi
  if [[ -n "$STREAK_TXT" && "$SESS_CT" -eq 0 ]]; then
    jadd "${DIM}${STREAK_TXT}${RST}"
  fi
  printf '%s' "$JOINED"
  exit 0
fi

# Line 1: Header bar with branding (severity-colored)
printf '%s━━━ %s🐤 CANARY%s %s%s%s\n' "$DIM" "${B}${HC}" "$RST" "$DIM" "$BAR" "$RST"

# Line 2: Core counter — total+glyph, high, session delta, types, last, streak
printf ' %s%s PII %s%s (%s high)%s │ %s%s types%s%s%s\n' \
  "$SC" "$TOTAL" "$GLYPH" "$RST" \
  "$HIGH" \
  "$SESS_SEG" \
  "$CYN" "$NUM_TYPES" "$RST" \
  "$LAST_SEG" \
  "$STREAK_SEG"

# Line 3: Detection breakdown + top categories + model/git/context/cost (dim)
JOINED=""
if [[ -n "$DET_PARTS" ]]; then jadd "${DIM}${DET_PARTS}${RST}"; fi
if [[ -n "$TOP_TYPES" ]]; then jadd "${DIM}top: ${TOP_TYPES}${RST}"; fi
jadd "$EXTRAS_LINE"
if [[ -n "$JOINED" ]]; then
  printf ' %s\n' "$JOINED"
fi

# Line 4: Dashboard link + skill shortcuts
printf ' %s │ %s/canary:leaked%s · %s/canary:scan%s\n' \
  "$DASH_SEG" \
  "$BCYN" "$RST" \
  "$BCYN" "$RST"

# Line 5: Footer bar
printf '%s%s%s' "$DIM" "$FULL_BAR" "$RST"

exit 0
