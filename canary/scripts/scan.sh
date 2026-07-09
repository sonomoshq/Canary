#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# scan.sh — Regex PII scan on Stop hook.
# Reads the transcript, extracts new user messages since the last scan,
# runs regex detectors, and appends hits to $SONOMOS_DIR/leaks.jsonl.
# Also runs Canary Tokens' check_text_for_trips (canary-tokens.sh) over
# the same extracted text — a certain, literal-match detector alongside
# the 36 probabilistic regex detectors.
# LLM scanning runs automatically via the Stop prompt hook (record-llm-hit.sh).
# The /canary:scan skill provides deeper manual scanning of the full conversation.

set -euo pipefail

umask 0077

SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || true)"
CONFIDENCE_THRESHOLD="${CLAUDE_PLUGIN_OPTION_CONFIDENCE_THRESHOLD:-medium}"

mkdir -p "$SONOMOS_DIR"
chmod 700 "$SONOMOS_DIR" 2>/dev/null || true
[[ -f "$LEAKS_FILE" ]] && { chmod 600 "$LEAKS_FILE" 2>/dev/null || true; }

# Always drain stdin synchronously — Claude Code pipes hook JSON and a
# backgrounded/skipped read here can race the caller.
INPUT=$(cat 2>/dev/null || true)

# jq drives every step below (transcript JSONL parsing, hit construction).
# Degrade quietly rather than crashing (exit 127 under set -e) when it's
# missing — this is a best-effort background hook, not user-facing.
command -v jq >/dev/null 2>&1 || exit 0

TRANSCRIPT_PATH=$(printf '%s' "$INPUT" | jq -r '.transcript_path // empty' 2>/dev/null || true)
SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)
HOOK_CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)

if [[ -z "$TRANSCRIPT_PATH" || ! -f "$TRANSCRIPT_PATH" ]]; then
  exit 0
fi

# Determine where we left off (line-based cursor per transcript path).
# cksum is POSIX and present on both GNU/Linux and BSD/macOS, unlike
# md5sum (absent on macOS by default, which crashes this script under
# set -e). Collision risk is irrelevant here — the hash is only used as
# a filename key for the cursor file, not for anything security-sensitive.
TRANSCRIPT_HASH=$(printf '%s' "$TRANSCRIPT_PATH" | cksum 2>/dev/null | cut -d' ' -f1)
CURSOR_KEY="$SONOMOS_DIR/.cursor_${TRANSCRIPT_HASH}"
LAST_LINE=0
if [[ -f "$CURSOR_KEY" ]]; then
  LAST_LINE=$(cat "$CURSOR_KEY" 2>/dev/null || true)
  [[ "$LAST_LINE" =~ ^[0-9]+$ ]] || LAST_LINE=0
fi

TOTAL_LINES=$(wc -l < "$TRANSCRIPT_PATH" 2>/dev/null | tr -d ' ')
[[ "$TOTAL_LINES" =~ ^[0-9]+$ ]] || TOTAL_LINES=0
if [[ "$TOTAL_LINES" -le "$LAST_LINE" ]]; then
  exit 0
fi

# ── Extract new user message text from the transcript ──────────────────
#
# Real Claude Code transcripts are JSONL where each line has a top-level
# `.type` ("user" / "assistant" / "summary" / ...) and, for message
# lines, `.message.role` / `.message.content`. Content is either a plain
# string or an array of blocks such as {type:"text",text:...} or
# {type:"tool_result",...}. Lines can also carry `.isMeta == true` for
# synthetic/internal entries that are not real user input.
#
# This ONE jq program is the primary (and only correct) extraction path:
# select real user turns, skip meta lines, and — for array content —
# keep only "text" blocks (this also naturally excludes tool_result
# noise, since array-content "user" lines are overwhelmingly tool
# results rather than typed text).
PRIMARY_FILTER='
  select((.isMeta // false) == false) |
  select(.type == "user") |
  (.message.content // empty) |
  if type == "string" then .
  elif type == "array" then ([.[]? | select(.type? == "text") | .text] | join("\n"))
  else empty end
'

NEW_TEXT=$(tail -n +"$((LAST_LINE + 1))" "$TRANSCRIPT_PATH" 2>/dev/null | \
  jq -r "$PRIMARY_FILTER" 2>/dev/null | \
  head -c 50000 || true)

# Advance the cursor regardless of whether this batch contained PII —
# we've read through TOTAL_LINES either way. Atomic temp+mv write avoids
# a torn/partial cursor file if the hook is interrupted mid-write
# (flock isn't available everywhere, so this is the practical guard).
CURSOR_TMP="${CURSOR_KEY}.tmp.$$"
if printf '%s\n' "$TOTAL_LINES" > "$CURSOR_TMP" 2>/dev/null; then
  mv -f "$CURSOR_TMP" "$CURSOR_KEY" 2>/dev/null || rm -f "$CURSOR_TMP" 2>/dev/null || true
fi

if [[ -z "$NEW_TEXT" ]]; then
  exit 0
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

HITS=$(bash "$SCRIPT_DIR/detectors.sh" "$NEW_TEXT" 2>/dev/null || true)

if [[ -n "$HITS" ]]; then
  ALARM_SHOWN=0
  echo "$HITS" | while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    # Respect confidence threshold from userConfig
    HIT_CONF=$(printf '%s' "$hit" | jq -r '.confidence // "medium"' 2>/dev/null || echo "medium")
    if [[ "$CONFIDENCE_THRESHOLD" == "high" && "$HIT_CONF" != "high" ]]; then
      continue
    fi
    printf '%s' "$hit" | jq -c \
      --arg ts "$TIMESTAMP" \
      --arg sid "$SESSION_ID" \
      --arg src "transcript" \
      --arg cwd "$HOOK_CWD" \
      '. + {timestamp: $ts, session_id: $sid, source: $src}
         + (if $cwd != "" then {cwd: $cwd} else {} end)' >> "$LEAKS_FILE" 2>/dev/null || true
    # Best-effort in-turn feedback: one line, first high/certain hit only.
    if [[ "$ALARM_SHOWN" -eq 0 ]] && { [[ "$HIT_CONF" == "high" ]] || [[ "$HIT_CONF" == "certain" ]]; }; then
      HIT_TYPE=$(printf '%s' "$hit" | jq -r '.type // "sensitive data"' 2>/dev/null || echo "sensitive data")
      printf '\xf0\x9f\x90\xa4 Canary caught a %s\n' "$HIT_TYPE" 2>/dev/null || true
      ALARM_SHOWN=1
    fi
  done
fi

chmod 600 "$LEAKS_FILE" 2>/dev/null || true

# ── Canary Tokens: certain literal match on the same extracted text ────
# Guarded so a missing/unreadable library or empty canaries.jsonl is a
# zero-overhead, zero-error no-op — this hook must still exit 0.
if [[ -r "$SCRIPT_DIR/canary-tokens.sh" ]]; then
  # shellcheck source=canary-tokens.sh
  source "$SCRIPT_DIR/canary-tokens.sh" 2>/dev/null || true
  if declare -f check_text_for_trips >/dev/null 2>&1; then
    printf '%s' "$NEW_TEXT" | check_text_for_trips - "transcript" "$SESSION_ID" "$HOOK_CWD" 2>/dev/null || true
  fi
fi

exit 0
