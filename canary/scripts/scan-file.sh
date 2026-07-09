#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# scan-file.sh — Lightweight PII scan triggered by PostToolUse on Write/Edit.
# Reads the hook JSON from stdin, extracts the file path, and runs
# fast-path detectors (credit cards, SSNs, API keys) on the file content.
# Content-hash indexed so unchanged files are never rescanned, and hits
# already recorded for a given file are never re-logged.

set -euo pipefail

umask 0077

SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
FILESCAN_INDEX="$SONOMOS_DIR/.filescan_index"
IGNORE_FILE="$SONOMOS_DIR/canaryignore"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || true)"
CONFIDENCE_THRESHOLD="${CLAUDE_PLUGIN_OPTION_CONFIDENCE_THRESHOLD:-medium}"

mkdir -p "$SONOMOS_DIR"
chmod 700 "$SONOMOS_DIR" 2>/dev/null || true
[[ -f "$LEAKS_FILE" ]] && { chmod 600 "$LEAKS_FILE" 2>/dev/null || true; }

# Read hook input from stdin
INPUT=$(cat 2>/dev/null || true)

# jq drives JSON parsing throughout this script; degrade quietly rather
# than crashing (exit 127 under set -e) when it's missing.
command -v jq >/dev/null 2>&1 || exit 0

FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null || true)
SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)
HOOK_CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)

if [[ -z "$FILE_PATH" || ! -f "$FILE_PATH" ]]; then
  exit 0
fi

# Reject paths containing traversal sequences
case "$FILE_PATH" in
  *../*|*/..*) exit 0 ;;
esac

# Skip files that are never meaningful user content: lockfiles,
# minified/mapped build output, and anything under common
# generated/vendored directories.
BASENAME="${FILE_PATH##*/}"
case "$BASENAME" in
  package-lock.json|yarn.lock|pnpm-lock.yaml|Cargo.lock|*.min.js|*.map|*.svg)
    exit 0 ;;
esac
case "$FILE_PATH" in
  */node_modules/*|*/.git/*|*/dist/*|*/build/*)
    exit 0 ;;
esac

# Honor a user-maintained ignore file: one glob/substring per line,
# matched case-sensitively against the full path. Blank lines and
# lines starting with # are ignored.
if [[ -f "$IGNORE_FILE" ]]; then
  while IFS= read -r pattern || [[ -n "$pattern" ]]; do
    [[ -z "$pattern" || "$pattern" == \#* ]] && continue
    case "$FILE_PATH" in
      *"$pattern"*) exit 0 ;;
    esac
  done < "$IGNORE_FILE"
fi

# Skip binary files and large files (>100KB)
FILE_SIZE=$(wc -c < "$FILE_PATH" 2>/dev/null || echo 0)
[[ "$FILE_SIZE" =~ ^[0-9]+$ ]] || FILE_SIZE=0
if [[ "$FILE_SIZE" -gt 102400 ]]; then
  exit 0
fi

# ── Dedup fast path: skip files whose content hasn't changed ───────────
# .filescan_index holds one line per file: "<path_hash> <content_cksum>".
# cksum (POSIX, GNU+BSD portable) stands in for a content hash — collision
# risk is irrelevant since this only gates a rescan, it isn't a security
# boundary.
PATH_HASH=$(printf '%s' "$FILE_PATH" | cksum 2>/dev/null | cut -d' ' -f1)
CONTENT_CKSUM=$(cksum "$FILE_PATH" 2>/dev/null | cut -d' ' -f1)

PREV_CKSUM=""
if [[ -f "$FILESCAN_INDEX" ]]; then
  PREV_CKSUM=$(awk -v h="$PATH_HASH" '$1 == h { v = $2 } END { print v }' "$FILESCAN_INDEX" 2>/dev/null || true)
fi

if [[ -n "$CONTENT_CKSUM" && "$CONTENT_CKSUM" == "$PREV_CKSUM" ]]; then
  exit 0
fi

# We're committing to a (re)scan of this path/content pair — record it
# now so a crash or early exit below still prevents a redundant rescan
# next time (e.g. if the file turns out to be empty).
INDEX_TMP="${FILESCAN_INDEX}.tmp.$$"
{
  [[ -f "$FILESCAN_INDEX" ]] && awk -v h="$PATH_HASH" '$1 != h' "$FILESCAN_INDEX" 2>/dev/null
  printf '%s %s\n' "$PATH_HASH" "$CONTENT_CKSUM"
} | tail -n 500 > "$INDEX_TMP" 2>/dev/null
if [[ -s "$INDEX_TMP" ]]; then
  mv -f "$INDEX_TMP" "$FILESCAN_INDEX" 2>/dev/null || rm -f "$INDEX_TMP" 2>/dev/null || true
else
  rm -f "$INDEX_TMP" 2>/dev/null || true
fi

# Read file content
FILE_TEXT=$(cat "$FILE_PATH" 2>/dev/null || true)
if [[ -z "$FILE_TEXT" ]]; then
  exit 0
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SRC_TAG="file:${FILE_PATH}"

# Pre-filter leaks.jsonl to hits already recorded for this exact file, so
# re-running the same (or lightly re-edited) file doesn't pile up
# duplicate entries. grep -F treats FILE_PATH as a literal string, which
# matters since paths often contain regex metacharacters.
PRIOR_FILE_HITS=""
if [[ -s "$LEAKS_FILE" ]]; then
  PRIOR_FILE_HITS=$(grep -F "\"source\":\"${SRC_TAG}\"" "$LEAKS_FILE" 2>/dev/null || true)
fi

already_seen() {
  local t="$1" v="$2"
  [[ -z "$PRIOR_FILE_HITS" ]] && return 1
  printf '%s\n' "$PRIOR_FILE_HITS" | \
    awk -v t="\"type\":\"${t}\"" -v v="\"value\":\"${v}\"" \
      'index($0, t) && index($0, v) { found=1; exit } END { exit !found }'
}

# Run full detectors on the file content
HITS=$(bash "$SCRIPT_DIR/detectors.sh" "$FILE_TEXT" 2>/dev/null || true)

if [[ -n "$HITS" ]]; then
  echo "$HITS" | while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    # Respect confidence threshold
    if [[ "$CONFIDENCE_THRESHOLD" == "high" ]]; then
      HIT_CONF=$(printf '%s' "$hit" | jq -r '.confidence // "medium"' 2>/dev/null || echo "medium")
      [[ "$HIT_CONF" != "high" ]] && continue
    fi

    HIT_TYPE=$(printf '%s' "$hit" | jq -r '.type // empty' 2>/dev/null || true)
    HIT_VALUE=$(printf '%s' "$hit" | jq -r '.value // empty' 2>/dev/null || true)

    if already_seen "$HIT_TYPE" "$HIT_VALUE"; then
      continue
    fi

    printf '%s' "$hit" | jq -c \
      --arg ts "$TIMESTAMP" \
      --arg sid "$SESSION_ID" \
      --arg src "$SRC_TAG" \
      --arg cwd "$HOOK_CWD" \
      '. + {timestamp: $ts, session_id: $sid, source: $src}
         + (if $cwd != "" then {cwd: $cwd} else {} end)' >> "$LEAKS_FILE" 2>/dev/null || true
  done
fi

chmod 600 "$LEAKS_FILE" 2>/dev/null || true

exit 0
