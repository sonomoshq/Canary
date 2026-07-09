#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# record-llm-hit.sh — Records a single LLM-detected PII hit to leaks.jsonl.
# Usage: record-llm-hit.sh <type> <redacted_value> [confidence] [session_id]
# Called by the LLM prompt hook after Claude identifies PII.

set -euo pipefail

TYPE_RAW="${1:-unknown}"
VALUE_RAW="${2:-••••}"
CONFIDENCE_RAW="${3:-high}"
SESSION_ARG="${4:-}"

# jq is used for safe JSON construction (prevents injection from values
# containing quotes, backslashes, or control characters). Degrade
# quietly rather than crashing (exit 127 under set -e) when it's missing.
command -v jq >/dev/null 2>&1 || exit 0

# Respect llm_scan_enabled userConfig (defense-in-depth)
LLM_ENABLED="${CLAUDE_PLUGIN_OPTION_LLM_SCAN_ENABLED:-true}"
if [[ "$LLM_ENABLED" == "false" || "$LLM_ENABLED" == "0" ]]; then
  exit 0
fi

SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
CONFIDENCE_THRESHOLD="${CLAUDE_PLUGIN_OPTION_CONFIDENCE_THRESHOLD:-medium}"

# ── Validate/normalize inputs ───────────────────────────────────────────
# TYPE must look like a category slug; anything else collapses to "unknown"
# rather than writing arbitrary attacker/model-controlled strings.
if [[ "$TYPE_RAW" =~ ^[a-z0-9_]{1,40}$ ]]; then
  TYPE="$TYPE_RAW"
else
  TYPE="unknown"
fi

case "$CONFIDENCE_RAW" in
  high|medium|low) CONFIDENCE="$CONFIDENCE_RAW" ;;
  *) CONFIDENCE="medium" ;;
esac

# Respect confidence threshold from userConfig
if [[ "$CONFIDENCE_THRESHOLD" == "high" && "$CONFIDENCE" != "high" ]]; then
  exit 0
fi

umask 0077
mkdir -p "$SONOMOS_DIR"
chmod 700 "$SONOMOS_DIR" 2>/dev/null || true
[[ -f "$LEAKS_FILE" ]] && { chmod 600 "$LEAKS_FILE" 2>/dev/null || true; }

# ── Defensive re-redaction ──────────────────────────────────────────────
# The prompt hook instructs Claude to redact before calling this script,
# but nothing enforces that — whatever is passed on $2 is written
# verbatim otherwise. Strip newlines (which would corrupt the JSONL),
# cap length, and re-mask anything that still looks unredacted.
VALUE=$(printf '%s' "$VALUE_RAW" | tr -d '\r\n')
VALUE="${VALUE:0:64}"
if [[ "$VALUE" != *"•"* && ${#VALUE} -gt 5 ]]; then
  VLEN=${#VALUE}
  VALUE="${VALUE:0:2}••••${VALUE:$((VLEN - 2)):2}"
elif [[ "$VALUE" != *"•"* && ${#VALUE} -le 5 && -n "$VALUE" ]]; then
  # Short unredacted values carry too much of themselves to keep any part
  VALUE="••••"
fi
[[ -z "$VALUE" ]] && VALUE="••••"

# ── Resolve session_id ───────────────────────────────────────────────────
# Prefer an explicit 4th argument (passed by the hook once hooks.json
# forwards it). Fall back to the session id session-start.sh recorded for
# the current session, then to "unknown" — never the placeholder
# "current", which is not a real identifier.
SESSION_ID="$SESSION_ARG"
if [[ -z "$SESSION_ID" && -f "$SONOMOS_DIR/.current_session" ]]; then
  SESSION_ID=$(tr -d '\r\n' < "$SONOMOS_DIR/.current_session" 2>/dev/null || true)
fi
[[ -z "$SESSION_ID" ]] && SESSION_ID="unknown"

# ── value_id: stable dedup key for this (redacted) value ────────────────
# first 12 hex chars of sha256(salt + value). The salt lives at
# $SONOMOS_DIR/.salt (0600, created on first use) so value_id isn't
# reproducible outside this machine. Hashing the already-redacted value
# is intentional: identical redactions should dedupe identically.
SALT_FILE="$SONOMOS_DIR/.salt"

get_salt() {
  if [[ ! -s "$SALT_FILE" ]]; then
    local generated=""
    if command -v od >/dev/null 2>&1; then
      generated=$(head -c 32 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    fi
    if [[ -z "$generated" ]]; then
      generated=$(head -c 4096 /dev/urandom 2>/dev/null | tr -dc 'a-f0-9' 2>/dev/null | head -c 64)
    fi
    if [[ -z "$generated" ]]; then
      # Last-resort entropy if /dev/urandom is unavailable — not
      # cryptographically strong, but the salt only needs to be
      # unpredictable-ish and stable per install, not secret-grade.
      generated=$(printf '%s-%s-%s%s%s' "$(date +%s 2>/dev/null || echo 0)" "$$" "$RANDOM" "$RANDOM" "$RANDOM")
    fi
    printf '%s' "$generated" > "$SALT_FILE" 2>/dev/null || true
    chmod 600 "$SALT_FILE" 2>/dev/null || true
  fi
  cat "$SALT_FILE" 2>/dev/null || true
}

sha256_hex() {
  # Portable SHA-256: GNU sha256sum, then shasum -a 256 (macOS/BSD),
  # then openssl. Prints nothing if none are available.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 2>/dev/null | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
  else
    cat >/dev/null 2>&1 || true
  fi
}

VALUE_ID=""
SALT=$(get_salt)
if [[ -n "$SALT" ]]; then
  HASH=$(printf '%s%s' "$SALT" "$VALUE" | sha256_hex 2>/dev/null || true)
  [[ -n "$HASH" ]] && VALUE_ID="${HASH:0:12}"
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n -c \
  --arg type "$TYPE" \
  --arg value "$VALUE" \
  --arg confidence "$CONFIDENCE" \
  --arg timestamp "$TIMESTAMP" \
  --arg sid "$SESSION_ID" \
  --arg vid "$VALUE_ID" \
  '{type: $type, value: $value, detector: "llm", confidence: $confidence,
    timestamp: $timestamp, session_id: $sid}
   + (if $vid != "" then {value_id: $vid} else {} end)' >> "$LEAKS_FILE" 2>/dev/null || true

chmod 600 "$LEAKS_FILE" 2>/dev/null || true

exit 0
