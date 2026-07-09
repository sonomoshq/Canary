#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# canary-tokens.sh — Canary Tokens: mint realistic-but-fake decoy
# secrets/PII, plant them, and detect the instant one reaches Claude.
#
# The insight: because Canary MINTS the token, a trip is a CERTAIN
# literal match (grep -F) against a value nobody else could produce —
# not a probabilistic shape-detection guess like the 36 regex
# detectors in detectors.sh. 36 detectors guess. This one knows.
#
# Sourceable library + dispatchable CLI. When sourced (e.g. from
# scan.sh/scan-file.sh), only function/constant definitions run — the
# CLI dispatch at the bottom is guarded so it fires only when this file
# is *executed* directly (`bash canary-tokens.sh <cmd>` or via
# bin/canary-token, which sources it and calls canary_tokens_cli
# itself).
#
# Public functions:
#   mint_token <type> [label] [planted_path]
#   plant_token <type> [path] [label]
#   list_tokens
#   trips
#   revoke <id>
#   ack
#   check_text_for_trips <textfile|-> <source> <session_id> <cwd>
#
# For type "freeform", the "label" slot in both mint_token and
# plant_token is repurposed to carry the user-supplied decoy STRING
# instead (freeform has no separate label — the string itself is the
# payload). See mint_token()/plant_token() below.
#
# Registry: $SONOMOS_DIR/canaries.jsonl (dir 0700, file 0600), one
# compact JSON object per line:
#   {"id":"<8 hex>","type":"...","value":"...","secret":"...",
#    "label":"...","planted_path":"...","created_at":"ISO8601Z",
#    "status":"armed|tripped","value_id":"<12 hex>","tripped_at":"",
#    "tripped_source":"","tripped_session_id":""}
#
# jq-optional throughout: every read/write path works via plain-text
# parsing (grep -F / awk) when jq is absent. jq, when present, is only
# used for marginally more robust JSON string escaping on write.
#
# Bash 3.2 compatible: no associative arrays, no mapfile, no ${var,,}.

set -euo pipefail
umask 0077

SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
CANARIES_FILE="$SONOMOS_DIR/canaries.jsonl"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"
CT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd 2>/dev/null || true)"
DETECTORS_SH="$CT_SCRIPT_DIR/detectors.sh"

# ══════════════════════════════════════════════════════════════════════
# Reuse detectors.sh's validation/hashing primitives via targeted
# extraction (the same technique tests/test-redact.sh already uses for
# `redact`) rather than sourcing the whole file. detectors.sh is
# script-shaped (TEXT="$1"; runs all 36 detectors immediately; `exit 0`
# on empty $1) — `source`ing it directly here would either run every
# detector against our own CLI argv or `exit` this entire process
# depending on what $1 happened to be. Pulling just the named function
# bodies out keeps one algorithmic source of truth (Luhn, placeholder
# denylist, salted value_id hashing) without either hazard.
# ══════════════════════════════════════════════════════════════════════
if [[ -r "$DETECTORS_SH" ]]; then
  eval "$(sed -n '/^is_repeated_digit()/,/^}/p' "$DETECTORS_SH" 2>/dev/null)" 2>/dev/null || true
  eval "$(sed -n '/^is_placeholder()/,/^}/p' "$DETECTORS_SH" 2>/dev/null)" 2>/dev/null || true
  eval "$(sed -n '/^luhn_valid()/,/^}/p' "$DETECTORS_SH" 2>/dev/null)" 2>/dev/null || true
  eval "$(sed -n '/^load_salt()/,/^}/p' "$DETECTORS_SH" 2>/dev/null)" 2>/dev/null || true
  eval "$(sed -n '/^compute_value_id()/,/^}/p' "$DETECTORS_SH" 2>/dev/null)" 2>/dev/null || true
  eval "$(sed -n '/^json_escape()/,/^}/p' "$DETECTORS_SH" 2>/dev/null)" 2>/dev/null || true
fi

# Defensive fallbacks if extraction failed for any reason (detectors.sh
# missing/moved/reshaped) — degrade instead of crashing the caller.
declare -f is_repeated_digit >/dev/null 2>&1 || is_repeated_digit() { return 1; }
declare -f is_placeholder    >/dev/null 2>&1 || is_placeholder()    { return 1; }
declare -f luhn_valid        >/dev/null 2>&1 || luhn_valid() {
  local num="${1//[- ]/}" len sum=0 alt=0 i d
  len=${#num}
  for (( i=len-1; i>=0; i-- )); do
    d=${num:$i:1}
    if [[ $alt -eq 1 ]]; then d=$((d * 2)); [[ $d -gt 9 ]] && d=$((d - 9)); fi
    sum=$((sum + d)); alt=$((1 - alt))
  done
  [[ $((sum % 10)) -eq 0 ]]
}
declare -f json_escape >/dev/null 2>&1 || json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}
declare -f load_salt >/dev/null 2>&1 || load_salt() { :; }
declare -f compute_value_id >/dev/null 2>&1 || compute_value_id() { printf ''; }

HASH_CMD=""
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD="shasum"
elif command -v openssl >/dev/null 2>&1; then
  HASH_CMD="openssl"
fi
SALT=""
# shellcheck disable=SC2034  # read/written by load_salt(), which is only
# visible to shellcheck through the eval'd string extracted above, so the
# static analyzer can't see the reference.
SALT_LOADED=0

# ══════════════════════════════════════════════════════════════════════
# Random value generation
# ══════════════════════════════════════════════════════════════════════
DIGITS="0123456789"
HEX_LOWER="0123456789abcdef"
UPPER_ALNUM="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALNUM_MIXED="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
B64ISH_ALPHA="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Pure-bash fallback random picker (no /dev/urandom needed). Not
# cryptographic — fine here, since canary tokens only need to be
# *unguessable enough* to plant convincingly, not authentication-grade
# secrets themselves.
_rand_pick_fallback() {
  local charset="$1" n="$2" out="" i len idx
  len=${#charset}
  [[ $len -eq 0 ]] && return 1
  for (( i = 0; i < n; i++ )); do
    idx=$(( RANDOM % len ))
    out="${out}${charset:idx:1}"
  done
  printf '%s' "$out"
}

# rand_string <charset> <n> — n random characters drawn from charset
# (a literal list of characters, no ranges needed since every alphabet
# below is spelled out — keeps `tr -dc` portable across GNU and BSD).
# Prefers /dev/urandom; falls back to $RANDOM if unavailable or short.
rand_string() {
  local charset="$1" n="$2" pool=""
  if [[ -r /dev/urandom ]]; then
    pool=$(head -c $((n * 8 + 64)) /dev/urandom 2>/dev/null | LC_ALL=C tr -dc "$charset" 2>/dev/null | head -c "$n")
  fi
  if [[ ${#pool} -eq $n ]]; then
    printf '%s' "$pool"
  else
    _rand_pick_fallback "$charset" "$n"
  fi
}

# ══════════════════════════════════════════════════════════════════════
# JSON field helpers (jq-free — used for every read, and as the
# fallback for every write). Values are always single-line, quoted
# JSON strings with only the 5 escape sequences json_escape() produces
# (\\, \", \t, \r, \n) — these helpers only need to handle exactly that.
# ══════════════════════════════════════════════════════════════════════

# _jf <json-line> <field> — print the raw (still JSON-escaped) string
# value of "field" in a flat single-line JSON object, or "" if absent.
_jf() {
  local line="$1" field="$2"
  awk -v f="\"${field}\":\"" '
    {
      i = index($0, f)
      if (i == 0) { print ""; exit }
      s = substr($0, i + length(f))
      out = ""
      n = length(s)
      j = 1
      while (j <= n) {
        c = substr(s, j, 1)
        if (c == "\\") {
          out = out c substr(s, j + 1, 1)
          j += 2
        } else if (c == "\"") {
          break
        } else {
          out = out c
          j += 1
        }
      }
      print out
    }
  ' <<< "$line" 2>/dev/null || true
}

# _json_unescape — reverse of json_escape(), in the opposite order it
# was applied (json_escape doubles backslashes FIRST, then introduces
# \t/\r/\n/\" — so unescaping must undo those four *before* collapsing
# doubled backslashes, or a literal \t etc. gets corrupted).
_json_unescape() {
  local s="$1"
  s="${s//\\n/$'\n'}"
  s="${s//\\r/$'\r'}"
  s="${s//\\t/$'\t'}"
  s="${s//\\\"/\"}"
  s="${s//\\\\/\\}"
  printf '%s' "$s"
}

# ══════════════════════════════════════════════════════════════════════
# Registry primitives
# ══════════════════════════════════════════════════════════════════════

ensure_registry() {
  mkdir -p "$SONOMOS_DIR" 2>/dev/null || true
  chmod 700 "$SONOMOS_DIR" 2>/dev/null || true
  [[ -f "$CANARIES_FILE" ]] || : > "$CANARIES_FILE" 2>/dev/null || true
  chmod 600 "$CANARIES_FILE" 2>/dev/null || true
}

# _build_canary_line <id> <type> <value> <secret> <label> <planted_path>
#                     <created_at> <status> <value_id> <tripped_at>
#                     <tripped_source> <tripped_session_id>
# Serializes one canary record as a compact single-line JSON object, in
# the exact field order the data contract specifies. Prefers jq (fully
# correct escaping incl. unicode/control chars); falls back to
# json_escape() per field (same scope/limits as detectors.sh's own use
# of it) when jq is unavailable.
_build_canary_line() {
  local id="$1" type="$2" value="$3" secret="$4" label="$5" planted_path="$6" \
        created_at="$7" status="$8" value_id="$9" tripped_at="${10}" \
        tripped_source="${11}" tripped_session_id="${12}"

  if command -v jq >/dev/null 2>&1; then
    jq -n -c \
      --arg id "$id" --arg type "$type" --arg value "$value" --arg secret "$secret" \
      --arg label "$label" --arg planted_path "$planted_path" --arg created_at "$created_at" \
      --arg status "$status" --arg value_id "$value_id" --arg tripped_at "$tripped_at" \
      --arg tripped_source "$tripped_source" --arg tripped_session_id "$tripped_session_id" \
      '{id:$id, type:$type, value:$value, secret:$secret, label:$label,
        planted_path:$planted_path, created_at:$created_at, status:$status,
        value_id:$value_id, tripped_at:$tripped_at, tripped_source:$tripped_source,
        tripped_session_id:$tripped_session_id}' 2>/dev/null && return 0
  fi

  printf '{"id":"%s","type":"%s","value":"%s","secret":"%s","label":"%s","planted_path":"%s","created_at":"%s","status":"%s","value_id":"%s","tripped_at":"%s","tripped_source":"%s","tripped_session_id":"%s"}' \
    "$(json_escape "$id")" "$(json_escape "$type")" "$(json_escape "$value")" \
    "$(json_escape "$secret")" "$(json_escape "$label")" "$(json_escape "$planted_path")" \
    "$(json_escape "$created_at")" "$(json_escape "$status")" "$(json_escape "$value_id")" \
    "$(json_escape "$tripped_at")" "$(json_escape "$tripped_source")" "$(json_escape "$tripped_session_id")"
}

_register_canary() {
  local id="$1" type="$2" value="$3" secret="$4" label="$5" planted_path="$6" created_at="$7" value_id="$8"
  ensure_registry
  local line
  line=$(_build_canary_line "$id" "$type" "$value" "$secret" "$label" "$planted_path" "$created_at" "armed" "$value_id" "" "" "")
  [[ -z "$line" ]] && return 1
  printf '%s\n' "$line" >> "$CANARIES_FILE" 2>/dev/null || true
  chmod 600 "$CANARIES_FILE" 2>/dev/null || true
}

# _get_canary_line <id> — the raw registry line for id, or empty.
_get_canary_line() {
  local id="$1"
  [[ -f "$CANARIES_FILE" ]] || return 1
  grep -F "\"id\":\"${id}\"" "$CANARIES_FILE" 2>/dev/null | head -1 || true
}

# _read_canary_record <id> — populates _CT_* globals from the record.
# Bash 3.2 has no way to return a struct, so this is the multi-value
# return convention used throughout this file; single-threaded, never
# called reentrantly, so plain globals are safe.
_read_canary_record() {
  local id="$1" line
  line=$(_get_canary_line "$id") || return 1
  [[ -z "$line" ]] && return 1
  _CT_ID="$id"
  _CT_TYPE=$(_json_unescape "$(_jf "$line" type)")
  _CT_VALUE=$(_json_unescape "$(_jf "$line" value)")
  _CT_SECRET=$(_json_unescape "$(_jf "$line" secret)")
  _CT_LABEL=$(_json_unescape "$(_jf "$line" label)")
  _CT_PLANTED_PATH=$(_json_unescape "$(_jf "$line" planted_path)")
  _CT_CREATED_AT=$(_json_unescape "$(_jf "$line" created_at)")
  _CT_STATUS=$(_json_unescape "$(_jf "$line" status)")
  _CT_VALUE_ID=$(_json_unescape "$(_jf "$line" value_id)")
  _CT_TRIPPED_AT=$(_json_unescape "$(_jf "$line" tripped_at)")
  _CT_TRIPPED_SOURCE=$(_json_unescape "$(_jf "$line" tripped_source)")
  _CT_TRIPPED_SESSION_ID=$(_json_unescape "$(_jf "$line" tripped_session_id)")
  return 0
}

# _rewrite_line_for_id <id> <new_line-or-empty>
# Walks CANARIES_FILE once, replacing the line whose "id" matches with
# $2 (or dropping it entirely when $2 is empty — used by revoke), every
# other line untouched. Atomic temp+mv, same discipline as scan.sh's
# cursor file and scan-file.sh's filescan index. Safe to call while a
# caller is mid-iteration over the *old* copy of this same file via its
# own `< "$CANARIES_FILE"` file descriptor: `mv` swaps the directory
# entry, it doesn't affect an fd already open on the previous inode, so
# that reader keeps seeing the pre-rewrite content until it hits EOF.
_rewrite_line_for_id() {
  local id="$1" new_line="$2"
  [[ -f "$CANARIES_FILE" ]] || return 0
  local tmp="${CANARIES_FILE}.tmp.$$"
  : > "$tmp" 2>/dev/null || return 1
  local line line_id matched=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    line_id=$(_jf "$line" "id")
    if [[ -n "$line_id" && "$line_id" == "$id" ]]; then
      matched=1
      [[ -n "$new_line" ]] && printf '%s\n' "$new_line" >> "$tmp"
    else
      printf '%s\n' "$line" >> "$tmp"
    fi
  done < "$CANARIES_FILE"
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$CANARIES_FILE" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
  [[ $matched -eq 1 ]]
}

_mark_planted() {
  local id="$1" path="$2"
  _read_canary_record "$id" || return 1
  local new_line
  new_line=$(_build_canary_line "$_CT_ID" "$_CT_TYPE" "$_CT_VALUE" "$_CT_SECRET" "$_CT_LABEL" \
    "$path" "$_CT_CREATED_AT" "$_CT_STATUS" "$_CT_VALUE_ID" "$_CT_TRIPPED_AT" "$_CT_TRIPPED_SOURCE" "$_CT_TRIPPED_SESSION_ID")
  [[ -z "$new_line" ]] && return 1
  _rewrite_line_for_id "$id" "$new_line"
}

# _mint_unique_id — 8 lowercase hex chars, checked against the current
# registry (collision astronomically unlikely at this length, but the
# check is cheap so there's no reason to skip it).
_mint_unique_id() {
  local id=""
  for _ in 1 2 3 4 5; do
    id=$(rand_string "$HEX_LOWER" 8)
    if [[ -n "$id" ]] && { [[ ! -f "$CANARIES_FILE" ]] || ! grep -qF "\"id\":\"${id}\"" "$CANARIES_FILE" 2>/dev/null; }; then
      printf '%s' "$id"
      return 0
    fi
  done
  printf '%s' "$id"
}

# ══════════════════════════════════════════════════════════════════════
# Type-specific minting
# ══════════════════════════════════════════════════════════════════════

# _mint_luhn_card — a fresh Luhn-VALID 16-digit number. Prefix "9999"
# is not assigned to any card network by ISO/IEC 7812 — unambiguously a
# decoy, never a real BIN/IIN. Reuses detectors.sh's own luhn_valid()
# to pick the check digit (brute-force over 0-9; exactly one passes),
# so the "is this Luhn-valid" logic never has two implementations to
# drift apart.
_mint_luhn_card() {
  local prefix="9999" payload d
  payload="${prefix}$(rand_string "$DIGITS" 11)"
  for d in 0 1 2 3 4 5 6 7 8 9; do
    if luhn_valid "${payload}${d}" 2>/dev/null; then
      printf '%s' "${payload}${d}"
      return 0
    fi
  done
  return 1
}

# _mint_fake_ssn — area 900-999 is SSA-reserved and has never been (and
# under the current SSN randomization scheme, structurally cannot be)
# issued to a real person, so this can never collide with a real SSN.
# Canary's OWN us_ssn detector's ssn_valid() explicitly rejects area
# >=900 — this canary type deliberately will NOT double-signal via the
# regex layer. That's fine: the certain literal match on trip is what
# matters, not the regex layer re-confirming the shape.
_mint_fake_ssn() {
  local area group serial
  area=$(( 900 + (RANDOM % 100) ))
  group=$(printf '%02d' $(( 1 + (RANDOM % 99) )))
  serial=$(printf '%04d' $(( 1 + (RANDOM % 9999) )))
  printf '%s-%s-%s' "$area" "$group" "$serial"
}

# ══════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════

# mint_token <type> [label] [planted_path]
# type: aws | card | ssn | env | dburl | freeform
#
# For every type EXCEPT freeform, [label] is a human label and the
# minted value is random. For freeform, the second argument is instead
# the REQUIRED decoy string itself (there is no separate label slot —
# see plant_token() for the CLI-facing rationale). Echoes the minted
# value to stdout on success, and also sets MINT_LAST_ID/_TYPE/_VALUE/
# _SECRET/_LABEL/_VALUE_ID globals so callers (the CLI) can report
# richer detail without re-parsing stdout.
mint_token() {
  local type="$1" arg2="${2:-}" planted_path="${3:-}"

  case "$type" in
    aws|card|ssn|env|dburl|freeform) ;;
    *)
      echo "canary-token: unknown type '$type' (expected aws|card|ssn|env|dburl|freeform)" >&2
      return 1
      ;;
  esac

  ensure_registry
  load_salt

  local value="" secret="" label=""

  if [[ "$type" == "freeform" ]]; then
    value="$arg2"
    label="freeform decoy"
    if [[ -z "$value" ]]; then
      echo 'canary-token: freeform requires a decoy string, e.g. `canary-token new freeform "Project Nightjar"`' >&2
      return 1
    fi
    if is_placeholder "$value" 2>/dev/null; then
      echo "canary-token: that string is a known placeholder/test value — refusing to mint it as a canary" >&2
      return 1
    fi
  else
    label="$arg2"
    for _ in 1 2 3 4 5; do
      secret=""
      case "$type" in
        aws)
          value="AKIA$(rand_string "$UPPER_ALNUM" 16)"
          secret="$(rand_string "$B64ISH_ALPHA" 40)"
          [[ -z "$label" ]] && label="AWS access key decoy"
          ;;
        card)
          value="$(_mint_luhn_card)"
          [[ -z "$label" ]] && label="Payment card decoy"
          ;;
        ssn)
          value="$(_mint_fake_ssn)"
          [[ -z "$label" ]] && label="SSN decoy (never-issued 900-999 area)"
          ;;
        env)
          value="$(rand_string "$ALNUM_MIXED" 40)"
          [[ -z "$label" ]] && label="API key decoy"
          ;;
        dburl)
          value="postgres://canary_svc:$(rand_string "$ALNUM_MIXED" 20)@db.internal.canary:5432/app_production"
          [[ -z "$label" ]] && label="Database URL decoy"
          ;;
      esac
      if ! is_placeholder "$value" 2>/dev/null; then
        break
      fi
      value=""
    done
    if [[ -z "$value" ]]; then
      echo "canary-token: could not mint a non-placeholder $type value after 5 attempts" >&2
      return 1
    fi
  fi

  local id created_at value_id=""
  id=$(_mint_unique_id)
  created_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [[ -n "$HASH_CMD" ]]; then
    [[ -n "$SALT" ]] && value_id=$(compute_value_id "$value")
  fi

  if ! _register_canary "$id" "$type" "$value" "$secret" "$label" "$planted_path" "$created_at" "$value_id"; then
    echo "canary-token: failed to register the new canary" >&2
    return 1
  fi

  MINT_LAST_ID="$id"
  MINT_LAST_TYPE="$type"
  MINT_LAST_VALUE="$value"
  MINT_LAST_SECRET="$secret"
  MINT_LAST_LABEL="$label"
  MINT_LAST_VALUE_ID="$value_id"

  printf '%s\n' "$value"
}

# plant_token <type> [path] [label]
# Mints (see mint_token) then writes a conventional decoy file to disk.
# Default paths: aws -> <cwd>/.aws-credentials.canary, env ->
# <cwd>/.env.canary, dburl -> <cwd>/database.canary.url, others ->
# <cwd>/canary-<id>.txt (needs the freshly-minted id, so it's resolved
# after minting for every type, uniformly, even though aws/env/dburl's
# default doesn't strictly need to be).
#
# For freeform, [label] is instead the REQUIRED decoy string (same
# special-case as mint_token) — there's no separate label for a
# freeform plant.
plant_token() {
  local type="$1" path="${2:-}" arg3="${3:-}"

  case "$type" in
    aws|card|ssn|env|dburl|freeform) ;;
    *)
      echo "canary-token: unknown type '$type' (expected aws|card|ssn|env|dburl|freeform)" >&2
      return 1
      ;;
  esac

  if [[ "$type" == "freeform" ]]; then
    mint_token "freeform" "$arg3" "" >/dev/null || return 1
  else
    mint_token "$type" "$arg3" "" >/dev/null || return 1
  fi

  local id="$MINT_LAST_ID" value="$MINT_LAST_VALUE" secret="$MINT_LAST_SECRET" label="$MINT_LAST_LABEL"
  local cwd_now target
  cwd_now="$(pwd 2>/dev/null || printf '.')"

  if [[ -n "$path" ]]; then
    target="$path"
  else
    case "$type" in
      aws)   target="$cwd_now/.aws-credentials.canary" ;;
      env)   target="$cwd_now/.env.canary" ;;
      dburl) target="$cwd_now/database.canary.url" ;;
      *)     target="$cwd_now/canary-${id}.txt" ;;
    esac
  fi

  local body=""
  case "$type" in
    aws)
      body="# Canary decoy AWS credentials — SAFE TO COMMIT. Monitored by Canary;
# if these ever reach Claude's context, Canary alarms with a CERTAIN
# (literal, non-probabilistic) match.
[default]
aws_access_key_id = ${value}
aws_secret_access_key = ${secret}
"
      ;;
    env)
      body="# rotated 2026 — do not delete
API_KEY=${value}
"
      ;;
    dburl)
      body="# Canary decoy database URL — SAFE TO COMMIT. Monitored by Canary.
DATABASE_URL=${value}
"
      ;;
    card)
      body="# Canary decoy payment card — SAFE TO COMMIT. Monitored by Canary.
card_number=${value}
"
      ;;
    ssn)
      body="# Canary decoy SSN — SAFE TO COMMIT. Monitored by Canary.
# (900-999 area: an intentionally invalid/never-issued SSN — the point
# is the CERTAIN literal-match trip, not the SSN regex layer.)
ssn=${value}
"
      ;;
    freeform)
      body="# Canary decoy — SAFE TO COMMIT. Monitored by Canary.
${value}
"
      ;;
  esac

  if ! printf '%s' "$body" > "$target" 2>/dev/null; then
    echo "canary-token: could not write $target" >&2
    return 1
  fi
  chmod 644 "$target" 2>/dev/null || true

  _mark_planted "$id" "$target" || true

  echo "Planted: $target"
  echo "  Label: $label"
  echo "  SAFE TO COMMIT — that's the point. If this file's contents ever"
  echo "  reach Claude, Canary alarms with a CERTAIN match, not a guess."
}

# list_tokens — every canary, armed and tripped.
list_tokens() {
  ensure_registry
  if [[ ! -s "$CANARIES_FILE" ]]; then
    echo "No canary tokens minted yet. Try: canary-token new env"
    return 0
  fi
  printf '%-10s %-8s %-9s %s\n' "ID" "TYPE" "STATUS" "LABEL"
  local line id type status label
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    id=$(_jf "$line" "id")
    [[ -z "$id" ]] && continue
    type=$(_jf "$line" "type")
    status=$(_jf "$line" "status")
    label=$(_json_unescape "$(_jf "$line" "label")")
    printf '%-10s %-8s %-9s %s\n' "$id" "$type" "$status" "$label"
  done < "$CANARIES_FILE"
}

# trips — only tripped canaries, with when/where/how.
trips() {
  ensure_registry
  if [[ ! -s "$CANARIES_FILE" ]]; then
    echo "No canary tokens minted yet."
    return 0
  fi
  local found=0
  local line id type status label tripped_at tripped_source tripped_session_id
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    status=$(_jf "$line" "status")
    [[ "$status" != "tripped" ]] && continue
    found=1
    id=$(_jf "$line" "id")
    type=$(_jf "$line" "type")
    label=$(_json_unescape "$(_jf "$line" "label")")
    tripped_at=$(_json_unescape "$(_jf "$line" "tripped_at")")
    tripped_source=$(_json_unescape "$(_jf "$line" "tripped_source")")
    tripped_session_id=$(_json_unescape "$(_jf "$line" "tripped_session_id")")
    echo "TRIPPED [$id] $type — \"$label\""
    echo "  at: $tripped_at  source: $tripped_source  session: $tripped_session_id"
  done < "$CANARIES_FILE"
  [[ $found -eq 0 ]] && echo "No trips yet. All canaries armed."
  return 0
}

# revoke <id> — removes the canary from the registry entirely
# (disarms it). Note the data contract's status enum is strictly
# armed|tripped, so "revoked" is not a third status value here —
# revoking just deletes the record, which is also simpler to reason
# about for check_text_for_trips (a gone canary can never trip again).
revoke() {
  local id="${1:-}"
  if [[ -z "$id" ]]; then
    echo "canary-token: revoke requires an id" >&2
    return 1
  fi
  if ! _read_canary_record "$id"; then
    echo "canary-token: no canary with id '$id'" >&2
    return 1
  fi
  if _rewrite_line_for_id "$id" ""; then
    echo "Revoked canary $id (\"$_CT_LABEL\")."
  else
    echo "canary-token: failed to revoke $id" >&2
    return 1
  fi
}

# ack — acknowledge current trips: writes the count of currently
# tripped canaries to $SONOMOS_DIR/.trips_acked, so a HUD/statusline
# can compare "tripped count now" vs "tripped count at last ack" to
# know whether to show an unacknowledged-trip indicator.
ack() {
  ensure_registry
  local count=0 line status
  if [[ -s "$CANARIES_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" ]] && continue
      status=$(_jf "$line" "status")
      [[ "$status" == "tripped" ]] && count=$((count + 1))
    done < "$CANARIES_FILE"
  fi
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  local tmp="$SONOMOS_DIR/.trips_acked.tmp.$$"
  if printf '%s\n' "$count" > "$tmp" 2>/dev/null; then
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$SONOMOS_DIR/.trips_acked" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
  fi
  printf 'Acknowledged %s tripped canary(ies).\n' "$count"
}

# _record_trip <id> <source> <session_id> <cwd>
# Idempotent: a no-op if the canary is already "tripped". Flips status
# (atomic rewrite), appends the canary_tripped entry to leaks.jsonl per
# the data contract, and — for a genuinely NEW trip only — prints the
# one-line alarm.
_record_trip() {
  local id="$1" source="$2" session_id="$3" cwd="$4"
  _read_canary_record "$id" || return 0
  [[ "$_CT_STATUS" == "tripped" ]] && return 0

  local ts new_line
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  new_line=$(_build_canary_line "$_CT_ID" "$_CT_TYPE" "$_CT_VALUE" "$_CT_SECRET" "$_CT_LABEL" \
    "$_CT_PLANTED_PATH" "$_CT_CREATED_AT" "tripped" "$_CT_VALUE_ID" "$ts" "$source" "$session_id")
  [[ -z "$new_line" ]] && return 0
  _rewrite_line_for_id "$id" "$new_line" || return 0

  mkdir -p "$SONOMOS_DIR" 2>/dev/null || true
  chmod 700 "$SONOMOS_DIR" 2>/dev/null || true
  [[ -f "$LEAKS_FILE" ]] && chmod 600 "$LEAKS_FILE" 2>/dev/null || true

  if command -v jq >/dev/null 2>&1; then
    jq -n -c \
      --arg value "$_CT_LABEL" --arg ts "$ts" --arg sid "$session_id" \
      --arg vid "$_CT_VALUE_ID" --arg src "canary:${id}" --arg cwd "$cwd" \
      '{type: "canary_tripped", value: $value, detector: "canary", confidence: "certain",
        timestamp: $ts, session_id: $sid, source: $src}
       + (if $vid != "" then {value_id: $vid} else {} end)
       + (if $cwd != "" then {cwd: $cwd} else {} end)' >> "$LEAKS_FILE" 2>/dev/null || true
  else
    printf '{"type":"canary_tripped","value":"%s","detector":"canary","confidence":"certain","timestamp":"%s","session_id":"%s","value_id":"%s","source":"canary:%s","cwd":"%s"}\n' \
      "$(json_escape "$_CT_LABEL")" "$ts" "$(json_escape "$session_id")" "$(json_escape "$_CT_VALUE_ID")" \
      "$(json_escape "$id")" "$(json_escape "$cwd")" >> "$LEAKS_FILE" 2>/dev/null || true
  fi
  chmod 600 "$LEAKS_FILE" 2>/dev/null || true

  printf '\xf0\x9f\x90\xa4 Canary: tripwire "%s" reached Claude\n' "$_CT_LABEL" 2>/dev/null || true
}

# check_text_for_trips <textfile-or-"-"-for-stdin> <source> <session_id> <cwd>
# The DETECTION core. For every ARMED canary, checks whether its value
# (and, if present, its paired secret — e.g. an AWS secret key can leak
# independently of its access key) appears verbatim in the given text.
# grep -F throughout: canary values may contain regex/glob metacharacters
# (URLs, `/`, `+`), so this must never be grep -E. Guarded: an absent or
# empty registry is a zero-overhead no-op, never an error.
check_text_for_trips() {
  local input="${1:-}" source="${2:-}" session_id="${3:-}" cwd="${4:-}"
  local text

  if [[ ! -s "$CANARIES_FILE" ]]; then
    # Still drain stdin if that's where the caller sent the text, so a
    # piped writer doesn't see SIGPIPE/a broken pipe.
    [[ "$input" == "-" ]] && { cat >/dev/null 2>&1 || true; }
    return 0
  fi

  if [[ "$input" == "-" ]]; then
    text=$(cat 2>/dev/null || true)
  elif [[ -n "$input" && -f "$input" ]]; then
    text=$(cat "$input" 2>/dev/null || true)
  else
    text="$input"
  fi
  [[ -z "$text" ]] && return 0

  local line status id value secret hit
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    status=$(_jf "$line" "status")
    [[ "$status" != "armed" ]] && continue
    id=$(_jf "$line" "id")
    [[ -z "$id" ]] && continue
    value=$(_json_unescape "$(_jf "$line" "value")")
    secret=$(_json_unescape "$(_jf "$line" "secret")")

    hit=0
    if [[ -n "$value" ]] && printf '%s' "$text" | grep -qF -- "$value" 2>/dev/null; then
      hit=1
    fi
    if [[ $hit -eq 0 && -n "$secret" ]] && printf '%s' "$text" | grep -qF -- "$secret" 2>/dev/null; then
      hit=1
    fi
    [[ $hit -eq 1 ]] && _record_trip "$id" "$source" "$session_id" "$cwd"
  done < "$CANARIES_FILE"
  return 0
}

# ══════════════════════════════════════════════════════════════════════
# CLI dispatch
# ══════════════════════════════════════════════════════════════════════

usage_canary_token() {
  cat <<'EOF'
Usage: canary-token <command> [args]

Commands:
  new <aws|card|ssn|env|dburl|freeform> [label]
                      Mint a fresh fake decoy value and register it as
                      an armed canary. For freeform, pass the decoy
                      string itself instead of a label, e.g.:
                        canary-token new freeform "Project Nightjar"
  plant <aws|card|ssn|env|dburl|freeform> [path] [label]
                      Mint + write a conventional decoy file to disk.
                      Safe to commit — that's the point.
  list                List all canary tokens (armed and tripped).
  trips               List only tripped canaries (when/where/how).
  revoke <id>         Remove a canary from the registry (disarms it).
  ack                 Acknowledge current trips (clears the HUD flag).
  --help              Show this help.

Canary tokens are fake-but-realistic secrets Canary mints itself, so
when one shows up in something Claude reads, detection is a CERTAIN
literal match — not a probabilistic guess. 36 detectors guess. This
one knows.
EOF
}

canary_tokens_cli() {
  local cmd="${1:-}"
  case "$cmd" in
    new|mint)
      shift || true
      local type="${1:-}"
      [[ $# -gt 0 ]] && shift || true
      local label="${1:-}"
      if [[ -z "$type" ]]; then
        echo "Usage: canary-token new <aws|card|ssn|env|dburl|freeform> [label]" >&2
        return 1
      fi
      if mint_token "$type" "$label" >/dev/null; then
        echo "Minted canary [$MINT_LAST_ID] type=$MINT_LAST_TYPE"
        echo "  Label: $MINT_LAST_LABEL"
        echo "  Value: $MINT_LAST_VALUE"
        [[ -n "$MINT_LAST_SECRET" ]] && echo "  Secret: $MINT_LAST_SECRET"
        [[ -n "$MINT_LAST_VALUE_ID" ]] && echo "  value_id: $MINT_LAST_VALUE_ID (correlates with leaks.jsonl if this also trips a regex detector)"
        echo "  Fake decoy. Plant it (canary-token plant $MINT_LAST_TYPE) or drop it"
        echo "  somewhere Claude might read it — Canary alarms with a CERTAIN match"
        echo "  the instant it does, not a probabilistic guess."
      else
        return 1
      fi
      ;;
    plant)
      shift || true
      local ptype="${1:-}"
      [[ $# -gt 0 ]] && shift || true
      local ppath="${1:-}"
      [[ $# -gt 0 ]] && shift || true
      local plabel="${1:-}"
      if [[ -z "$ptype" ]]; then
        echo "Usage: canary-token plant <aws|card|ssn|env|dburl|freeform> [path] [label]" >&2
        return 1
      fi
      plant_token "$ptype" "$ppath" "$plabel"
      ;;
    list)
      list_tokens
      ;;
    trips)
      trips
      ;;
    revoke)
      shift || true
      revoke "${1:-}"
      ;;
    ack)
      ack
      ;;
    -h|--help|help|"")
      usage_canary_token
      ;;
    *)
      echo "canary-token: unknown command '$cmd'" >&2
      usage_canary_token >&2
      return 1
      ;;
  esac
}

# Only dispatch when this file is *executed* directly — never when
# sourced (scan.sh/scan-file.sh source this to get check_text_for_trips
# without triggering a CLI run).
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  canary_tokens_cli "$@"
fi
