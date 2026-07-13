#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# detectors.sh — Regex-based PII detection with checksum validation.
# Takes text on $1, outputs JSONL hits to stdout.
# Each hit: {"type":"<category>","value":"<redacted>","detector":"regex",
#            "confidence":"high|medium|low","value_id":"<12 hex chars, optional>"}
#
# Confidence can be downgraded one tier (high->medium, medium->low) by the
# negative-context dampener below when a hit lands near words like
# "example"/"dummy"/"changeme" — see HAS_NEG_CTX / context_window(). This
# never drops a hit outright (undercounting is the failure that matters —
# see THREAT_MODEL.md); it only de-emphasizes the weighted score.
#
# Portability: Works on both GNU grep (Linux) and BSD grep (macOS).
# Falls back to Perl when grep -P is unavailable. Bash 3.2 compatible:
# no associative arrays, no mapfile, no ${var,,}.
#
# 38 detectors (was 16): every original detector plus mac_address, a
# vendor-secret pack (GitHub/GitLab/Slack/Stripe/Anthropic/OpenAI/Google/
# SendGrid/npm/JWT/private keys/DB URLs), an entropy-gated generic_secret,
# checksum-validated NHS/SIN/NPI/DEA/ITIN identifiers, and a UK identity
# pack (National Insurance number w/ HMRC prefix rules, and postcode).

TEXT="$1"

if [[ -z "$TEXT" ]]; then
  exit 0
fi

# ── Portability shim: grep -oP / grep -oiP via Perl fallback ────────
# macOS ships BSD grep without -P (PCRE) support. Perl is universal
# on macOS and supports identical PCRE syntax.
#
# The Perl fallback uses m{PATTERN} rather than /PATTERN/ delimiters.
# Several of our patterns contain literal, unescaped "/" (URLs like
# https?://, postgres://, hooks.slack.com/services/...). With /.../
# delimiters Perl treats the first bare "/" inside the pattern as the
# closing delimiter and the rest fails to compile (silently, since we
# redirect stderr) — every pattern with a "/" in it would just emit
# nothing. {}/[]/()/<> are Perl's "bracketing" delimiters, which Perl
# matches by counting nesting depth instead of scanning for the next
# occurrence, so the {n,m} quantifiers already used throughout this
# file (e.g. IPv6's {1,4}) nest safely inside m{...} too.
if echo "test" | grep -oP 'test' &>/dev/null; then
  # GNU grep available — use native grep -oP. "-e" marks the pattern
  # explicitly so a pattern that itself starts with "-" (e.g.
  # private_key_block's "-----BEGIN...") isn't parsed as an option.
  pgrep_o()  { grep -oP  -e "$1" 2>/dev/null || true; }
  pgrep_oi() { grep -oiP -e "$1" 2>/dev/null || true; }
else
  # BSD grep — fall back to Perl
  pgrep_o()  { perl -ne "while (m{$1}g)  { print \"\$&\\n\" }" 2>/dev/null || true; }
  pgrep_oi() { perl -ne "while (m{$1}gi) { print \"\$&\\n\" }" 2>/dev/null || true; }
fi

# ── Utility: precomputed bullet masks (avoids seq/printf subshells) ──
# Built once, pure bash (indexed array + string append, no fork). We
# deliberately do NOT slice a single long "DOTS" string by character
# offset: this shell may run under a non-UTF-8 locale (LC_CTYPE=POSIX
# is common in minimal/container environments) where bash's substring
# expansion counts *bytes*, and "•" is a 3-byte UTF-8 sequence — slicing
# would cut a bullet in half and emit invalid UTF-8. Building each
# length independently via concatenation sidesteps that entirely.
DOT_MASKS=("")
_dm=""
for (( _i = 1; _i <= 20; _i++ )); do
  _dm="${_dm}•"
  DOT_MASKS[_i]="$_dm"
done
unset _dm _i

# ── Utility: redact a value, keeping first 2 and last 2 chars ────────
# len<=5 -> "••••" (fully masked). Otherwise first2 + dots + last2, with
# the dot run capped at 20 chars (plus a "…" marker so a capped mask is
# visually distinguishable from a short one). Values over 64 chars are
# truncated before redacting so we never build unbounded masks.
redact() {
  local val="$1"
  local clean="${val//[[:space:]]/}"
  local len=${#clean}
  if [[ $len -gt 64 ]]; then
    clean="${clean:0:64}"
    len=64
  fi
  if [[ $len -le 5 ]]; then
    printf '••••'
    return
  fi
  local mid=$((len - 4))
  local ellipsis=""
  if [[ $mid -gt 20 ]]; then
    mid=20
    ellipsis='…'
  fi
  printf '%s%s%s%s' "${clean:0:2}" "${DOT_MASKS[$mid]}" "$ellipsis" "${clean: -2}"
}

# ── Utility: JSON-string escaping (backslash, quote, control chars) ──
# Values are already redacted (mostly bullets + a couple of original
# chars) so this is deliberately minimal — but it must be CORRECT, since
# hand-interpolated JSON silently drops hits downstream when a raw value
# happens to end on a quote character (e.g. url_credentials matching up
# to a trailing `"` in `url = "https://u:p@h"`).
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

# ── Utility: is a cleaned value made of one repeated digit? ─────────
is_repeated_digit() {
  local s="$1"
  [[ "$s" =~ ^[0-9]+$ ]] || return 1
  local first="${s:0:1}"
  local i
  for (( i = 1; i < ${#s}; i++ )); do
    [[ "${s:$i:1}" != "$first" ]] && return 1
  done
  return 0
}

# ── Utility: known placeholder / doc / test values (never emitted) ───
# Suppresses the standard test PANs, SSA-published example SSNs, AWS's
# own docs example key pair, NANP's reserved 555-01xx fictional phone
# range, and any value that is just one digit repeated (e.g. all-zero).
is_placeholder() {
  local raw="$1"
  local clean="${raw//[- ]/}"
  case "$clean" in
    4111111111111111|4242424242424242|5555555555554444|378282246310005|6011111111111117|4012888888881881)
      return 0 ;;
    123456789|078051120|219099999|457555462)
      return 0 ;;
    AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)
      return 0 ;;
  esac
  local digits="${raw//[^0-9]/}"
  [[ "$digits" =~ 55501[0-9][0-9]$ ]] && return 0
  is_repeated_digit "$clean" && return 0
  return 1
}

# ── value_id: salted hash of the RAW value, for cross-hit correlation ─
# Tries sha256sum, then shasum -a 256, then openssl dgst -sha256; omits
# value_id entirely if none is available. The salt lives next to
# Canary's other plugin state and is generated once on first use.
HASH_CMD=""
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD="shasum"
elif command -v openssl >/dev/null 2>&1; then
  HASH_CMD="openssl"
fi

SALT=""
SALT_LOADED=0

# Must be called as a bare statement (never inside "$(...)") — it
# memoizes into globals, and a command-substitution subshell would
# throw that memoization away on every single call.
load_salt() {
  [[ $SALT_LOADED -eq 1 ]] && return 0
  SALT_LOADED=1
  local dir="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
  local salt_file="$dir/.salt"
  if [[ ! -s "$salt_file" ]]; then
    mkdir -p "$dir" 2>/dev/null
    chmod 700 "$dir" 2>/dev/null
    if [[ -r /dev/urandom ]]; then
      head -c 16 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n' > "$salt_file" 2>/dev/null
    fi
    [[ -f "$salt_file" ]] && chmod 600 "$salt_file" 2>/dev/null
  fi
  [[ -s "$salt_file" ]] && SALT=$(cat "$salt_file" 2>/dev/null)
}

compute_value_id() {
  local raw="$1"
  local digest=""
  case "$HASH_CMD" in
    sha256sum) digest=$(printf '%s' "${SALT}${raw}" | sha256sum 2>/dev/null | cut -c1-12) ;;
    shasum)    digest=$(printf '%s' "${SALT}${raw}" | shasum -a 256 2>/dev/null | cut -c1-12) ;;
    openssl)   digest=$(printf '%s' "${SALT}${raw}" | openssl dgst -sha256 -r 2>/dev/null | cut -d' ' -f1 | cut -c1-12) ;;
  esac
  printf '%s' "$digest"
}

# ── Utility: one-tier confidence downgrade (high->medium->low->low) ──
# Prints to stdout (usable as `x=$(downgrade_confidence "$x")`) for
# external callers/tests. emit()'s own hot path below does NOT call this
# via a subshell — it inlines the same 3-line case statement directly —
# since it runs on every dampened hit and a fork is avoidable there. Kept
# here as a standalone, testable utility so the mapping has one
# authoritative definition to read (and this exact function body is what
# any future extraction-based test would target, matching the redact()/
# luhn_valid() convention elsewhere in this file).
downgrade_confidence() {
  case "$1" in
    high) printf 'medium' ;;
    medium) printf 'low' ;;
    *) printf '%s' "$1" ;;
  esac
}

# ── Utility: ~40-char context window around the first occurrence of a
#             literal substring of $TEXT (used for negative-context
#             confidence dampening — see emit()). "token" MUST be a
#             literal substring of $TEXT (e.g. the raw $match a detector
#             just pulled out of it via pgrep_o/pgrep_oi, or a whole
#             $line for detectors that already loop line-by-line) — NOT
#             a post-processed value like dash-stripped digits, which
#             may no longer appear verbatim in $TEXT. Quoting "$token"
#             inside the ${TEXT%%...} pattern makes bash treat it as a
#             literal string rather than a glob, per standard bash
#             parameter-expansion semantics. Falls back to the token
#             itself (never dampens) if it isn't found verbatim — safe,
#             since that just skips the confidence downgrade.
#
# Sets the global CTX_WINDOW_RESULT rather than printing+being called via
# "$(...)" — this runs once per HIT (not once per invocation), so it
# deliberately avoids the subshell/fork a command substitution would cost.
context_window() {
  local token="$1"
  CTX_WINDOW_RESULT=""
  [[ -z "$token" ]] && return 0
  case "$TEXT" in
    *"$token"*) : ;;
    *) CTX_WINDOW_RESULT="$token"; return 0 ;;
  esac
  local prefix="${TEXT%%"$token"*}"
  local plen=${#prefix}
  local start=$(( plen - 40 ))
  [[ $start -lt 0 ]] && start=0
  local pre="${TEXT:$start:$((plen - start))}"
  local after_start=$(( plen + ${#token} ))
  local post="${TEXT:$after_start:40}"
  CTX_WINDOW_RESULT="${pre}${token}${post}"
}

# ── emit: single JSON-emission path (placeholder gate, dedup, negative-
#          context dampening, redact, value_id, print). All detectors
#          funnel through this. ───────────────────────────────────────
SEEN_KEYS=$'\x1e'

# emit <type> <raw-value> <confidence> [context-token]
#
# context-token, when given, is used ONLY for the negative-context
# dampening check (see context_window() above) — it must be a literal
# substring of $TEXT, not a transformed value like $digits or $clean.
# Every call site below passes the detector's own $match (or, for the
# few detectors that already loop line-by-line, $line — an equally
# literal, and more complete, substring of $TEXT).
emit() {
  local type="$1" raw="$2" conf="$3" ctx_token="${4:-}"

  is_placeholder "$raw" && return 0

  local key="${type}"$'\x1f'"${raw}"$'\x1e'
  case "$SEEN_KEYS" in
    *"$key"*) return 0 ;;
  esac
  SEEN_KEYS="${SEEN_KEYS}${key}"

  # Negative-context dampening: never drops a hit (undercounting is the
  # failure that matters), only lowers confidence one tier so the
  # weighted score de-emphasizes probable placeholders/examples. Gated
  # on HAS_NEG_CTX (computed once for the whole $TEXT) so texts with none
  # of these words never pay for the per-hit window lookup. Both
  # context_window() and the [[ =~ ]] match below are fork-free (see
  # their comments) since this runs once per hit.
  if [[ $HAS_NEG_CTX -eq 1 && -n "$ctx_token" ]]; then
    context_window "$ctx_token"
    if [[ "$CTX_WINDOW_RESULT" =~ $NEG_CTX_PATTERN ]]; then
      case "$conf" in
        high) conf="medium" ;;
        medium) conf="low" ;;
      esac
    fi
  fi

  local red
  if [[ "$type" == "private_key_block" ]]; then
    red="-----BEGIN …PRIVATE KEY----- ••••"
  else
    red=$(redact "$raw")
  fi

  local vid=""
  if [[ -n "$HASH_CMD" ]]; then
    load_salt
    [[ -n "$SALT" ]] && vid=$(compute_value_id "$raw")
  fi

  local out
  out="{\"type\":\"$(json_escape "$type")\",\"value\":\"$(json_escape "$red")\",\"detector\":\"regex\",\"confidence\":\"$(json_escape "$conf")\""
  [[ -n "$vid" ]] && out="${out},\"value_id\":\"$(json_escape "$vid")\""
  out="${out}}"
  printf '%s\n' "$out"
}

# ── Utility: precise case-insensitive keyword containment ───────────
# Used only where a plain glob substring gate would be too loose (e.g.
# "sin" needs a \b word boundary — plain substring hits "using"/"since").
text_has_keyword() {
  [[ -n "$(printf '%s' "$1" | pgrep_oi "$2")" ]]
}

# ── Utility: Luhn checksum validation ────────────────────────────────
luhn_valid() {
  local num="${1//[- ]/}"
  local len=${#num}
  local sum=0
  local alt=0
  for (( i=len-1; i>=0; i-- )); do
    local d=${num:$i:1}
    if [[ $alt -eq 1 ]]; then
      d=$((d * 2))
      [[ $d -gt 9 ]] && d=$((d - 9))
    fi
    sum=$((sum + d))
    alt=$(( 1 - alt ))
  done
  [[ $((sum % 10)) -eq 0 ]]
}

# ── Utility: MOD-97 validation for IBAN ──────────────────────────────
mod97_valid() {
  local iban
  iban=$(echo "$1" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
  # Move first 4 chars to end
  local rearranged="${iban:4}${iban:0:4}"
  # Replace letters with numbers (A=10, B=11, ..., Z=35)
  local numeric=""
  for (( i=0; i<${#rearranged}; i++ )); do
    local c="${rearranged:$i:1}"
    if [[ "$c" =~ [A-Z] ]]; then
      numeric+=$(( $(printf '%d' "'$c") - 55 ))
    else
      numeric+="$c"
    fi
  done
  # MOD 97 using chunked arithmetic (bash can't handle big ints)
  local remainder=0
  for (( i=0; i<${#numeric}; i++ )); do
    remainder=$(( (remainder * 10 + ${numeric:$i:1}) % 97 ))
  done
  [[ $remainder -eq 1 ]]
}

# ── Utility: ABA routing number checksum ─────────────────────────────
aba_valid() {
  local r="$1"
  [[ ${#r} -ne 9 ]] && return 1
  local sum=$(( 3*(${r:0:1}+${r:3:1}+${r:6:1}) + 7*(${r:1:1}+${r:4:1}+${r:7:1}) + (${r:2:1}+${r:5:1}+${r:8:1}) ))
  [[ $((sum % 10)) -eq 0 ]]
}

# ── Utility: Base58 / Bech32 format check (Bitcoin) ──────────────────
# NOT a cryptographic validation — this only re-confirms the same shape
# the calling regex already matched (length + alphabet). A real
# Base58Check validation would decode and verify the embedded SHA256d
# checksum; we deliberately don't implement that here (no crypto deps),
# so bitcoin_address is emitted at "medium" confidence, not "high".
base58check_valid() {
  local addr="$1"
  [[ "$addr" =~ ^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$ ]] || \
  [[ "$addr" =~ ^bc1[a-zA-HJ-NP-Z0-9]{25,89}$ ]]
}

# ── Utility: Ethereum address format check ───────────────────────────
# NOT EIP-55 checksum validation — only confirms "0x" + 40 hex chars,
# the same shape the calling regex already matched. A real EIP-55 check
# requires Keccak-256, which we don't implement here (no crypto deps),
# so ethereum_address is emitted at "medium" confidence, not "high".
eth_valid() {
  local addr="$1"
  [[ "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]]
}

# ── Utility: VIN MOD-11 validation ───────────────────────────────────
# Compatible with bash 3.2+ (no associative arrays)
vin_valid() {
  local vin
  vin=$(echo "$1" | tr '[:lower:]' '[:upper:]')
  [[ ${#vin} -ne 17 ]] && return 1
  # VIN transliteration: letter → numeric value (I, O, Q excluded from VINs)
  local trans_chars="ABCDEFGHJKLMNPRSTUVWXYZ"
  local trans_vals="12345678123457923456789"
  local weights=(8 7 6 5 4 3 2 10 0 9 8 7 6 5 4 3 2)
  local sum=0
  for (( i=0; i<17; i++ )); do
    local c="${vin:$i:1}"
    local val=0
    if [[ "$c" =~ [0-9] ]]; then
      val=$c
    else
      # Find character position in trans_chars to look up value
      local j
      for (( j=0; j<${#trans_chars}; j++ )); do
        if [[ "${trans_chars:$j:1}" == "$c" ]]; then
          val=${trans_vals:$j:1}
          break
        fi
      done
    fi
    sum=$((sum + val * ${weights[$i]}))
  done
  local check=$((sum % 11))
  local check_char
  [[ $check -eq 10 ]] && check_char="X" || check_char="$check"
  [[ "${vin:8:1}" == "$check_char" ]]
}

# ── Utility: SSN SSA exclusion rules ─────────────────────────────────
ssn_valid() {
  local ssn="${1//[- ]/}"
  [[ ${#ssn} -ne 9 ]] && return 1
  local area="${ssn:0:3}"
  local group="${ssn:3:2}"
  local serial="${ssn:5:4}"
  # Strip leading zeros to prevent bash octal interpretation
  local area_num=$((10#$area))
  # SSA exclusions
  [[ "$area" == "000" || "$area" == "666" ]] && return 1
  [[ $area_num -ge 900 && $area_num -le 999 ]] && return 1
  [[ "$group" == "00" ]] && return 1
  [[ "$serial" == "0000" ]] && return 1
  return 0
}

# ── Utility: NHS number MOD-11 validation ────────────────────────────
nhs_valid() {
  local n="${1//[- ]/}"
  [[ ${#n} -ne 10 ]] && return 1
  is_repeated_digit "$n" && return 1
  local sum=0 w=10 i
  for (( i=0; i<9; i++ )); do
    sum=$(( sum + ${n:$i:1} * w ))
    w=$(( w - 1 ))
  done
  local check=$(( 11 - (sum % 11) ))
  [[ $check -eq 11 ]] && check=0
  [[ $check -eq 10 ]] && return 1
  [[ "${n:9:1}" -eq "$check" ]]
}

# ── Utility: NPI Luhn validation (80840 prefix + 10-digit NPI) ───────
npi_valid() {
  local n="${1//[- ]/}"
  [[ ${#n} -ne 10 ]] && return 1
  luhn_valid "80840${n}"
}

# ── Utility: DEA registrant number check digit ───────────────────────
dea_valid() {
  local m="${1//[- ]/}"
  [[ ${#m} -ne 9 ]] && return 1
  [[ "${m:0:2}" =~ ^[A-Za-z]{2}$ ]] || return 1
  local digits="${m:2:7}"
  [[ "$digits" =~ ^[0-9]{7}$ ]] || return 1
  local sum=$(( (${digits:0:1}+${digits:2:1}+${digits:4:1}) + 2*(${digits:1:1}+${digits:3:1}+${digits:5:1}) ))
  [[ $((sum % 10)) -eq ${digits:6:1} ]]
}

# ── Utility: UK National Insurance Number structural validation ──────
# A NINO has NO check digit — validation is prefix rules + suffix only.
# These are HMRC's published constraints (mirrored by the redacta
# clinical-de-identification project, whose UK detector set this pack
# extends Canary with):
#   * 9 chars total: 2 prefix letters, 6 digits, 1 suffix letter A–D
#   * first prefix letter is not one of D F I Q U V
#   * second prefix letter is not one of D F I O Q U V
#   * the 2-letter prefix is not one of BG GB NK KN TN NT ZZ
#     (administrative / never allocated)
# The GOV.UK example "QQ123456C" fails this for free (Q is an invalid
# first letter), so it never needs a placeholder-denylist entry.
nino_valid() {
  local n
  n=$(printf '%s' "$1" | tr -d ' -' | tr '[:lower:]' '[:upper:]')
  [[ ${#n} -ne 9 ]] && return 1
  [[ "$n" =~ ^[A-Z]{2}[0-9]{6}[A-D]$ ]] || return 1
  case "${n:0:1}" in D|F|I|Q|U|V) return 1 ;; esac
  case "${n:1:1}" in D|F|I|O|Q|U|V) return 1 ;; esac
  case "${n:0:2}" in BG|GB|NK|KN|TN|NT|ZZ) return 1 ;; esac
  return 0
}

# ── Utility: Shannon entropy (bits/char), used by generic_secret ────
shannon_entropy() {
  printf '%s\n' "$1" | awk '
    {
      n = length($0)
      for (i = 1; i <= n; i++) {
        c = substr($0, i, 1)
        freq[c]++
      }
    }
    END {
      if (n == 0) { print 0; exit }
      e = 0
      for (c in freq) {
        p = freq[c] / n
        e -= p * log(p) / log(2)
      }
      printf "%.4f", e
    }
  '
}

# ══════════════════════════════════════════════════════════════════════
# CHEAP PRE-GATES — skip whole detector blocks when a match is impossible.
# Plain bash glob tests (no subshell), computed once and reused below.
# ══════════════════════════════════════════════════════════════════════
HAS_DIGIT=0
[[ "$TEXT" == *[0-9]* ]] && HAS_DIGIT=1

HAS_AT=0
[[ "$TEXT" == *@* ]] && HAS_AT=1

HAS_COLON=0
[[ "$TEXT" == *:* ]] && HAS_COLON=1

HAS_SCHEME=0
[[ "$TEXT" == *://* ]] && HAS_SCHEME=1

HAS_0X=0
[[ "$TEXT" == *0x* || "$TEXT" == *0X* ]] && HAS_0X=1

HAS_AWS=0
case "$TEXT" in *AKIA*|*ASIA*|*ABIA*|*ACCA*|*[Aa][Ww][Ss]*) HAS_AWS=1 ;; esac

HAS_LICENSE=0
case "$TEXT" in *[Ll][Ii][Cc][Ee][Nn]*) HAS_LICENSE=1 ;; esac

# Cheap superset glob for the negative-context dampening word list (see
# NEG_CTX_PATTERN / context_window() below). It only gates whether we
# bother computing a per-hit context window at all. Every string the
# precise regex can match also matches one of these globs, so this adds no
# false-negative risk, just lets texts with none of these words skip the
# per-hit work entirely.
HAS_NEG_CTX=0
case "$TEXT" in
  *[Ee][Xx][Aa][Mm][Pp][Ll][Ee]*|*[Ss][Aa][Mm][Pp][Ll][Ee]*|*[Dd][Uu][Mm][Mm][Yy]*| \
  *[Pp][Ll][Aa][Cc][Ee][Hh][Oo][Ll][Dd][Ee][Rr]*|*[Ee].[Gg]*|*[Ll][Oo][Rr][Ee][Mm]*| \
  *[Ii][Pp][Ss][Uu][Mm]*|*[Rr][Ee][Dd][Aa][Cc][Tt][Ee][Dd]*|*[Xx][Xx][Xx][Xx]*| \
  *[Yy][Oo][Uu][Rr]_*|*[Mm][Yy]_*|*[Tt][Oo][Dd][Oo]*|*[Ff][Ii][Xx][Mm][Ee]*| \
  *[Cc][Hh][Aa][Nn][Gg][Ee][Mm][Ee]*|*[Tt][Ee][Ss][Tt]-[Oo][Nn][Ll][Yy]*|*[Ff][Aa][Kk][Ee]*)
    HAS_NEG_CTX=1 ;;
esac
# Pattern re-checked per-hit (only reached when the cheap glob above
# already passed). Matched via bash's own [[ =~ ]] (no subshell/fork) —
# this runs once per HIT, not once per invocation, so avoiding a fork
# here matters. NO \b word boundaries: bash's [[ =~ ]] uses the platform
# C-library regex, and \b is a glibc extension that BSD/macOS regex does
# not implement (it silently never matches there, which disabled the
# whole dampener on macOS — caught by the macOS CI leg). POSIX ERE has no
# word-boundary token common to both glibc and BSD, so we drop bounding
# entirely; that's harmless here because the dampener only LOWERS
# confidence one tier, never drops a hit, so a loose substring match
# (e.g. "sample" inside "resample") at worst under-weights a real hit
# slightly. Case-folding is spelled out per-letter with bracket
# expressions instead of `shopt -s nocasematch`, deliberately: that shopt
# is global for the rest of the process and several OTHER =~ checks below
# rely on case-SENSITIVE matching (e.g. generic_secret's `[[ "$value" =~
# ^[a-z]+$ ]]` — nocasematch would make that match mixed-case secrets too
# and silently suppress them).
NEG_CTX_PATTERN='([Ee][Xx][Aa][Mm][Pp][Ll][Ee]|[Ss][Aa][Mm][Pp][Ll][Ee]|[Dd][Uu][Mm][Mm][Yy]|[Pp][Ll][Aa][Cc][Ee][Hh][Oo][Ll][Dd][Ee][Rr]|[Ll][Oo][Rr][Ee][Mm]|[Ii][Pp][Ss][Uu][Mm]|[Rr][Ee][Dd][Aa][Cc][Tt][Ee][Dd]|[Tt][Oo][Dd][Oo]|[Ff][Ii][Xx][Mm][Ee]|[Cc][Hh][Aa][Nn][Gg][Ee][Mm][Ee]|[Ff][Aa][Kk][Ee]|[Tt][Ee][Ss][Tt]-[Oo][Nn][Ll][Yy])|[Ee]\.[Gg]\.?|[Xx]{4,}|[Yy][Oo][Uu][Rr]_|[Mm][Yy]_'

# ══════════════════════════════════════════════════════════════════════
# DETECTORS
# ══════════════════════════════════════════════════════════════════════

# ── 1. Credit Card Numbers ───────────────────────────────────────────
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    clean="${match//[- ]/}"
    if [[ ${#clean} -ge 13 && ${#clean} -le 19 ]] && luhn_valid "$clean"; then
      emit "credit_card" "$clean" "high" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_o '\b(?:\d[ -]?){13,19}\b')
fi

# ── 2. Email Addresses ──────────────────────────────────────────────
# Require: 2+ char local part, real domain with dot, 2-12 char TLD
# Exclude: URL userinfo (preceded by ://), common false positives, and
# RFC 2606 reserved documentation domains/TLDs (example.com, .test, ...)
#
# The boundary used to be a single lookbehind, (?<![:/@]), applied to the
# WHOLE match start. That's wrong on two counts at once: it blocks a
# "mailto:" prefix from ever matching (the local part starts right after
# a ':', so the lookbehind vetoes the only valid start position — either
# ZERO detection when the local part has no interior '.', e.g.
# "mailto:foo@bar.com", or a TRUNCATED match when it does, e.g.
# "mailto:jane.smith@x.com" matching only "smith@x.com" because "smith"
# is the first substring after a '.' that both starts a \b word boundary
# and isn't immediately preceded by ':'). Fix: allow the match to start
# either right after a literal "mailto:" prefix, OR anywhere the original
# exclusion applies (not preceded by ':', '/', '@'). Both lookbehind
# branches are fixed-width (7 chars / 1 char), which PCRE and Perl both
# support in an alternation even though the two branches differ in
# length. This still blocks the original target — "pass" in
# "https://user:pass@host" is preceded by ':' and isn't preceded by a
# literal "mailto:", so neither branch fires and it still doesn't match.
if [[ $HAS_AT -eq 1 ]]; then
  while IFS= read -r match; do
    local_part="${match%%@*}"
    domain="${match#*@}"
    [[ ${#local_part} -lt 2 ]] && continue
    [[ "$local_part" =~ ^(noreply|no-reply|example|test|user|admin|root|localhost)$ ]] && continue
    domain_lc=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')
    case "$domain_lc" in
      example.com|example.net|example.org) continue ;;
      *.test|*.invalid|*.localhost) continue ;;
    esac
    emit "email" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_oi '(?:(?<=mailto:)|(?<![:/@]))\b[a-z0-9][a-z0-9._%+\-]{0,62}[a-z0-9]@[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,12}\b')
fi

# ── 3. IBAN ──────────────────────────────────────────────────────────
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    if mod97_valid "$match"; then
      emit "iban" "$match" "high" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_o '\b[A-Z]{2}\d{2}[ ]?[\dA-Z]{4}[ ]?[\dA-Z]{4}[ ]?[\dA-Z]{4}[ ]?[\dA-Z]{0,16}\b')
fi

# ── 4. IPv4 Addresses ───────────────────────────────────────────────
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    # Exclude non-PII: private, loopback, link-local, multicast, broadcast, documentation
    if [[ ! "$match" =~ ^(127\.|0\.|255\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|224\.|225\.|226\.|227\.|228\.|229\.|23[0-9]\.|24[0-9]\.|25[0-4]\.|169\.254\.|198\.51\.100\.|203\.0\.113\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]] && [[ "$match" != "255.255.255.255" ]]; then
      emit "ipv4" "$match" "medium" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_o '\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
fi

# ── 5. MAC Addresses ─────────────────────────────────────────────────
# Detected FIRST (and excluded below) so it never gets misread as IPv6.
if [[ $HAS_COLON -eq 1 || "$TEXT" == *-* ]]; then
  while IFS= read -r match; do
    emit "mac_address" "$match" "medium" "$match"
  done < <(echo "$TEXT" | pgrep_oi '\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b')
fi

# ── 6. IPv6 Addresses ───────────────────────────────────────────────
# Require "::" OR (4+ colon-groups AND at least one a-f hex letter), and
# reject anything MAC-shaped. This is what keeps clock times (10:30:45,
# 3 groups, no letters) and MAC addresses (aa:bb:cc:dd:ee:ff, all-hex
# 2-char groups) from being misread as IPv6.
if [[ $HAS_COLON -eq 1 ]]; then
  while IFS= read -r match; do
    [[ "$match" == "::1" || "$match" == "::" ]] && continue
    if [[ "$match" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
      continue  # MAC-shaped (6 groups of exactly 2 hex chars) — not IPv6
    fi
    if [[ "$match" == *"::"* ]]; then
      emit "ipv6" "$match" "medium" "$match"
      continue
    fi
    colons="${match//[^:]/}"
    groups=$(( ${#colons} + 1 ))
    if [[ $groups -ge 4 && "$match" =~ [a-fA-F] ]]; then
      emit "ipv6" "$match" "medium" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_oi '(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:)*::[0-9a-f:]*')
fi

# ── 7. Bitcoin Addresses ────────────────────────────────────────────
# "medium" confidence: base58check_valid() only re-checks format, not
# the real Base58Check SHA256d checksum. See comment on that function.
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    if base58check_valid "$match"; then
      emit "bitcoin_address" "$match" "medium" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_o '\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,89})\b')
fi

# ── 8. Ethereum Addresses ───────────────────────────────────────────
# "medium" confidence: eth_valid() only re-checks format, not the real
# EIP-55 mixed-case (Keccak-256) checksum. See comment on that function.
if [[ $HAS_0X -eq 1 ]]; then
  while IFS= read -r match; do
    if eth_valid "$match"; then
      emit "ethereum_address" "$match" "medium" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_o '\b0x[0-9a-fA-F]{40}\b')
fi

# ── 9. US SSN (separated form: XXX-XX-XXXX with a consistent separator) ─
# Backreference \2 rejects mixed separators like "123-45 6789". Fires
# unconditionally (no keyword needed) since the punctuated shape is
# distinctive enough on its own.
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    digits="${match//[- ]/}"
    if ssn_valid "$digits"; then
      emit "us_ssn" "$digits" "high" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_o '\b(\d{3})([- ])(\d{2})\2(\d{4})\b')
fi

# ── 10. US SSN (bare 9-digit) + ABA Routing — keyword-gated per line ──
# A bare 9-digit number collides with both formats (~1-in-10 chance of
# passing either checksum), so an invoice/tracking/order number reads
# as a false SSN or false ABA routing number about as often as a real
# one does. Only fire when the CONTAINING LINE has topical context.
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r line; do
    [[ "$line" == *[0-9]* ]] || continue
    ssn_kw=0
    case "$line" in
      *[Ss][Ss][Nn]*|*[Ss]ocial*[Ss]ecurity*) ssn_kw=1 ;;
    esac
    aba_kw=0
    case "$line" in
      *[Rr][Oo][Uu][Tt][Ii][Nn][Gg]*|*[Aa][Bb][Aa]*|*[Rr][Tt][Nn]*) aba_kw=1 ;;
    esac
    [[ $ssn_kw -eq 0 && $aba_kw -eq 0 ]] && continue
    while IFS= read -r match; do
      if [[ $ssn_kw -eq 1 ]] && ssn_valid "$match"; then
        emit "us_ssn" "$match" "high" "$line"
      fi
      if [[ $aba_kw -eq 1 ]] && aba_valid "$match"; then
        emit "aba_routing" "$match" "high" "$line"
      fi
    done < <(echo "$line" | pgrep_o '\b[0-9]{9}\b')
  done <<< "$TEXT"
fi

# ── 11. URL with Credentials ────────────────────────────────────────
# Userinfo must precede the first slash — a bare "user:pass" host:port
# like https://host:443/path@thing no longer matches.
if [[ $HAS_SCHEME -eq 1 ]]; then
  while IFS= read -r match; do
    emit "url_credentials" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o 'https?://[^\s/@:]+:[^\s/@]+@[^\s]+')
fi

# ── 12. Database URL Credentials ────────────────────────────────────
if [[ $HAS_SCHEME -eq 1 ]]; then
  case "$TEXT" in
    *postgres*|*mysql*|*mongodb*|*redis*|*amqp*)
      while IFS= read -r match; do
        emit "db_url_credentials" "$match" "high" "$match"
      done < <(echo "$TEXT" | pgrep_o '\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s/@:]+:[^\s/@]+@[^\s]+')
      ;;
  esac
fi

# ── 13. Phone Numbers ───────────────────────────────────────────────
# Use negative lookahead/lookbehind to avoid matching substrings of longer numbers
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    digits=$(echo "$match" | tr -cd '0-9')
    [[ ${#digits} -lt 10 || ${#digits} -gt 15 ]] && continue
    # Exclude if digits are 13+ without formatting (likely CC)
    if [[ ${#digits} -ge 13 ]]; then
      has_format=$(echo "$match" | grep -c '[ ()\-+]' || true)
      [[ "$has_format" -eq 0 ]] && continue
    fi
    # Exclude if Luhn-valid with 13+ digits (credit card)
    if luhn_valid "$digits" && [[ ${#digits} -ge 13 ]]; then
      continue
    fi
    emit "phone_number" "$digits" "medium" "$match"
  done < <(echo "$TEXT" | pgrep_o '(?<!\d)(?:\+?1[ -]?)?(?:\(?\d{3}\)?[ -]?)?\d{3}[ -]?\d{4}(?!\d)|\+\d{1,3}[ -]?\d{4,14}(?!\d)')
fi

# ── 14. US Driver's License (multi-state format) ────────────────────
if [[ $HAS_LICENSE -eq 1 ]]; then
  while IFS= read -r match; do
    emit "us_drivers_license" "$match" "medium" "$match"
  done < <(echo "$TEXT" | pgrep_oi "(?:driver'?s?\\s*(?:license|lic|licence)\\s*(?:#|no\\.?|number)?\\s*[:=]?\\s*)[A-Z]?\\d{4,12}")
fi

# ── 15/16. AWS Access Key + Secret Key ──────────────────────────────
if [[ $HAS_AWS -eq 1 ]]; then
  while IFS= read -r match; do
    emit "aws_access_key" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b')

  # Previously a variable-length lookbehind, which PCRE (and Perl)
  # reject outright — grep -oP / perl both fail to compile it and,
  # since we redirect stderr, this detector fired on nothing, ever.
  # Match the whole "key = value" text instead and strip the label in
  # bash by taking the last 40 characters of the match.
  while IFS= read -r match; do
    secret="${match: -40}"
    emit "aws_secret_key" "$secret" "high" "$match"
  done < <(echo "$TEXT" | pgrep_oi "aws_secret_access_key\\s*[=:]\\s*[\"']?[A-Za-z0-9/+=]{40}")
fi

# ── 17. US Medicare/Medicaid ID (MBI) ────────────────────────────────
# Format: 1C11-AA1-AA11 (C=letter excl S,L,O,I,B,Z; 1=digit excl 0)
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    emit "us_mbi" "$match" "medium" "$match"
  done < <(echo "$TEXT" | pgrep_o '\b[1-9][AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y][0-9]-[A-Z]{2}[0-9]-[A-Z]{2}[0-9]{2}\b')
fi

# ── 18. VIN (Vehicle Identification Number) ──────────────────────────
if [[ $HAS_DIGIT -eq 1 ]]; then
  while IFS= read -r match; do
    # Previously piped through `pgrep_o '^(?!\d+$)'`, a zero-width
    # lookahead-only pattern with no anchor content to actually print —
    # grep -oP prints nothing for a zero-width match, so this stage
    # silently discarded every candidate and VIN never fired. Do the
    # all-digit / all-letter rejection directly in bash instead.
    if [[ "$match" =~ ^[0-9]+$ ]] || [[ "$match" =~ ^[A-Za-z]+$ ]]; then
      continue
    fi
    if vin_valid "$match"; then
      emit "vin" "$match" "high" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_oi '\b[A-HJ-NPR-Z0-9]{17}\b')
fi

# ── 19. GitHub Personal Access Token ─────────────────────────────────
if [[ "$TEXT" == *ghp_* || "$TEXT" == *gho_* || "$TEXT" == *ghu_* || "$TEXT" == *ghs_* || "$TEXT" == *ghr_* || "$TEXT" == *github_pat_* ]]; then
  while IFS= read -r match; do
    emit "github_pat" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b')
fi

# ── 20. GitLab Personal Access Token ─────────────────────────────────
if [[ "$TEXT" == *glpat-* ]]; then
  while IFS= read -r match; do
    emit "gitlab_pat" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\bglpat-[A-Za-z0-9_-]{20}\b')
fi

# ── 21. Slack Token ──────────────────────────────────────────────────
if [[ "$TEXT" == *xox* ]]; then
  while IFS= read -r match; do
    emit "slack_token" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\bxox[abposr]-[A-Za-z0-9-]{10,}\b')
fi

# ── 22. Slack Webhook URL ────────────────────────────────────────────
if [[ "$TEXT" == *hooks.slack.com* ]]; then
  while IFS= read -r match; do
    emit "slack_webhook" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o 'hooks\.slack\.com/services/T[A-Za-z0-9_/]+')
fi

# ── 23. Stripe API Key ───────────────────────────────────────────────
if [[ "$TEXT" == *sk_live_* || "$TEXT" == *sk_test_* || "$TEXT" == *rk_live_* || "$TEXT" == *rk_test_* ]]; then
  while IFS= read -r match; do
    emit "stripe_api_key" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b')
fi

# ── 24. Anthropic API Key ────────────────────────────────────────────
if [[ "$TEXT" == *sk-ant-* ]]; then
  while IFS= read -r match; do
    emit "anthropic_api_key" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\bsk-ant-[A-Za-z0-9_-]{20,}\b')
fi

# ── 25. OpenAI API Key ───────────────────────────────────────────────
# Negative lookahead excludes sk-ant- so this never double-fires
# alongside anthropic_api_key on the same value.
if [[ "$TEXT" == *sk-* ]]; then
  while IFS= read -r match; do
    emit "openai_api_key" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b')
fi

# ── 26. Google API Key ───────────────────────────────────────────────
if [[ "$TEXT" == *AIza* ]]; then
  while IFS= read -r match; do
    emit "google_api_key" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\bAIza[0-9A-Za-z_-]{35}\b')
fi

# ── 27. SendGrid API Key ─────────────────────────────────────────────
if [[ "$TEXT" == *SG.* ]]; then
  while IFS= read -r match; do
    emit "sendgrid_api_key" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b')
fi

# ── 28. npm Token ─────────────────────────────────────────────────────
if [[ "$TEXT" == *npm_* ]]; then
  while IFS= read -r match; do
    emit "npm_token" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\bnpm_[A-Za-z0-9]{36}\b')
fi

# ── 29. JWT ──────────────────────────────────────────────────────────
if [[ "$TEXT" == *eyJ* ]]; then
  while IFS= read -r match; do
    emit "jwt" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')
fi

# ── 30. Private Key Block ────────────────────────────────────────────
if [[ "$TEXT" == *BEGIN* ]]; then
  while IFS= read -r match; do
    emit "private_key_block" "$match" "high" "$match"
  done < <(echo "$TEXT" | pgrep_o '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----')
fi

# ── 31. Generic Secret (entropy-gated) ───────────────────────────────
# Fires only when the assigned value both looks random (Shannon entropy
# >= 3.5 bits/char) AND isn't plain lowercase prose/words — this is what
# keeps `password = changeme` and `token = mytokenvalue` silent while
# still catching `api_key = Tg7Rk2Xy9Bn4Wq8Lp3Vz6Cm1`.
if [[ $HAS_COLON -eq 1 || "$TEXT" == *=* ]]; then
  while IFS= read -r match; do
    value=$(printf '%s' "$match" | pgrep_o '[A-Za-z0-9+/_=-]{16,64}$')
    [[ -z "$value" ]] && continue
    [[ "$value" =~ ^[a-z]+$ ]] && continue
    ent=$(shannon_entropy "$value")
    if awk -v e="$ent" 'BEGIN{exit !(e>=3.5)}'; then
      emit "generic_secret" "$value" "medium" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_oi '\b(?:api[_-]?key|secret|token|password|passwd|auth)\b\s*[:=]\s*["'"'"']?[A-Za-z0-9+/_=-]{16,64}')
fi

# ── 32. NHS Number (UK) ──────────────────────────────────────────────
# Only fires when "nhs" appears in the text — a bare mod-11-valid
# 10-digit number is otherwise indistinguishable from many other IDs.
if [[ $HAS_DIGIT -eq 1 ]]; then
  case "$TEXT" in
    *[Nn][Hh][Ss]*)
      while IFS= read -r match; do
        if nhs_valid "$match"; then
          emit "nhs_number" "${match//[- ]/}" "high" "$match"
        fi
      done < <(echo "$TEXT" | pgrep_o '\b\d{3}[ -]?\d{3}[ -]?\d{4}\b')
      ;;
  esac
fi

# ── 33. Canadian SIN ─────────────────────────────────────────────────
# "sin" is too short/common a substring to gate on directly (matches
# "using", "since", ...), so text_has_keyword's precise \bsin\b regex
# is the real gate — but it spawns a subshell, so only pay for it when
# a cheap superset glob ("sin" or "insuran") already passed. Every
# string that can match \bsin\b|social insurance contains one of these
# two substrings, so this adds no false-negative risk.
if [[ $HAS_DIGIT -eq 1 ]]; then
  case "$TEXT" in
    *[Ss][Ii][Nn]*|*[Ii]nsuran*)
      if text_has_keyword "$TEXT" '\bsin\b|social insurance'; then
        while IFS= read -r match; do
          digits="${match//[- ]/}"
          if luhn_valid "$digits"; then
            emit "sin_canadian" "$digits" "high" "$match"
          fi
        done < <(echo "$TEXT" | pgrep_o '\b\d{3}[ -]?\d{3}[ -]?\d{3}\b')
      fi
      ;;
  esac
fi

# ── 34. US NPI (National Provider Identifier) ────────────────────────
if [[ $HAS_DIGIT -eq 1 ]]; then
  case "$TEXT" in
    *[Nn][Pp][Ii]*)
      while IFS= read -r match; do
        if npi_valid "$match"; then
          emit "npi_number" "$match" "high" "$match"
        fi
      done < <(echo "$TEXT" | pgrep_o '\b\d{10}\b')
      ;;
  esac
fi

# ── 35. US DEA Number ────────────────────────────────────────────────
if [[ $HAS_DIGIT -eq 1 ]]; then
  case "$TEXT" in
    *[Dd][Ee][Aa]*)
      while IFS= read -r match; do
        if dea_valid "$match"; then
          emit "dea_number" "$match" "high" "$match"
        fi
      done < <(echo "$TEXT" | pgrep_o '\b[A-Za-z]{2}\d{7}\b')
      ;;
  esac
fi

# ── 36. US ITIN ───────────────────────────────────────────────────────
# No check digit exists for ITIN — the 9xx prefix + narrow group-number
# range (70-88, 90-92, 94-99) is the only validation available. Fires
# at "high" with the itin keyword nearby, "medium" without it.
if [[ $HAS_DIGIT -eq 1 ]]; then
  itin_kw=0
  case "$TEXT" in *[Ii][Tt][Ii][Nn]*) itin_kw=1 ;; esac
  while IFS= read -r match; do
    digits="${match//[- ]/}"
    if [[ $itin_kw -eq 1 ]]; then
      emit "us_itin" "$digits" "high" "$match"
    else
      emit "us_itin" "$digits" "medium" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_o '\b9\d{2}[- ]?(?:7\d|8[0-8]|9[0-2]|9[4-9])[- ]?\d{4}\b')
fi

# ── 37. UK National Insurance Number (NINO) ──────────────────────────
# The UK's tax/identity number — the closest analogue to a US SSN, and a
# gap in Canary's UK coverage next to the NHS number it already catches.
# nino_valid() enforces HMRC's prefix rules + A–D suffix; there is no
# check digit (see that function). Like us_itin, this fires "high" when a
# national-insurance keyword is nearby and "medium" on the validated
# shape alone — the prefix rules make the shape distinctive enough to
# count without a keyword, but not to claim the higher tier.
if [[ $HAS_DIGIT -eq 1 ]]; then
  nino_kw=0
  case "$TEXT" in
    *[Nn][Ii][Nn][Oo]*|*[Nn]ational[[:space:]][Ii]nsurance*|*[Nn][Ii][[:space:]][Nn]umber*) nino_kw=1 ;;
  esac
  while IFS= read -r match; do
    norm=$(printf '%s' "$match" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
    if nino_valid "$norm"; then
      if [[ $nino_kw -eq 1 ]]; then
        emit "uk_nino" "$norm" "high" "$match"
      else
        emit "uk_nino" "$norm" "medium" "$match"
      fi
    fi
  done < <(echo "$TEXT" | pgrep_oi '\b[A-Z]{2} ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D]\b')
fi

# ── 38. UK Postcode ──────────────────────────────────────────────────
# A full UK postcode narrows to roughly 15 households, so it is PII under
# UK-GDPR (and one of the identifiers the redacta research redacts).
# Royal Mail postcodes have no check digit, so this is format-only.
# Precision guard: the canonical *spaced* form ("SW1A 1AA") is
# distinctive enough to count on its own (medium), but the *unspaced*
# form ("SW1A1AA") collides with ordinary alphanumeric tokens (hex
# fragments, product codes), so it only counts when an address/postcode
# keyword is present. A keyword lifts either form to "high".
if [[ $HAS_DIGIT -eq 1 ]]; then
  pc_kw=0
  case "$TEXT" in
    *[Pp][Oo][Ss][Tt]*[Cc][Oo][Dd][Ee]*|*[Aa][Dd][Dd][Rr][Ee][Ss][Ss]*) pc_kw=1 ;;
  esac
  while IFS= read -r match; do
    case "$match" in
      *" "*) spaced=1 ;;
      *) spaced=0 ;;
    esac
    [[ $spaced -eq 0 && $pc_kw -eq 0 ]] && continue
    norm=$(printf '%s' "$match" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
    if [[ $pc_kw -eq 1 ]]; then
      emit "uk_postcode" "$norm" "high" "$match"
    else
      emit "uk_postcode" "$norm" "medium" "$match"
    fi
  done < <(echo "$TEXT" | pgrep_oi '\b(?:GIR ?0AA|[A-Z]{1,2}[0-9][A-Z0-9]? ?[0-9][A-Z]{2})\b')
fi

exit 0
