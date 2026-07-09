#!/usr/bin/env bash
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# audit-plugins.sh — Scan INSTALLED Claude Code extensions (skills, agents,
# plugins, MCP/settings configs) for leaked secrets and suspicious /
# exfiltration patterns. Report-only tool: it never mutates the scanned
# files and never writes to leaks.jsonl unless --record is passed.
#
# Usage: audit-plugins.sh [--json] [--record] [--strict] [--help]
#
# Scans (when present):
#   ~/.claude/skills/    ~/.claude/agents/   ~/.claude/plugins/ (incl. marketplaces/)
#   ./.claude/ (project, recursive)
#   ~/.claude/settings.json   ./.claude/settings.json   ./.mcp.json
#
# Portability: bash 3.2+, BSD+GNU tools, jq optional (degrades gracefully).
# set -e note: every command that may legitimately fail (grep no-match,
# missing optional tool, etc.) is guarded with `|| true` or a conditional —
# see CONTRIBUTING.md's "Code Style" section for the house convention.

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════
# Setup
# ══════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTORS="$SCRIPT_DIR/detectors.sh"
SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
LEAKS_FILE="$SONOMOS_DIR/leaks.jsonl"

HAVE_JQ=false
command -v jq >/dev/null 2>&1 && HAVE_JQ=true

HAVE_FILE=false
command -v file >/dev/null 2>&1 && HAVE_FILE=true

HAVE_GREP_P=false
echo "test" | grep -oP 'test' &>/dev/null && HAVE_GREP_P=true

JSON_MODE=false
RECORD_MODE=false
STRICT_MODE=false

usage() {
  cat <<'EOF'
Usage: audit-plugins.sh [--json] [--record] [--strict] [--help]

Scan installed Claude Code extensions (skills, agents, plugins, and
MCP/settings configs) for leaked secrets and suspicious exfiltration
patterns (curl-pipe-shell, webhook collector domains, credential-file
reads, env harvesting, hidden unicode, wildcard tool permissions, ...).

Scans (when present):
  ~/.claude/skills/   ~/.claude/agents/   ~/.claude/plugins/ (incl. marketplaces/)
  ./.claude/ (project, recursive)
  ~/.claude/settings.json   ./.claude/settings.json   ./.mcp.json

Options:
  --json     Emit a JSON report instead of human-readable text
  --record   Append one leaks.jsonl summary line per flagged extension
  --strict   Exit 2 if any CRITICAL-severity finding exists
  --help     Show this help and exit

This tool is report-only: findings are never written to leaks.jsonl
unless --record is given, and even then only a per-extension score
summary is recorded — never a raw secret value. Detected secrets are
always shown pre-redacted by detectors.sh.

False-positive suppression:
  - A line containing the literal text "# canary-ignore" is never flagged.
  - In .md files, a fenced ``` code block is treated as a documentation
    example (and skipped) when the line immediately before the opening
    fence contains the word "example".
EOF
}

for arg in "$@"; do
  case "$arg" in
    --json) JSON_MODE=true ;;
    --record) RECORD_MODE=true ;;
    --strict) STRICT_MODE=true ;;
    --help|-h) usage; exit 0 ;;
    *) echo "audit-plugins.sh: unknown option: $arg" >&2; usage >&2; exit 1 ;;
  esac
done

TMPDIR_AUDIT="$(mktemp -d "${TMPDIR:-/tmp}/canary-audit.XXXXXX" 2>/dev/null || true)"
if [[ -z "$TMPDIR_AUDIT" || ! -d "$TMPDIR_AUDIT" ]]; then
  echo "audit-plugins.sh: could not create a temp directory" >&2
  exit 0
fi
trap 'rm -rf "$TMPDIR_AUDIT"' EXIT

FINDINGS_TSV="$TMPDIR_AUDIT/findings.tsv"
EXT_LIST="$TMPDIR_AUDIT/extensions.txt"
: > "$FINDINGS_TSV"
: > "$EXT_LIST"

# Per-file example-fence cache (recomputed per .md file being rule-scanned).
CUR_EXFENCE=""

# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

# json_escape STR — minimal JSON string escaping for the no-jq fallback path.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}

# is_text_file FILE — true (0) if the file looks like text and is worth
# scanning; false (1) to skip it. Uses `file` when available, otherwise a
# known-binary extension denylist (defaults to "scan it" for unknowns).
is_text_file() {
  local f="$1"
  if $HAVE_FILE; then
    if file -b "$f" 2>/dev/null | grep -qi 'text\|json\|script\|source\|empty\|ascii'; then
      return 0
    else
      return 1
    fi
  fi
  case "$f" in
    *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.pdf|*.zip|*.tar|*.gz|*.tgz|*.bz2|*.xz|*.7z| \
    *.so|*.dylib|*.dll|*.exe|*.bin|*.woff|*.woff2|*.ttf|*.otf|*.mp3|*.mp4|*.mov|*.wasm| \
    *.pyc|*.class|*.jar|*.o|*.a)
      return 1 ;;
    *) return 0 ;;
  esac
}

# extension_name_for FILE — group a scanned file under a stable top-level
# "extension" name (a skill dir, an agent file, a plugin dir, or a lone
# config file) so findings can be scored per-extension rather than per-file.
extension_name_for() {
  local f="$1" home="$HOME" pc="$PWD/.claude"
  case "$f" in
    "$home/.claude/skills/"*)
      local rest="${f#"$home"/.claude/skills/}"
      printf 'skills/%s\n' "${rest%%/*}"
      ;;
    "$home/.claude/agents/"*)
      local rest="${f#"$home"/.claude/agents/}"
      rest="${rest%%/*}"
      printf 'agents/%s\n' "${rest%.md}"
      ;;
    "$home/.claude/plugins/marketplaces/"*)
      local rest="${f#"$home"/.claude/plugins/marketplaces/}"
      local mp="${rest%%/*}"
      local rest2="${rest#*/}"
      printf 'plugins/marketplaces/%s/%s\n' "$mp" "${rest2%%/*}"
      ;;
    "$home/.claude/plugins/"*)
      local rest="${f#"$home"/.claude/plugins/}"
      printf 'plugins/%s\n' "${rest%%/*}"
      ;;
    "$pc/skills/"*)
      local rest="${f#"$pc"/skills/}"
      printf 'project:.claude/skills/%s\n' "${rest%%/*}"
      ;;
    "$pc/agents/"*)
      local rest="${f#"$pc"/agents/}"
      rest="${rest%%/*}"
      printf 'project:.claude/agents/%s\n' "${rest%.md}"
      ;;
    "$pc/settings.json")
      printf 'project:.claude/settings.json\n'
      ;;
    "$pc/"*)
      local rest="${f#"$pc"/}"
      printf 'project:.claude/%s\n' "${rest%%/*}"
      ;;
    "$home/.claude/settings.json")
      printf 'settings:~/.claude/settings.json\n'
      ;;
    "$PWD/.mcp.json")
      printf 'mcp:.mcp.json\n'
      ;;
    *)
      printf 'other:%s\n' "$f"
      ;;
  esac
}

# nearest_plugin_name FILE — walk up from FILE looking for a plugin
# manifest (.claude-plugin/plugin.json or plugin.json) and print its
# "name" field, or empty if none is found within a bounded depth.
nearest_plugin_name() {
  local dir depth pj
  dir="$(dirname "$1")"
  depth=0
  while [[ "$dir" != "/" && -n "$dir" && $depth -lt 12 ]]; do
    pj=""
    [[ -f "$dir/.claude-plugin/plugin.json" ]] && pj="$dir/.claude-plugin/plugin.json"
    [[ -z "$pj" && -f "$dir/plugin.json" ]] && pj="$dir/plugin.json"
    if [[ -n "$pj" ]]; then
      if $HAVE_JQ; then
        jq -r '.name // empty' "$pj" 2>/dev/null || true
      else
        grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$pj" 2>/dev/null | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/'
      fi
      return 0
    fi
    dir="$(dirname "$dir")"
    depth=$((depth + 1))
  done
  printf ''
}

# is_canary_extension FILE — true if FILE belongs to Canary's own plugin
# (by path component or by its plugin.json name), so it should be skipped:
# Canary legitimately ships the detector pattern library and rule text
# that this very scanner would otherwise flag.
is_canary_extension() {
  local f="$1"
  case "$f" in
    */canary/*) return 0 ;;
  esac
  local pname
  pname="$(nearest_plugin_name "$f")"
  pname="$(printf '%s' "$pname" | tr '[:upper:]' '[:lower:]')"
  [[ "$pname" == "canary" ]] && return 0
  return 1
}

# compute_example_fences FILE — print the line numbers (1-indexed,
# inclusive of the fence markers) that fall inside a ``` fenced code block
# whose immediately preceding non-fence line contains the word "example".
# This is a deliberately simple heuristic, documented in --help.
compute_example_fences() {
  awk '
    /^```/ {
      if (in_fence == 0) {
        in_fence = 1
        fence_start = NR
        is_example = prev_had_example
      } else {
        in_fence = 0
        if (is_example) { for (i = fence_start; i <= NR; i++) print i }
        is_example = 0
      }
      prev_had_example = 0
      next
    }
    {
      if (in_fence == 0) {
        prev_had_example = (index(tolower($0), "example") > 0) ? 1 : 0
      }
    }
  ' "$1" 2>/dev/null || true
}

# in_example_fence LINENO — membership test against $CUR_EXFENCE (set by
# the caller before scanning a given .md file).
in_example_fence() {
  local lineno="$1"
  [[ -z "$CUR_EXFENCE" || ! -s "$CUR_EXFENCE" ]] && return 1
  grep -qx "$lineno" "$CUR_EXFENCE" 2>/dev/null
}

# band_for_score SCORE — map a 0-100 score to a severity band.
band_for_score() {
  local s="$1"
  if   [[ "$s" -ge 81 ]]; then printf 'CRITICAL\n'
  elif [[ "$s" -ge 51 ]]; then printf 'HIGH\n'
  elif [[ "$s" -ge 21 ]]; then printf 'MEDIUM\n'
  else                         printf 'LOW\n'
  fi
}

# display_path FILE — shorten an absolute path under $HOME or $PWD for
# human-readable report lines (~/... or ./...). The JSON report keeps
# the full absolute path instead, for unambiguous machine consumption.
display_path() {
  local p="$1"
  case "$p" in
    "$HOME"/*) printf '~/%s\n' "${p#"$HOME"/}" ;;
    "$PWD"/*)  printf './%s\n' "${p#"$PWD"/}" ;;
    *)         printf '%s\n' "$p" ;;
  esac
}

# ══════════════════════════════════════════════════════════════════════
# Rule table (grep -E based exfiltration / suspicious-pattern rules)
# ══════════════════════════════════════════════════════════════════════
# Patterns are written as portable POSIX ERE (BSD + GNU grep -E): `\s` is
# a GNU-only extension, so whitespace uses [[:space:]] instead; `\|`,
# `\(`, `\)`, `\*` are literal-char escapes, which both BSD and GNU grep
# -E treat the same way. Each rule: id, severity, ERE pattern, description.

# scan_rule FILE EXT RULE_ID SEVERITY PATTERN DESCRIPTION [MD_DOWNGRADE]
scan_rule() {
  local file="$1" ext="$2" rule_id="$3" severity="$4" pattern="$5" desc="$6" md_downgrade="${7:-}"
  local sev="$severity"
  if [[ -n "$md_downgrade" && "$file" == *.md ]]; then
    sev="$md_downgrade"
  fi
  local matches
  matches=$(grep -noE "$pattern" "$file" 2>/dev/null || true)
  [[ -z "$matches" ]] && return 0
  while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    local lineno="${m%%:*}"
    local linetext
    linetext=$(sed -n "${lineno}p" "$file" 2>/dev/null || true)
    case "$linetext" in *"# canary-ignore"*) continue ;; esac
    if [[ "$file" == *.md ]] && in_example_fence "$lineno"; then continue; fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ext" "$sev" "$file" "$lineno" "$rule_id" "$desc" >> "$FINDINGS_TSV"
  done <<< "$matches"
}

# scan_hidden_unicode FILE EXT — zero-width / RTL-override characters
# (U+200B-U+200F, U+202A-U+202E), a known prompt-injection hiding trick.
# Skipped gracefully if neither grep -P nor perl is available.
scan_hidden_unicode() {
  local file="$1" ext="$2"
  local pat='[\x{200B}-\x{200F}\x{202A}-\x{202E}]'
  local matches=""
  if $HAVE_GREP_P; then
    matches=$(grep -noP "$pat" "$file" 2>/dev/null || true)
  elif command -v perl >/dev/null 2>&1; then
    matches=$(perl -ne 'print "$.:hidden\n" if /[\x{200B}-\x{200F}\x{202A}-\x{202E}]/' "$file" 2>/dev/null || true)
  else
    return 0
  fi
  [[ -z "$matches" ]] && return 0
  while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    local lineno="${m%%:*}"
    local linetext
    linetext=$(sed -n "${lineno}p" "$file" 2>/dev/null || true)
    case "$linetext" in *"# canary-ignore"*) continue ;; esac
    if [[ "$file" == *.md ]] && in_example_fence "$lineno"; then continue; fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ext" "HIGH" "$file" "$lineno" "hidden-unicode" \
      "contains hidden zero-width or RTL-override characters (possible hidden instructions)" >> "$FINDINGS_TSV"
  done <<< "$matches"
}

run_rule_table() {
  local f="$1" ext="$2"
  CUR_EXFENCE=""
  if [[ "$f" == *.md ]]; then
    CUR_EXFENCE="$TMPDIR_AUDIT/exfence.$$.tmp"
    compute_example_fences "$f" > "$CUR_EXFENCE"
  fi

  scan_rule "$f" "$ext" "curl-pipe-shell" "HIGH" \
    'curl[^|]*\|[[:space:]]*(ba)?sh' \
    "pipes curl output directly into a shell"

  scan_rule "$f" "$ext" "base64-decode-exec" "HIGH" \
    'base64[[:space:]]+(-d|--decode).*\|(.*sh|.*eval)|eval.*base64' \
    "decodes base64 output and executes/evals it"

  scan_rule "$f" "$ext" "collector-domain" "CRITICAL" \
    'discord\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|ngrok\.io|requestbin|pipedream\.net' \
    "references a known data-exfiltration/webhook collector domain"

  scan_rule "$f" "$ext" "credential-path-read" "HIGH" \
    '\.ssh/id_[a-z0-9]+|\.aws/credentials|\.kube/config|\.netrc|\.npmrc' \
    "reads a well-known credential file path" "MEDIUM"

  scan_rule "$f" "$ext" "env-harvesting" "CRITICAL" \
    'env[[:space:]]*\|[[:space:]]*(curl|nc|base64)|printenv[[:space:]]*\|' \
    "dumps environment variables into a pipe (possible credential harvesting)"

  scan_rule "$f" "$ext" "wildcard-tool-permissions" "MEDIUM" \
    'allowed-tools:[[:space:]]*\*|"Bash\(\*\)"' \
    "grants unrestricted tool/bash permissions"

  scan_rule "$f" "$ext" "agent-snooping" "LOW" \
    '\.claude/(skills|agents|plugins)' \
    "references other skills/agents/plugins directories"

  scan_hidden_unicode "$f" "$ext"
}

# run_detectors FILE EXT CONTENT — delegate to the shared detectors.sh
# secret/PII library (contract: text in, JSONL hits out). Hits are mapped
# to a severity band from their confidence (detectors.sh only ever emits
# "high" or "medium"): high -> HIGH, medium -> MEDIUM. detectors.sh does
# not report a position, so these findings are file-level (line "-"),
# unlike rule-table findings which carry an exact line number.
run_detectors() {
  local f="$1" ext="$2" content="$3"
  [[ -z "$content" ]] && return 0
  [[ ! -f "$DETECTORS" ]] && return 0
  local hits
  hits=$(bash "$DETECTORS" "$content" 2>/dev/null || true)
  [[ -z "$hits" ]] && return 0
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    local dtype dvalue dconf
    if $HAVE_JQ; then
      dtype=$(printf '%s' "$hit" | jq -r '.type // "unknown"' 2>/dev/null || echo unknown)
      dvalue=$(printf '%s' "$hit" | jq -r '.value // "••••"' 2>/dev/null || echo '••••')
      dconf=$(printf '%s' "$hit" | jq -r '.confidence // "medium"' 2>/dev/null || echo medium)
    else
      dtype=$(printf '%s' "$hit" | grep -o '"type":"[^"]*"' | head -1 | sed -E 's/.*:"([^"]*)"/\1/')
      dvalue=$(printf '%s' "$hit" | grep -o '"value":"[^"]*"' | head -1 | sed -E 's/.*:"([^"]*)"/\1/')
      dconf=$(printf '%s' "$hit" | grep -o '"confidence":"[^"]*"' | head -1 | sed -E 's/.*:"([^"]*)"/\1/')
      [[ -z "$dtype" ]] && dtype="unknown"
      [[ -z "$dvalue" ]] && dvalue="••••"
      [[ -z "$dconf" ]] && dconf="medium"
    fi
    local sev="MEDIUM"
    [[ "$dconf" == "high" ]] && sev="HIGH"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ext" "$sev" "$f" "-" "detector:$dtype" \
      "leaked secret/PII found by the shared detector library (redacted: $dvalue)" >> "$FINDINGS_TSV"
  done <<< "$hits"
}

# ══════════════════════════════════════════════════════════════════════
# Walk
# ══════════════════════════════════════════════════════════════════════

process_file() {
  local f="$1"

  is_canary_extension "$f" && return 0

  local size
  size=$(wc -c < "$f" 2>/dev/null || echo 0)
  size="${size//[[:space:]]/}"
  [[ -z "$size" ]] && size=0
  [[ "$size" -gt 204800 ]] && return 0
  [[ "$size" -eq 0 ]] && return 0

  is_text_file "$f" || return 0

  local ext
  ext="$(extension_name_for "$f")"
  [[ -z "$ext" ]] && return 0
  printf '%s\n' "$ext" >> "$EXT_LIST"

  local content
  content=$(cat "$f" 2>/dev/null || true)
  [[ -z "$content" ]] && return 0

  # canary-ignore applies to both the rule table (checked per matched
  # line in scan_rule) and the detectors.sh pass (line dropped up front,
  # since detectors.sh scans the whole blob at once and reports no line).
  local filtered
  filtered=$(printf '%s\n' "$content" | grep -v '# canary-ignore' || true)

  run_detectors "$f" "$ext" "$filtered"
  run_rule_table "$f" "$ext"
}

ROOTS=()
[[ -d "$HOME/.claude/skills" ]] && ROOTS+=("$HOME/.claude/skills")
[[ -d "$HOME/.claude/agents" ]] && ROOTS+=("$HOME/.claude/agents")
[[ -d "$HOME/.claude/plugins" ]] && ROOTS+=("$HOME/.claude/plugins")
[[ -d "$PWD/.claude" ]] && ROOTS+=("$PWD/.claude")

STANDALONE=()
[[ -f "$HOME/.claude/settings.json" ]] && STANDALONE+=("$HOME/.claude/settings.json")
[[ -f "$PWD/.mcp.json" ]] && STANDALONE+=("$PWD/.mcp.json")
# Note: $PWD/.claude/settings.json is already covered by the $PWD/.claude
# recursive walk above (extension_name_for gives it its own bucket).

# Collect every candidate path into one list and de-duplicate by exact
# path string before scanning anything. This matters because the roots
# above can legitimately overlap or nest — e.g. $PWD/.claude IS
# $HOME/.claude when the shell's cwd is the home directory itself — and
# without de-duplication a file reachable from two roots would be
# scanned (and scored) twice.
ALL_FILES="$TMPDIR_AUDIT/all_files.txt"
: > "$ALL_FILES"

for root in "${ROOTS[@]+"${ROOTS[@]}"}"; do
  find "$root" \( -path '*/node_modules/*' -o -path '*/.git/*' \) -prune -o -type f -print 2>/dev/null >> "$ALL_FILES" || true
done
for f in "${STANDALONE[@]+"${STANDALONE[@]}"}"; do
  printf '%s\n' "$f" >> "$ALL_FILES"
done

sort -u "$ALL_FILES" -o "$ALL_FILES" 2>/dev/null || true

while IFS= read -r f; do
  [[ -n "$f" ]] && process_file "$f"
done < "$ALL_FILES"

# ══════════════════════════════════════════════════════════════════════
# Score
# ══════════════════════════════════════════════════════════════════════

EXT_ALL="$TMPDIR_AUDIT/ext_all.txt"
sort -u "$EXT_LIST" > "$EXT_ALL" 2>/dev/null || : > "$EXT_ALL"

EXT_SCORES_FINDINGS="$TMPDIR_AUDIT/ext_scores_findings.tsv"
awk -F'\t' '
  {
    ext = $1; sev = $2
    if (sev == "CRITICAL") score[ext] += 50
    else if (sev == "HIGH") score[ext] += 25
    else if (sev == "MEDIUM") score[ext] += 10
    else if (sev == "LOW") score[ext] += 5
  }
  END {
    for (e in score) {
      s = score[e]; if (s > 100) s = 100
      print e "\t" s
    }
  }
' "$FINDINGS_TSV" > "$EXT_SCORES_FINDINGS" 2>/dev/null || : > "$EXT_SCORES_FINDINGS"

EXT_SCORES="$TMPDIR_AUDIT/ext_scores.tsv"
: > "$EXT_SCORES"
while IFS= read -r e; do
  [[ -z "$e" ]] && continue
  sc=$(awk -F'\t' -v want="$e" '$1 == want { print $2 }' "$EXT_SCORES_FINDINGS" 2>/dev/null || true)
  [[ -z "$sc" ]] && sc=0
  printf '%s\t%s\n' "$e" "$sc" >> "$EXT_SCORES"
done < "$EXT_ALL"

# Sort worst-first (score desc, then name) for both report modes.
if [[ -s "$EXT_SCORES" ]]; then
  sort -t "$(printf '\t')" -k2,2nr -k1,1 "$EXT_SCORES" -o "$EXT_SCORES" 2>/dev/null || true
fi

# ══════════════════════════════════════════════════════════════════════
# Report — human
# ══════════════════════════════════════════════════════════════════════

print_human_report() {
  local total_ext=0 flagged=0 crit=0 high=0 med=0 low=0
  echo "══════════════════════════════════════════════════════════"
  echo " CANARY — Extension Audit"
  echo "══════════════════════════════════════════════════════════"
  echo ""

  if [[ ! -s "$EXT_SCORES" ]]; then
    echo "Nothing to scan — no ~/.claude/{skills,agents,plugins}, ./.claude/,"
    echo "or MCP/settings config files were found."
  fi

  while IFS=$'\t' read -r ext score; do
    [[ -z "$ext" ]] && continue
    total_ext=$((total_ext + 1))
    local band
    band="$(band_for_score "$score")"
    if [[ "$score" -gt 0 ]]; then
      flagged=$((flagged + 1))
      printf '%s  [%s]  score %s/100\n' "$ext" "$band" "$score"
      while IFS=$'\t' read -r fext fsev ffile fline frule fdesc; do
        [[ "$fext" != "$ext" ]] && continue
        case "$fsev" in
          CRITICAL) crit=$((crit + 1)) ;;
          HIGH) high=$((high + 1)) ;;
          MEDIUM) med=$((med + 1)) ;;
          LOW) low=$((low + 1)) ;;
        esac
        local shown_file
        shown_file="$(display_path "$ffile")"
        if [[ "$fline" == "-" ]]; then
          printf '    [%-8s] %s — %s (%s)\n' "$fsev" "$shown_file" "$fdesc" "$frule"
        else
          printf '    [%-8s] %s:%s — %s (%s)\n' "$fsev" "$shown_file" "$fline" "$fdesc" "$frule"
        fi
      done < "$FINDINGS_TSV"
      echo ""
    else
      printf '%s  [clean]  score 0/100\n' "$ext"
    fi
  done < "$EXT_SCORES"

  echo "──────────────────────────────────────────────────────────"
  printf 'Extensions scanned: %d   Flagged: %d\n' "$total_ext" "$flagged"
  printf 'Findings — CRITICAL: %d  HIGH: %d  MEDIUM: %d  LOW: %d\n' "$crit" "$high" "$med" "$low"
  echo "══════════════════════════════════════════════════════════"
}

# ══════════════════════════════════════════════════════════════════════
# Report — JSON
# ══════════════════════════════════════════════════════════════════════

print_json_report() {
  if $HAVE_JQ; then
    local scores_jsonl="$TMPDIR_AUDIT/scores.jsonl"
    local findings_jsonl="$TMPDIR_AUDIT/findings.jsonl"
    jq -R -c 'select(length > 0) | split("\t") | {extension: .[0], score: (.[1] | tonumber)}' \
      "$EXT_SCORES" > "$scores_jsonl" 2>/dev/null || : > "$scores_jsonl"
    jq -R -c 'select(length > 0) | split("\t") | {extension: .[0], severity: .[1], file: .[2], line: .[3], rule: .[4], description: .[5]}' \
      "$FINDINGS_TSV" > "$findings_jsonl" 2>/dev/null || : > "$findings_jsonl"

    jq -n -c \
      --slurpfile scores "$scores_jsonl" \
      --slurpfile findings "$findings_jsonl" \
      '
      ($findings | group_by(.extension) | map({key: .[0].extension, value: .}) | from_entries) as $fmap
      | {
          version: 1,
          extensions: (
            $scores
            | map(. + {
                band: (if .score >= 81 then "CRITICAL" elif .score >= 51 then "HIGH" elif .score >= 21 then "MEDIUM" else "LOW" end),
                findings: ($fmap[.extension] // [])
              })
            | sort_by(-.score)
          ),
          totals: {
            extensions_scanned: ($scores | length),
            flagged: ($scores | map(select(.score > 0)) | length),
            findings_by_severity: (
              ["CRITICAL","HIGH","MEDIUM","LOW"] as $sevs
              | reduce $sevs[] as $s ({}; . + {($s): ([$findings[] | select(.severity == $s)] | length)})
            )
          }
        }
      '
    return 0
  fi

  # No jq — hand-build minimal JSON with explicit escaping.
  printf '{\n  "version": 1,\n  "jq_available": false,\n  "extensions": [\n'
  local first=true total_ext=0 flagged=0
  while IFS=$'\t' read -r ext score; do
    [[ -z "$ext" ]] && continue
    total_ext=$((total_ext + 1))
    [[ "$score" -gt 0 ]] && flagged=$((flagged + 1))
    local band
    band="$(band_for_score "$score")"
    $first || printf ',\n'
    first=false
    printf '    {"extension":"%s","score":%s,"band":"%s","findings":[' \
      "$(json_escape "$ext")" "$score" "$band"
    local ffirst=true
    while IFS=$'\t' read -r fext fsev ffile fline frule fdesc; do
      [[ "$fext" != "$ext" ]] && continue
      $ffirst || printf ','
      ffirst=false
      printf '{"severity":"%s","file":"%s","line":"%s","rule":"%s","description":"%s"}' \
        "$(json_escape "$fsev")" "$(json_escape "$ffile")" "$(json_escape "$fline")" \
        "$(json_escape "$frule")" "$(json_escape "$fdesc")"
    done < "$FINDINGS_TSV"
    printf ']}'
  done < "$EXT_SCORES"
  printf '\n  ],\n  "totals": {"extensions_scanned": %d, "flagged": %d}\n}\n' "$total_ext" "$flagged"
}

# ══════════════════════════════════════════════════════════════════════
# Record
# ══════════════════════════════════════════════════════════════════════

record_findings() {
  $RECORD_MODE || return 0
  umask 0077
  mkdir -p "$SONOMOS_DIR"
  chmod 700 "$SONOMOS_DIR" 2>/dev/null || true
  [[ -f "$LEAKS_FILE" ]] && { chmod 600 "$LEAKS_FILE" 2>/dev/null || true; }
  local ts sid
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  sid="unknown"
  if [[ -f "$SONOMOS_DIR/.current_session" ]]; then
    sid=$(cat "$SONOMOS_DIR/.current_session" 2>/dev/null || echo "unknown")
    [[ -z "$sid" ]] && sid="unknown"
  fi
  while IFS=$'\t' read -r ext score; do
    [[ -z "$ext" ]] && continue
    [[ "$score" -le 0 ]] && continue
    local val="${ext} score:${score}"
    local src="audit:${ext}"
    if $HAVE_JQ; then
      jq -n -c \
        --arg type "plugin_finding" \
        --arg value "$val" \
        --arg detector "audit" \
        --arg confidence "high" \
        --arg ts "$ts" \
        --arg sid "$sid" \
        --arg src "$src" \
        '{type:$type, value:$value, detector:$detector, confidence:$confidence, timestamp:$ts, session_id:$sid, source:$src}' \
        >> "$LEAKS_FILE"
    else
      printf '{"type":"plugin_finding","value":"%s","detector":"audit","confidence":"high","timestamp":"%s","session_id":"%s","source":"%s"}\n' \
        "$(json_escape "$val")" "$ts" "$(json_escape "$sid")" "$(json_escape "$src")" >> "$LEAKS_FILE"
    fi
  done < "$EXT_SCORES"
  chmod 600 "$LEAKS_FILE" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

if $JSON_MODE; then
  print_json_report
else
  print_human_report
fi

record_findings

EXIT_CODE=0
if $STRICT_MODE && grep -qF "$(printf '\t')CRITICAL$(printf '\t')" "$FINDINGS_TSV" 2>/dev/null; then
  EXIT_CODE=2
fi

exit "$EXIT_CODE"
