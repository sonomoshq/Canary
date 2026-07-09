# Custom detector rules (`rules.d/`)

`canary/scripts/custom_rules.py` lets you define your own detector rules —
things specific to your org (employee IDs, internal project codes, loyalty
account numbers, whatever) — without touching `detectors.sh`. It's Python 3
**stdlib only**, **local-only**, and **zero network**, matching the rest of
Canary.

Rule files live at `$SONOMOS_DIR/rules.d/*.json`, where `SONOMOS_DIR` is
`$CLAUDE_PLUGIN_DATA` if set, else `~/.sonomos`. If that directory doesn't
exist, or contains no `.json` files, `custom_rules.py` does nothing and
exits 0 — it's entirely opt-in.

This document is the integration contract for `custom_rules.py`. The CLI
contract is also documented verbatim at the top of that file — treat the
two as kept in sync.

## CLI contract

```
python3 custom_rules.py <path-to-textfile>
```

Reads the given file's text, applies every enabled rule under
`$SONOMOS_DIR/rules.d/*.json`, and prints one JSON object per hit to
stdout (newline-delimited), in the same shape `detectors.sh`'s `emit()`
produces:

```json
{"type": "employee_id", "value": "EM••••••13", "detector": "custom", "confidence": "high", "value_id": "3ab6ca9ff91a"}
```

- `value` is redacted with the exact same rule `detectors.sh` uses: strip
  whitespace, cap at 64 chars, then `<=5` chars → `••••`, else first 2
  chars + dots (capped at 20, with a trailing `…` past the cap) + last 2
  chars. The raw matched text is never printed.
- `value_id` is a salted SHA-256 prefix (12 hex chars), using the same
  `$SONOMOS_DIR/.salt` file `detectors.sh` uses, so a value detected by
  both a built-in detector and a custom rule correlates. Omitted if a
  salt can't be established.
- Exit code is **always 0** for a normal scan. A missing/empty `rules.d/`,
  a malformed rule file, or an unreadable input file are all
  silently-degrade-and-continue conditions — this is a best-effort second
  stage in a Stop-hook pipeline and must never be the thing that breaks
  the hook. Warnings go to stderr, never stdout, so stdout is always
  clean JSONL.
- The one exception: `python3 custom_rules.py --selftest` runs the
  built-in self-tests and exits 1 if any assertion fails (0 otherwise),
  so CI can catch regressions in this file itself.

### How the orchestrator wires this in

`custom_rules.py` does **not** read hook stdin, does not know about
`leaks.jsonl`, and does not write anywhere — it only prints hits to
stdout. The orchestrator (`scan.sh` / `scan-file.sh`) wires it in as an
**optional second stage**, run after the regular regex `detectors.sh`
pass, and only when `rules.d/` exists and is non-empty:

```bash
HITS=$(bash "$SCRIPT_DIR/detectors.sh" "$TEXT")
if [[ -d "$SONOMOS_DIR/rules.d" ]] && find "$SONOMOS_DIR/rules.d" -maxdepth 1 -name '*.json' -print -quit | grep -q .; then
  printf '%s' "$TEXT" > "$TMP_TEXT_FILE"
  CUSTOM_HITS=$(python3 "$SCRIPT_DIR/custom_rules.py" "$TMP_TEXT_FILE")
  HITS="${HITS}"$'\n'"${CUSTOM_HITS}"
fi
```

(Sites with no `rules.d/` pay zero extra cost — the directory check short-circuits before python3 is even invoked.)

## Rule schema

A file under `rules.d/` is either:
- a single rule object, or
- `{"rules": [<rule object>, ...]}`

| field | type | required | notes |
|---|---|---|---|
| `name` | string | **yes** | `^[a-z][a-z0-9_]{2,40}$`. Must not collide with a built-in detector type name (from `taxonomy.json`) — rejected with a stderr warning if it does. |
| `pattern` | string | **yes** | A Python `re` pattern. Hard cap: 200 chars. Compiled via `re.compile` only — never `eval`/`exec`. |
| `flags` | list of string | no | Allowlist only: `"IGNORECASE"`, `"MULTILINE"`. Any other value rejects the whole rule. |
| `context_words` | list of string | no | If any word appears within `context_window` words of a match, confidence is boosted one tier (capped at `high`). |
| `negative_words` | list of string | no | Same proximity window; dampens confidence one tier (floored at `low`) — **never drops the hit**. |
| `context_window` | int | no | Word-count radius for the two lists above. Default `10`. |
| `validator` | `"luhn"` \| `"mod97"` \| `"aba"` \| `null` | no | Dispatches to a shipped, stdlib-only validator — never to user code. A match that fails validation is dropped individually; the rule keeps running. |
| `severity` | `"high"` \| `"medium"` \| `"low"` | **yes** | Base confidence before context boosting/dampening. |
| `sensitivity_class` | string | no | Metadata only — not emitted in hits; for the orchestrator/dashboard to merge into its own taxonomy if desired. |
| `regulatory_tags` | list of string | no | Metadata only, see above. |
| `risk_weight` | int, 1-10 | no | Metadata only, see above. |
| `enabled` | bool | no | **Defaults to `true` if omitted.** `enabled: false` disables the rule silently — the normal way to turn one off without deleting it. |

## Safety measures

- **Never `eval`/`exec` anything.** Patterns only ever go through
  `re.compile`.
- **Hard pattern-length cap** (200 chars) — oversized patterns are
  rejected at load time with a stderr warning.
- **Heuristic rejection of "obviously catastrophic" regex shapes** at
  load time: a quantified group that's immediately re-quantified
  (`(a+)+`, `(a*)*`, ...), and a quantified alternation group whose
  branches are identical (`(a|a)*`). This heuristic is **best-effort, not
  exhaustive** — subtler ReDoS shapes (e.g. ambiguous alternation like
  `(a|aa)+`) can slip past it.
- **Per-rule wall-clock timeout (250ms)**, implemented with
  `signal.setitimer(signal.ITIMER_REAL, ...)` wrapped around match
  iteration. This is the real safety net for anything the static
  heuristic misses: if a rule's regex runs past its budget against the
  given text, that one rule is skipped for this run (with a one-time
  stderr warning), and every other rule still executes. (We use
  `setitimer` rather than `signal.alarm` because `alarm()` only accepts
  whole seconds — a 250ms budget needs the finer-grained itimer API;
  both use the same POSIX SIGALRM mechanism. On a platform without
  `SIGALRM`, the timeout is skipped gracefully rather than erroring.)
- **Confidence, never suppression**: `context_words`/`negative_words` can
  only shift a hit's confidence among `low`/`medium`/`high` — they can
  never make a hit disappear.
- **Local-only**: rule files are read from local disk only. This script
  never opens a socket or fetches a URL, ever.
- **Redact before printing**: matched values are redacted before they're
  ever written to stdout; the raw matched substring only exists in memory
  for the duration of processing one rule.

Run `python3 canary/scripts/custom_rules.py --selftest` to exercise all of
the above (including a live demonstration of the runtime timeout catching
a pattern the static heuristic doesn't) without needing a real `rules.d/`
directory.

## Example rule files

### `rules.d/employee_id.json` — a single-rule file

```json
{
  "name": "employee_id",
  "pattern": "\\bEMP-\\d{6}\\b",
  "flags": ["IGNORECASE"],
  "context_words": ["employee", "staff", "badge"],
  "negative_words": ["example", "sample", "test", "changeme"],
  "context_window": 10,
  "severity": "medium",
  "sensitivity_class": "organizational",
  "regulatory_tags": [],
  "risk_weight": 4,
  "enabled": true
}
```

### `rules.d/internal.json` — multiple rules in one file, one with checksum validation

```json
{
  "rules": [
    {
      "name": "internal_project_code",
      "pattern": "\\bPROJ-[A-Z]{2}-\\d{4}\\b",
      "severity": "low",
      "enabled": true
    },
    {
      "name": "loyalty_card_number",
      "pattern": "\\b\\d{13,16}\\b",
      "validator": "luhn",
      "context_words": ["loyalty", "rewards", "member"],
      "negative_words": ["example", "test"],
      "severity": "medium",
      "enabled": true
    }
  ]
}
```

With the first file in place, `employee EMP-482913` in a scanned message
produces (roughly):

```json
{"type": "employee_id", "value": "EM••••••13", "detector": "custom", "confidence": "high", "value_id": "..."}
```

(boosted from `medium` to `high` because "employee" is nearby) — while
`e.g. a sample employee id EMP-482913 for docs` produces the same hit at
`medium` (the "employee" boost and the "sample"/"e.g." dampening roughly
cancel out) instead of being dropped, consistent with Canary's threat
model: undercounting is the failure that matters, not over-counting.
