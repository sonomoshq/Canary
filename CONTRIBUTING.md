# Contributing to Canary

PRs welcome. Here's how to get started.

## Setup

```bash
git clone https://github.com/sonomoshq/Canary.git
cd Canary
```

No build step. Canary is shell scripts + one Python file. Edit and test directly.

## Run Tests

```bash
bash tests/test-detectors.sh          # regex detector accuracy
bash tests/test-checksums.sh          # checksum validation (Luhn, MOD-97, ABA, etc.)
bash tests/test-redact.sh             # redaction format
bash tests/test-no-false-positives.sh # false positive prevention
bash tests/test-corpus.sh             # labeled benchmark corpus (recall / false-positive ratchet)
bash tests/test-tokens.sh             # Canary Tokens: mint/plant/list/trips/revoke/ack + the trip detector
bash tests/test-rotation.sh           # log rotation: archive+gzip, rollup ledger, gzip-absent degrade path
python3 canary/scripts/custom_rules.py --selftest   # custom rules.d engine: safety measures + matching behavior
```

All 7 suites, plus `custom_rules.py --selftest`, must pass before submitting a PR.

### How the corpus ratchet works

`tests/corpus.json` is a labeled benchmark of ~25 cases across 5 attack surfaces (prose, edge, near-miss, injection, leakage) — see the `_comment` field in that file for the full schema. `tests/score.py` runs `canary/scripts/detectors.sh` against every case and reports:

- **Recall** — of all `gold` items (values the engine must catch), what fraction were caught. Cases marked `"expected_miss": true` are excluded from this calculation on purpose — they document PII that is structurally outside a regex engine's reach (person names, etc.), not something to chase.
- **Preserve violations** — `preserve` items are values that must *not* fire under a specific type (documented false-positive traps: RFC 5737 test-net IPs, SSA-excluded SSN ranges, AWS's own example key, a clock time that looks like IPv6, etc.). Any violation is a regression.

`tests/test-corpus.sh` compares those two numbers against `tests/baseline.json` (`recall_min`, `max_preserve_violations`) and fails the build if either one gets worse. This is a ratchet, not a fixed target:

- **If your change lowers recall or introduces a preserve violation**, fix the detector — don't lower the baseline to make the test pass.
- **If your change legitimately improves recall** (e.g. you added a new gold case your detector now catches), **update `tests/baseline.json` in the same PR** so the ratchet locks in the improvement instead of leaving slack for a future regression to hide in.

## Defang Conventions

Test fixtures need secret-*shaped* values to exercise the detectors, but a contiguous string that looks like a real credential is exactly what GitHub's push-protection secret scanning flags on push — including in a repo whose entire purpose is detecting that shape. Two conventions keep fixtures out of that trap:

**Shell test suites** (`tests/test-detectors.sh`, etc.): split the value into two adjacent string literals with no space between them. Bash concatenates adjacent quoted strings at parse time, so the test still runs against the real, complete value — but no single literal in the source is a plausible secret:

```bash
assert_detects "GitHub PAT (classic ghp_)" "token: ghp_""oHBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclR" "github_pat"
assert_detects "Stripe live secret key" "sk_live_""51H8abcdefghijklmnopqrst" "stripe_api_key"
```

**`tests/corpus.json`**: embed the literal splitter `__X__` inside the value; `tests/score.py` strips it (`text.replace("__X__", "")`) before running the detector, so the JSON file itself never contains the unbroken string:

```json
"text": "STRIPE_SECRET_KEY=sk_live___X__sy1JjL5LR3lTdhpzLACuBARS\n"
```

Follow one of these two patterns for any new fixture that resembles a credential, API key, or private key block. Values that are inherently safe (RFC 5737/2606 documentation ranges, published vendor example keys, SSA-excluded SSNs) don't need defanging — they aren't real regardless of formatting.

## Adding a New Detector

1. Add the detection logic to `canary/scripts/detectors.sh`, following the existing `emit()`-based pattern: regex match -> validator/keyword-gate -> `emit "<type>" "<raw_value>" "<confidence>"`. Let `emit()` handle placeholder filtering, dedup, redaction, and `value_id` — don't reimplement those inline.
2. Include real checksum validation if the format supports one (Luhn, MOD-97, ABA, MOD-11, etc.). If it doesn't (e.g. ITIN has no published check digit), say so in a comment rather than implying a checksum that isn't there.
3. If a bare pattern would be too noisy on its own (e.g. a bare 9-digit number), add a keyword gate on the containing line/text instead of firing unconditionally — see the SSN/ABA and NHS/SIN/NPI/DEA detectors for the pattern.
4. Add the value to `is_placeholder()` if the format has well-known published example/test values (AWS's docs key, SSA-published example SSNs, standard test PANs, etc.) so documentation doesn't inflate real users' counts.
5. Set `confidence` to `"high"` only when checksum-validated or otherwise unambiguous; `"medium"` for format-only matches.
6. Add positive and negative tests to `tests/test-detectors.sh` (using the defang convention above for anything secret-shaped) and false-positive cases to `tests/test-no-false-positives.sh`.
7. Add at least one case to `tests/corpus.json` — a `gold` entry under the most relevant `surface`, plus a `preserve` entry if the new detector could plausibly collide with an existing one. Run `bash tests/test-corpus.sh` and update `tests/baseline.json` if recall improved (see above).
8. Update the detector count (currently 36) in `README.md` if you're adding or removing a type — and in `canary/hooks/hooks.json`'s Stop prompt "skip" list, so the LLM layer doesn't try to double-count a category the regex layer now owns.

## Code Style

- Shell scripts: `set -euo pipefail`, POSIX-compatible where possible, Bash 3.2+ minimum (no associative arrays, no `mapfile`, no `${var,,}`) — this is what macOS's stock `/bin/bash` requires, and CI runs the full suite on both `ubuntu-latest` and `macos-latest`.
- Use `|| true` for commands that may legitimately fail (grep no-match, missing optional tool, etc.).
- Never log raw PII values — always redact first. If a value reaches a script from outside `detectors.sh` (e.g. an LLM-reported hit), re-redact defensively rather than trusting the caller.
- Use `jq` for JSON construction, not string interpolation — when `jq` isn't available, degrade quietly rather than crash.
- All files written to the data directory (`${CLAUDE_PLUGIN_DATA:-~/.sonomos}`) must use `umask 0077` and end up `0700` (dirs) / `0600` (files) — this includes `canaries.jsonl` (the Canary Tokens registry) alongside `leaks.jsonl`. The one intentional exception is `canary-badge`'s SVG output (`0644` — it's meant to be embedded in a public README and carries no PII). `rules.d/*.json` rule files are the other exception in spirit: they're user-authored, and `custom_rules.py` only ever reads them — never writes to or `chmod`s that directory — so don't add code that assumes Canary controls their permissions.

## What We're Looking For

- New detectors for region-specific PII (UK NI, EU VAT, etc.)
- Performance improvements (especially for large `leaks.jsonl` files)
- Dashboard enhancements
- Better false positive prevention
- macOS/Linux/Windows compatibility fixes

## What We Won't Merge

- Features that make network requests
- Telemetry or analytics of any kind
- Changes that store raw (unredacted) PII values
- Dependencies on external services

## Security Issues

Do not open a public issue. Email info@sonomos.ai. See [SECURITY.md](SECURITY.md).
