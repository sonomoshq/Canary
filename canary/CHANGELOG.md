# Changelog

All notable changes to the Sonomos Canary plugin are documented here.

## [1.4.0] - 2026-07-09

A major overhaul of both detection pipelines: the automatic scan didn't actually run in production, several detectors were silently dead, and the dashboard could crash or leak network requests. This release fixes all of that, adds a plugin-security audit, and rebuilds the dashboard and statusline from the ground up.

### Fixed
- **The automatic transcript regex scan never fired in production.** `scan.sh` selected user messages via `.type=="human"` / a top-level `.role` field — neither of which exists in real Claude Code transcripts — so the Stop-hook regex scan silently recorded nothing, ever. It also crashed outright on macOS, which ships without `md5sum`, causing the script to die under `set -e` before it could scan anything.
- **Two detectors were dead on arrival.** The VIN detector piped candidates through a zero-width lookahead-only pattern (`^(?!\d+$)`) that `grep -oP` prints nothing for on a match, discarding every candidate. The AWS secret-key detector used a variable-length lookbehind that both PCRE and Perl reject at compile time; because stderr was redirected, it failed silently and simply never matched.
- LLM-detected hits recorded a hardcoded `session_id` ("current") instead of the real session identifier, breaking per-session attribution for every semantic-scan hit.
- Detector JSON emission broke on any raw value that contained a double quote (e.g. a `url_credentials` match ending on a trailing `"`) — hand-interpolated JSON produced an invalid record that got silently dropped downstream.
- `canary-export` truncated CSV output after the first malformed line in `leaks.jsonl`, because `jq`'s default stream parser aborts entirely on the first invalid JSON value.
- The statusline miscounted (and in some cases zeroed) its stats against a pretty-printed or otherwise non-compact `leaks.jsonl`, because its fast-path aggregator assumed exactly one compact JSON object per line.
- The dashboard could crash with a `KeyError` on any record missing a `type` field, made a live request to Google Fonts on every open (measured 13s hangs when offline — directly contradicting the zero-network-requests claim), embedded logged values into the page without escaping (a stored-XSS vector), and blew its layout past 3000px once history spanned enough days.
- The regex and LLM self-scan layers double-counted PII: the LLM prompt had no awareness of what the regex layer already caught in the same Stop event, so the same value could be logged twice under two different detector types.
- Repeated edits to the same file re-counted the same PII on every save; `scan-file.sh` now tracks already-logged `(type, value)` pairs per file and suppresses re-hits.

### Added
- **20 new detector types** (16 → 36 total): a vendor secret pack (GitHub, GitLab, Slack token + webhook, Stripe, Anthropic, OpenAI, Google, SendGrid, npm, JWT, private-key blocks, DB connection strings) plus an entropy-gated `generic_secret`, checksummed NHS/Canadian-SIN/NPI/DEA numbers, ITIN, and `mac_address`.
- **`/canary:audit`** — new skill plus `canary/scripts/audit-plugins.sh`: scans installed skills, agents, plugins, and MCP/settings configs for leaked secrets (via the same detector engine) and exfiltration patterns (curl-pipe-shell, base64-decode-exec, known collector domains, credential-path reads, env harvesting, hidden Unicode, wildcard tool permissions), with a 0-100 per-extension risk score and `--json`/`--record`/`--strict` modes.
- **Dashboard rebuild**: dark/light themes, a ring-gauge risk grade (A+ through F), a dual-area exposure timeline with automatic day/week/month bucketing, a 26-week leak-activity heatmap, per-family category bars, a full searchable/filterable/sortable/paginated detections table, an achievements strip, sessions/projects panels, and a `--demo` mode with realistic synthetic data.
- **Statusline superset segments** (model name, git branch, context-window usage bar, session cost), `CANARY_HUD_MODE=full|compact` layout modes (auto-compact under 80 columns), and an mtime+size-keyed render cache.
- **Clean-session streaks and exposure milestones** (10 / 50 / 100 / 500 / 1000 items) surfaced in the SessionStart banner and the HUD.
- **Salted `value_id`** on every hit (regex, LLM, and audit), enabling repeat-exposure dedup in the dashboard and `canary-stats`.
- **Benchmark corpus**: `tests/corpus.json` (25 labeled cases across 5 attack surfaces — prose, edge, near-miss, injection, leakage), a scorer (`tests/score.py`), and a CI recall/false-positive ratchet (`tests/baseline.json`, enforced by the new `tests/test-corpus.sh`).
- **Placeholder denylist** — documented test credit-card numbers, SSA-published example SSNs, AWS's own documentation key pair, and NANP's reserved `555-01xx` range no longer inflate the counter.
- **`canaryignore` support** and per-project (`cwd`) attribution on file-sourced hits.
- `THREAT_MODEL.md` — what Canary does and doesn't guarantee, including the LLM layer's injection-surface risk and an honest breakdown of which detectors are truly checksum-validated versus format- or rule-only.

### Changed
- The Stop-hook LLM prompt was rewritten for the small model that runs it: it now explicitly excludes every category the regex layer already owns (fixing the double-counting above), adds an anti-rationalization guard, and reports a real confidence value instead of a hardcoded `"high"`.
- `bitcoin_address` and `ethereum_address` are now honestly labeled `medium` confidence — the validators only re-check the address *shape*, not the real Base58Check/EIP-55 checksum, which would require crypto dependencies this project deliberately doesn't ship.
- `/canary:leaked` and `/canary:scan` skill descriptions are now trigger-only; both use the corrected transcript-discovery path and `jq` selectors, and `/canary:scan` gained `full`/`quick` modes and a machine-parseable `LEAK_SCAN:` status line.
- `canary-stats` and `canary-export` degrade gracefully without `jq` instead of crashing, gained `--help`, and `canary-export`'s CSV output gained `source`, `value_id`, and `cwd` columns.
- The `pii-audit` agent was aligned with the same transcript selectors and recording interface as the hooks.
- Every documented repository reference — previously an inconsistent mix of `sonomos-ai/Canary`, `sonomos-ai/Canary-Plugin`, and `sonomos-ai/Canary-Plugin-Claude` across different docs — now points to the actual repository, `sonomoshq/Canary`. The install command is now `/plugin marketplace add sonomoshq/Canary`.
- `canary/README.md` trimmed to a short plugin-scoped quick reference that links to the root README instead of duplicating it.
- CI (`validate.yml`) now runs the full suite on both `ubuntu-latest` and `macos-latest` (exercising the Perl regex fallback BSD `grep` requires), added the corpus-benchmark step, made `shellcheck` blocking at `severity: error`, added a step that builds a `--demo` dashboard and fails the build on any external network reference, and added a README-badge/`plugin.json` version-consistency check.

### Security
- Defensive re-redaction in `record-llm-hit.sh` — the script no longer trusts that a value arrived already redacted, and re-masks anything that still looks raw before it's written to disk.
- `chmod 700`/`600` enforcement extended to every script that touches the data directory, not just the original two.
- Dashboard HTML output now escapes every dynamic value with `html.escape`, and the client-side table is built via `textContent`/`createElement` rather than `innerHTML`, closing the stored-XSS vector described under Fixed.

## [1.3.0] - 2026-04-15

### Added
- Rich multi-line HUD replacing the single-line PII counter
- Session-specific detection delta (▲N) showing detections in the current session
- Type diversity count (distinct PII categories detected)
- Last detection relative timestamp (e.g., "3m ago")
- Detection method breakdown (regex/llm/file counts)
- Top 3 exposure categories with hit counts
- Dashboard file link in HUD (path when generated, command hint otherwise)
- Skill shortcut references (/canary:leaked, /canary:scan) in HUD footer

### Changed
- statusline.sh: rewritten as a 5-line bordered HUD with ANSI color-coding
- session-start.sh: now syncs statusline script on every session (not just first run)
- session-start.sh: updated welcome message with HUD setup instructions
- session-start.sh: returning-user summary uses new bordered layout with dashboard link

## [1.2.0] - 2026-04-14

### Fixed
- hooks.json: Added required `"hooks"` wrapper key (fixes hook loading failure in v1.1.0)

### Added
- Automatic LLM semantic scanning on every Stop hook (previously required manual `/canary:scan`)
- Defense-in-depth `llm_scan_enabled` gating in `record-llm-hit.sh`

### Changed
- LLM scan is now automatic (runs on every Stop alongside regex); `/canary:scan` remains for deep full-conversation audits
- Updated session-start welcome message to reflect automatic LLM scanning
- Updated skill descriptions to reflect new automatic behavior

## [1.1.0] - 2026-04-14

### Added
- macOS compatibility: Perl fallback when `grep -P` (GNU PCRE) is unavailable
- Bash 3.2 compatibility: VIN validator no longer requires associative arrays
- `userConfig` support: configure `llm_scan_enabled` and `confidence_threshold` at install time
- `PostToolUse` hook: real-time PII scanning when Claude writes/edits files
- `pii-audit` agent: comprehensive PII audit across all conversation transcripts
- `canary-stats` CLI tool: quick terminal stats from the command line
- `canary-export` CLI tool: export detections to CSV or JSON
- `record-llm-hit.sh` script: dedicated script for recording LLM-detected PII
- Test suite: 63 tests covering detectors, redaction, checksums, and false positives
- CI pipeline: GitHub Actions workflow for automated validation and testing
- Team distribution docs: `extraKnownMarketplaces` template for project-level auto-install

### Changed
- Data storage: uses `${CLAUDE_PLUGIN_DATA}` with `~/.sonomos` fallback for backward compatibility
- Marketplace source: simplified from `git-subdir` to relative path `./canary`
- Version management: removed duplicate version from marketplace.json (plugin.json is authoritative)
- LLM prompt hook: refactored to use `record-llm-hit.sh` script instead of inline shell

### Fixed
- SSN validator: fixed octal interpretation bug with leading-zero area codes (e.g., 078)

## [1.0.0] - 2026-04-14

### Added
- 16 regex-based PII detectors with cryptographic validation (Luhn, MOD-97, ABA checksum, Base58Check, EIP-55, VIN MOD-11, SSA exclusion rules)
- 70+ semantic PII categories via Claude self-scan (LLM prompt hook on Stop event)
- Persistent PII counter stored in `leaks.jsonl`
- Interactive HTML dashboard with category breakdown, timeline, top types, and recent detections
- Terminal status line integration with color-coded counter
- `/canary:leaked` skill — dashboard, stats, and reset subcommands
- `/canary:scan` skill — on-demand deep LLM scan of current conversation
- SessionStart hook — welcome message on first run, counter summary on subsequent sessions
- Stop hook — automatic regex scan after every Claude task

### Fixed
- Repaired broken plugin: hooks never registered due to wrapping `"hooks"` key in hooks.json (Claude Code expects event names at root level)

### Changed
- Rebranded from "leak-counter" to "Canary"
- Redesigned dashboard: white theme, Jost/Poppins fonts, "sensitive data" language
