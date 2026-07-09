# Changelog

All notable changes to the Sonomos Canary plugin are documented here.

## [1.5.0] - 2026-07-09

Canary stops being purely passive. **Canary Tokens** add active defense — decoy secrets Canary mints itself, so a trip is a certain, literal match instead of a probabilistic guess. **Canary Wrapped** turns your exposure history into a shareable, Spotify-Wrapped-style recap. Every scoring surface now agrees on a single weighted risk model instead of a flat detection count, onboarding gained a real auto-installed HUD instead of a hoped-for copy-paste snippet, and `leaks.jsonl` rotates automatically so none of this slows down for your heaviest (most-leaking) users.

### Added
- **Canary Tokens** (`/canary:token`, `canary-token` CLI) — mint fake-but-realistic decoy secrets: an AWS access key + paired secret key, a Luhn-valid card number on the `9999` IIN (unassigned by ISO/IEC 7812, so it can never collide with a real card), an SSN in the SSA-reserved 900-999 area (never issued to a real person), a `.env`/database-URL decoy, or a freeform codename. Plant one as a conventional, **safe-to-commit** file (`.env.canary`, `.aws-credentials.canary`, `database.canary.url`, ...) and get an alarm the *instant* its exact bytes reach Claude — a literal `grep -F` match against a value only Canary could have produced, logged at `confidence: "certain"`, distinct from every other entry in the leak log. Subcommands: `new | plant | list | trips | revoke | ack`. Registry at `canaries.jsonl` (`0700`/`0600`).
- **Canary Wrapped** (`/canary:wrapped [30d|90d|all]`, `canary/scripts/wrapped.py`) — a self-contained, scroll-snapped HTML recap in the Spotify-Wrapped style: cover, the big number + weighted grade + verdict, a top-3-categories podium, the biggest single-day spike, the longest clean streak, a persona reveal, and an install CTA — each scene independently screenshot-ready. Reads the same `leaks.jsonl` and the same shared `taxonomy.json` as the dashboard, so the grade and persona never disagree between the two. `--demo` renders ~140 realistic, fully-fake detections for a preview.
- **Weighted risk score, shared everywhere.** A new `canary/scripts/taxonomy.json` is the single source of truth mapping every detector type to a family, sensitivity class, regulatory tags, and a researched risk weight (1-10 — e.g. `aws_secret_key`/`private_key`/`seed_phrase` are 10, while `aws_access_key`/`aba_routing`/`npi_number` are deliberately low, since none of those is secret standing alone). Every scoring surface — the dashboard, the HUD, `canary-stats`, `canary-card`, `canary-badge`, and Canary Wrapped — now computes `S = Σ(risk_weight × confidence_multiplier)` from that one file and derives the same A+-F letter grade from it, so your grade reads identically no matter which tool you check.
- **Lighthouse-style privacy report** on the dashboard: a 0-100 sub-score per data family (colored with Lighthouse's own red/orange/green thresholds) plus a ranked **"Top things to stop pasting"** list, decoupled from the score itself so it tells you how to improve it — and a regulatory-exposure row tagging hits by PCI-DSS / HIPAA / GDPR\* / SOC2 / GLBA / IRS / PIPEDA / UK-GDPR (`*` = an equivalent regime being tagged for convenience, not literal EU jurisdiction — not legal advice).
- **Personas** — a one-line character read of your exposure history ("The Secret Sprinkler," "The Crypto Cowboy," "The Night Owl," "The Untouchable," ...) computed from the shared taxonomy and shown identically in the dashboard's persona banner and in Canary Wrapped's persona scene.
- **`canary-card`** — a neofetch/onefetch-style branded ANSI summary card (ASCII canary logo, total, weighted grade + persona, distinct types, clean streak, top category, a 14-day sparkline) for screenshotting into Slack. Degrades gracefully without `jq` (count-based grade, dominant-family-only persona).
- **`canary-badge`** — an offline, self-contained SVG badge (`Canary: N PII` or `grade: X`) for embedding in a repo README, colored by the shared weighted grade. Zero network and no rendering library — text is laid out from a hardcoded Verdana glyph-width table, the same trick shields.io-style badge generators use.
- **Custom detector rules** (`$SONOMOS_DIR/rules.d/*.json`, `canary/scripts/custom_rules.py`) — add your own regex detectors (with an optional `luhn`/`mod97`/`aba` validator, context/negative words, and severity) without touching `detectors.sh`. Patterns are only ever `re.compile`'d, never `eval`'d; capped at 200 characters; checked at load time against an "obviously catastrophic" nested-quantifier shape; and wrapped in a 250ms wall-clock (`SIGALRM`) timeout so one runaway rule can't stall a hook — every other rule still runs. `python3 custom_rules.py --selftest` exercises all of it (37 internal assertions). Wired into both `scan.sh` and `scan-file.sh` as an optional second stage — zero overhead when `rules.d/` doesn't exist. See `canary/scripts/rules.d.README.md`.
- **HUD auto-install.** `session-start.sh` now installs the statusline for you on first run, merging a `statusLine` entry into `~/.claude/settings.json` via a structural `jq` merge (never string-splicing) — but only when you don't already have one configured, yours or anyone else's; an existing `statusLine` is never touched, and the very first change is backed up once to `settings.json.canary-bak`.
- **HUD: 14-day sparkline, truecolor, and a persistent tripped banner.** The statusline now renders a 14-day exposure sparkline, honors truecolor/256-color terminals for the weighted-grade accent (degrading cleanly through 256 → 16-color → mono/`NO_COLOR`), and — in both `full` and `compact` layouts — shows a bold `‼ CANARY TRIPPED — <label> reached Claude` banner for as long as a token trip is unacknowledged (`/canary:token ack` clears it).
- **Weekly digest.** Once per ISO week, the SessionStart banner adds a compact recap: this week's exposure count and weighted grade, the delta versus last week, the top categories, and which single type to stop pasting to raise the grade.
- **Automatic log rotation.** `leaks.jsonl` rotates — archived and gzip'd when `gzip` is available — at 50,000 lines or 5MiB, folding per-type/per-detector counts into a cumulative rollup ledger *before* archiving so the lifetime total in the SessionStart banner never drops after a rotation (see the new "Log Rotation" note in `THREAT_MODEL.md` for the one thing this doesn't yet fix). Keeps every tool fast indefinitely, no matter how much you've leaked.
- **`canary-export --team-digest`** — an anonymized, counts-only summary (no redacted values, paths, `value_id`s, or session ids) safe to paste into a team Slack channel. Zero telemetry: it only ever writes to stdout or `--output`; nothing is sent anywhere by Canary itself.
- `tests/test-tokens.sh` (36 assertions) and `tests/test-rotation.sh` (28 assertions).

### Changed
- **Negative-context confidence dampening gains a `low` tier.** A hit within about 40 characters of a word like `example`/`dummy`/`changeme`/`placeholder` now drops one confidence tier (`high` → `medium` → `low`) instead of firing at full weight — it is still never dropped outright, since undercounting, not overcounting, is the failure Canary optimizes against.
- **`canary-stats` and `canary-export` gain the weighted model too**: `canary-stats`'s `--json` output adds `weighted_score`/`grade`/`by_class`/`by_regulatory`; `canary-export`'s CSV/JSON gain `risk_weight`/`sensitivity_class` columns. Both degrade gracefully (fields blank/omitted) when `taxonomy.json` is missing.
- **`/canary:audit` is now surfaced** in the SessionStart welcome and returning-user banners and the HUD footer, alongside `/canary:leaked` and `/canary:scan` — previously discoverable only via the README or the skill list.
- **Two dead legacy transcript-extraction fallbacks removed from `scan.sh`.** They matched no real Claude Code transcript shape and had been unreachable code ever since the correct extraction path (`.type=="user"` + `.message.content`) shipped in 1.4.0.
- **Test suites: 5 → 7**, now totaling **240 assertions** (detectors 77, checksums 43, redact 7, no-false-positives 47, corpus 2, tokens 36, rotation 28), plus `custom_rules.py --selftest`'s own 37 internal assertions.

### Fixed
- **The `email` detector missed or truncated every `mailto:` address.** A single `(?<![:/@])` lookbehind blocked the character right after a `mailto:` prefix from ever starting a match: `mailto:foo@bar.com` matched nothing, and `mailto:jane.smith@x.com` matched only `smith@x.com`. Fixed with a fixed-width lookbehind alternation, `(?:(?<=mailto:)|(?<![:/@]))`, that both PCRE and the Perl fallback accept; a `https://user:pass@host` URL-userinfo password is still correctly excluded.
- **`canary-stats`/`canary-export` validated `leaks.jsonl` by forking `jq` once per line** — about 11 minutes at 200k lines, worse at scale. Replaced with a single `jq -cR 'fromjson? // empty'` pass feeding one `awk` aggregation; the same validation now takes about 2 seconds at 200k lines (about 11s at 1M), with identical output.
- **`audit-plugins.sh`'s documentation-example fence detection reset on blank lines**, so idiomatic Markdown — a blank line between the introducing prose and a fenced code block — never actually suppressed the example, and a documented `curl | bash` snippet in a README could flag as a HIGH finding. It now tracks the nearest non-blank preceding line instead; a real, non-example `curl | bash` still flags normally.
- **`dashboard.py --demo` without an explicit `--out` could silently overwrite your real dashboard.** It now defaults to a sibling file, `dashboard-demo.html`, whenever `--demo` is set without `--out`; an explicit `--out` still wins over both defaults.

### Security
- `dashboard.py` and `wrapped.py` now `chmod 0600` their generated HTML the moment it's written — previously only the JSONL/state files in the data directory got this treatment, not the generated reports themselves.
- Canary Tokens' registry (`canaries.jsonl`) follows the same `0700`/`0600` discipline as the rest of the data directory; a token's raw value is never written to `leaks.jsonl` on trip — only its human-readable label, at `confidence: "certain"`.
- Custom rules are compiled via `re.compile()` only, never `eval`/`exec`, and every rule runs under a 250ms wall-clock timeout so a hostile or merely careless pattern can't hang a hook.

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
