<p align="center">
  <img src="images/Canary-readme.png" alt="Canary by Sonomos" width="480" />
</p>

<p align="center">
  <strong>You have no idea how much PII you've fed to Claude.</strong>
</p>

<p align="center">
  <a href="https://github.com/sonomoshq/Canary/actions"><img src="https://github.com/sonomoshq/Canary/actions/workflows/validate.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License" /></a>
  <a href="https://github.com/sonomoshq/Canary/releases"><img src="https://img.shields.io/badge/version-1.5.0-blue" alt="Version" /></a>
  <a href="https://docs.anthropic.com/en/docs/claude-code"><img src="https://img.shields.io/badge/Claude_Code-plugin-8B5CF6" alt="Claude Code Plugin" /></a>
</p>

<p align="center">
  Canary is a privacy plugin for <a href="https://docs.anthropic.com/en/docs/claude-code">Claude Code</a> that counts every piece of sensitive data you expose across all sessions.<br/><br/>
  Credit cards. SSNs. API keys. Emails. Medical records. Crypto wallets. Names. Addresses.<br/><br/>
  <strong>The number only goes up.</strong>
</p>

<p align="center">
  New in 1.5.0: plant a fake secret and get a <strong>certain</strong> alarm — not a guess — the instant it reaches Claude (<a href="#plant-a-tripwire">Canary Tokens</a>), and turn your exposure history into a shareable, screenshot-ready recap (<a href="#canary-wrapped">Canary Wrapped</a>).
</p>

---

## Install

```bash
/plugin marketplace add sonomoshq/Canary
/plugin install canary@sonomos
```

No API keys. No external services. No config. Two commands and you're running.

---

## Plant a Tripwire

Every detector below — all 38 of them, plus any custom rule you add — is a *guess*. It looks at the shape of a value and infers it's probably a secret. That's genuinely useful, but it's still an inference: a coincidentally similar string can fool it, and it can never prove a match is the real thing.

**Canary Tokens flip that around.** Canary mints a fake-but-realistic secret itself — an AWS key, a credit card number, an SSN, a database URL, a codename, whatever — and remembers the *exact* value it minted. When that exact value later shows up in something Claude reads, it isn't a guess about shape. It's a literal string match against a value nobody else could have produced.

**38 detectors guess. This one knows.** This is the one place Canary says "proven, not probabilistic" — and means it.

```bash
/canary:token plant env
```

```
Planted: /home/you/project/.env.canary
  Label: API key decoy
  SAFE TO COMMIT — that's the point. If this file's contents ever
  reach Claude, Canary alarms with a CERTAIN match, not a guess.
```

Commit that file. Forget about it. If it — or its contents — ever reaches Claude's context (a transcript message, or a file Claude writes or edits), Canary alarms instantly, at `confidence: "certain"`:

```
🐤 Canary: tripwire "API key decoy" reached Claude
```

Six decoy types, each mimicking something real:

| Type | Mimics |
|------|--------|
| `aws` | An `AKIA...` access key + a paired 40-char secret key |
| `card` | A Luhn-valid 16-digit card number on the `9999` IIN — unassigned by ISO/IEC 7812, so it's unambiguously a decoy, never a real card |
| `ssn` | An SSN in the 900-999 area — reserved by the SSA, never issued to a real person |
| `env` | A high-entropy, API-key-shaped string |
| `dburl` | A `postgres://user:pass@host/db` connection string |
| `freeform` | Any string you choose — a fake codename, a decoy trade secret, anything |

```bash
/canary:token new <aws|card|ssn|env|dburl|freeform> [label]   # mint only — nothing written to disk
/canary:token plant <type> [path] [label]                     # mint AND write a safe-to-commit file
/canary:token list                                            # every canary, armed and tripped
/canary:token trips                                           # only tripped canaries — when, where, how
/canary:token revoke <id>                                     # disarm one
/canary:token ack                                             # clear the HUD's tripped banner
```

Or use the `canary-token` CLI directly — same subcommands, same behavior. A tripped canary shows up everywhere: a persistent red banner in the HUD, a "PROOF OF LEAK" card on the dashboard, and its own line in `leaks.jsonl` at `confidence: "certain"`, distinct from every regex/LLM hit around it.

This detects the decoy reaching *Claude's* context specifically — not an attacker who obtains it some other way. Pair it with a real network canarytoken (e.g. from canarytokens.org) for that outer layer; Canary itself never calls one. Full scope, honestly stated, in [THREAT_MODEL.md](THREAT_MODEL.md#canary-tokens).

---

## Canary Wrapped

Your Spotify Wrapped, but it's the sensitive data you've fed to Claude.

```bash
/canary:wrapped 30d
```

A single self-contained HTML file, generated locally, zero network requests, that scrolls through a cover, **the number** (with your weighted grade and a verdict), your top leaked categories, the single worst day, your longest clean streak, and a **persona reveal** ("The Secret Sprinkler," "The Crypto Cowboy," "The Night Owl," "The Untouchable," ...) — closing with an install CTA. Every scene is its own screenshot-ready card; share the one that stings the most, or the one you're proud of.

```bash
/canary:wrapped [30d|90d|all]     # default 30d
/canary:wrapped demo              # no history yet? see it with realistic sample data
```

Same shared scoring model as the dashboard ([below](#score--privacy-report)), so your grade and persona never disagree between the two.

---

## What Gets Caught

<table>
<tr>
<td width="50%">

**38 Regex Detectors** (every message + every file write; a few ms typical, tens of ms on PII-dense text)

Real checksum validation where the format actually has one — not just pattern matching:

- **Checksummed:** credit cards (Luhn), IBANs (MOD-97), ABA routing numbers, VINs (MOD-11), NHS numbers (MOD-11), Canadian SINs (Luhn), NPIs (Luhn), DEA numbers
- **Rule-validated (no true checksum exists):** SSNs (SSA exclusion ranges), ITINs (IRS prefix/range), UK National Insurance numbers (HMRC prefix rules)
- **11 vendor secret keys:** GitHub, GitLab, Slack (token + webhook), Stripe, Anthropic, OpenAI, Google, SendGrid, npm, JWTs, private-key blocks
- **Network/contact:** emails (including `mailto:` links), phone numbers, IPv4/IPv6, MAC addresses
- **Other:** DB connection strings, URL-embedded credentials, entropy-gated generic secrets, driver's licenses, Medicare MBIs, UK postcodes (format-only, so *medium* confidence unless address context lifts it)
- Bitcoin & Ethereum addresses — format-checked only, so these are flagged at *medium* confidence, not high (see [THREAT_MODEL.md](THREAT_MODEL.md))
- **Plus your own** — drop a rule under `rules.d/` and Canary runs it too (see [Custom Detectors](#custom-detectors-rulesd) below)

</td>
<td width="50%">

**~33 Semantic Categories** (Claude self-scan, automatic, zero extra cost)

Claude reads your latest message itself for what regex structurally can't catch — categories the regex layer already owns are excluded here so nothing gets double-counted:

- Names, dates of birth, street addresses
- Passport and national ID numbers
- Medical records, health plan IDs, diagnosis codes
- Legal case numbers, contracts, patents
- Trade secrets, internal communications
- Employee and customer data
- Crypto seed phrases, private keys
- OAuth tokens, financial records
- ...and more

Run `/canary:scan` for an on-demand deep scan of your full conversation history — **70+ categories**, not just the latest message.

</td>
</tr>
</table>

**Plus Canary Tokens** ([above](#plant-a-tripwire)) for the one thing shape-matching can never give you: certainty.

---

## Score & Privacy Report

A flat detection count used to be the whole grade — more hits, worse grade, no matter what they were. As of 1.5.0, every scoring surface reads one shared model (`canary/scripts/taxonomy.json`) and computes a **weighted risk score**:

```
S = Σ (risk_weight × confidence_multiplier)   →   A+ … F
```

A single leaked `aws_secret_key` (risk weight 10, the ceiling) moves your grade more than ten stray `aba_routing` numbers (risk weight 2 — a number printed on every check isn't secret standing alone). The same grade shows up identically on the dashboard, the HUD, `canary-stats`, `canary-card`, `canary-badge`, and Canary Wrapped, because every one of them computes it from the same file.

The dashboard turns that score into a Lighthouse-style **privacy report**: a 0-100 sub-score per data family (colored with Lighthouse's own red/orange/green thresholds), a ranked **"Top things to stop pasting"** list, and a regulatory-exposure row — PCI-DSS, HIPAA, GDPR\*, SOC2, GLBA, IRS, PIPEDA, UK-GDPR (`*` = an equivalent regime being flagged for convenience, not literal EU jurisdiction — not legal advice) — plus a persona banner and, if you've planted one, your tripwires.

---

## How It Works

```
You type a message
       |
       v
Claude processes it ──> Stop hook fires (async, invisible)
                              |
              ┌───────────────┼───────────────┐
         Regex + Rules   Claude Self-Scan   Canary Token Check
        (38 types + your  (~33 categories,   (certain grep -F
         rules.d/ rules)  regex overlap       match, not a guess)
                          excluded)
              └───────────────┼───────────────┘
                              v
                 Canary's data directory / leaks.jsonl
                              ^
                              │
     Claude writes/edits a file ──> PostToolUse hook ──> the same three checks
     (Write, Edit, or NotebookEdit)         │
                 Session start ──> counter, streak, milestones, weekly digest
```

On demand, two more paths feed the same log:

- **`/canary:scan`** — Claude re-reads the whole conversation for the full 70+-category deep scan (the automatic self-scan above only ever looks at the latest message).
- **`/canary:audit`** — turns the *same* detector engine on your **installed** skills, agents, plugins, and MCP configs instead of your conversation. See [Audit Your Plugins](#audit-your-plugins) below.

- **Automatic**: regex + custom rules run on every message and every file write/edit; the semantic self-scan runs on every message; the Canary Token check runs alongside both
- **Local-only**: zero network requests (checked mechanically in CI), no telemetry, no external APIs
- **Non-blocking**: detection runs async, never slows your workflow
- **Persistent**: counter survives restarts and log rotation, accumulates across all sessions, with clean-session streaks, milestones, and a weekly digest

---

## Commands

| Command | What it does |
|---------|-------------|
| `/canary:leaked` | Open the interactive HTML dashboard |
| `/canary:leaked stats` | Print a text summary |
| `/canary:leaked demo` | Preview the dashboard with realistic sample data — try before you leak |
| `/canary:leaked reset` | Clear all detection data (asks for confirmation first) |
| `/canary:scan [full\|quick]` | Deep-scan the full conversation history (70+ categories) |
| `/canary:audit [--record] [--strict]` | Scan installed skills/agents/plugins/MCP configs for leaked secrets |
| `/canary:token new <type> [label]` | Mint a fake decoy secret (`aws\|card\|ssn\|env\|dburl\|freeform`) |
| `/canary:token plant <type> [path] [label]` | Mint **and** write a safe-to-commit decoy file |
| `/canary:token list` / `trips` / `revoke <id>` / `ack` | List canaries · show trips · disarm one · clear the HUD flag |
| `/canary:wrapped [30d\|90d\|all]` | Generate the shareable Canary Wrapped recap |

**CLI tools** (on `PATH` automatically while the plugin is enabled — no separate install step):

```bash
canary-stats                # quick summary — weighted grade + PCI/PHI/Secrets/GDPR breakdown when jq+taxonomy available
canary-stats --json         # machine-readable, same fields

canary-export --csv         # export all detections as CSV (default) — now with risk_weight, sensitivity_class columns
canary-export --json        # export as a JSON array
canary-export --csv -o out.csv    # write to a file instead of stdout
canary-export --team-digest # anonymized, counts-only summary safe to paste in Slack — zero telemetry, zero network

canary-token new env                          # mint a decoy secret
canary-token plant aws ./config/.aws.canary   # mint + write a safe-to-commit decoy file
canary-token trips                            # show which planted decoys have tripped

canary-card                 # neofetch-style ANSI summary card — screenshot it to Slack
canary-card --no-color      # mono variant, for piping/logging

canary-badge                              # offline SVG badge → ${CLAUDE_PLUGIN_DATA}/canary-badge.svg
canary-badge --metric grade --out badge.svg
```

Embed the badge in your own README:

```markdown
![Canary](badge.svg)
```

---

## Persistent HUD

As of 1.5.0, Canary installs its own HUD for you. On first run, it merges a `statusLine` entry into `~/.claude/settings.json` — a safe, structural `jq` merge, never string-splicing — but **only if you don't already have one configured**. Yours or anyone else's existing `statusLine` is never touched, and the very first change Canary ever makes is backed up to `settings.json.canary-bak`. If Canary declined to touch your config (or you'd rather wire it in by hand), its first-run message prints the exact snippet, with the correct path for your install:

```json
{
  "statusLine": {
    "type": "command",
    "command": "bash ~/.sonomos/statusline.sh"
  }
}
```

(the path shown is Canary's data directory — `${CLAUDE_PLUGIN_DATA}` when running as an installed plugin, `~/.sonomos` when running outside plugin data dirs. Don't assume the literal `~/.sonomos` path without checking the message; it prints the real one.)

Two layout modes, set via `CANARY_HUD_MODE`:

- **`full`** (default) — a framed HUD: PII counter with a colorblind-safe severity glyph (`✓` 0 / `▲` 1-9 / `‼` 10+), the weighted letter grade, high-confidence count, this-session delta, type diversity, last-detection age, a **14-day exposure sparkline**, a clean-streak badge, a detector breakdown (regex / llm / audit / files), top 3 categories, and a dashboard link with skill shortcuts.
- **`compact`** — a single line, no frame. Auto-selected when the terminal is under 80 columns.

The HUD also renders **model name, git branch, a context-window usage bar, and session cost** — the same segments a general-purpose statusline would show — so it can be the *only* statusline you configure. It honors your terminal's real color depth: truecolor and 256-color terminals get a smooth gradient grade accent, everything else degrades cleanly to a 16-color/mono-safe palette (`NO_COLOR` always respected). Renders are cached (keyed on the leak log's mtime + size): about 13ms on a cache hit, regardless of how large `leaks.jsonl` gets — automatic log rotation keeps it that way forever.

**If a planted Canary Token trips**, the HUD leads with a bold red banner in both layout modes, until you acknowledge it:

```
‼ CANARY TRIPPED — API key decoy reached Claude · /canary:token ack
```

Want the HUD as a static image instead of a live statusline? `canary-card` renders the same data as a one-shot ANSI card you can screenshot into Slack; `canary-badge` renders it as an SVG for a repo README.

---

## Custom Detectors (`rules.d`)

Drop a JSON file at `${CLAUDE_PLUGIN_DATA:-~/.sonomos}/rules.d/your-rule.json` and Canary runs it as an extra detection stage, right after the 38 built-ins, with zero code changes:

```json
{
  "name": "employee_id",
  "pattern": "\\bEMP-\\d{6}\\b",
  "context_words": ["employee", "staff", "badge"],
  "negative_words": ["example", "sample", "test"],
  "severity": "medium"
}
```

Safe by construction: patterns are only ever `re.compile`'d — never `eval`'d or `exec`'d — capped at 200 characters, checked at load time against an "obviously catastrophic" nested-quantifier shape, and wrapped in a 250ms timeout so one runaway regex can't hang a hook (every other rule still runs). `context_words`/`negative_words` can only shift a hit's confidence, never suppress it. Full schema, safety details, and worked examples in [`canary/scripts/rules.d.README.md`](canary/scripts/rules.d.README.md); run `python3 canary/scripts/custom_rules.py --selftest` to see the safety measures exercised directly.

---

## Audit Your Plugins

Your conversation isn't the only thing that can leak. Installed skills, agents, and MCP servers run with real permissions — filesystem access, environment variables, sometimes network egress — and a careless or malicious one is a bigger risk than anything you type. `/canary:audit` turns Canary's detection engine on your **installed extensions** instead of your chat:

- **Leaked secrets** — the same 38-detector engine, checking for API keys, tokens, and private keys accidentally committed into a skill or agent file
- **Exfiltration patterns** — curl-pipe-shell, base64-decode-and-exec, known collector domains (webhook.site, ngrok, Discord/Telegram bot APIs, ...), reads of `~/.ssh`, `~/.aws/credentials`, or `~/.netrc`, environment-harvesting pipes, hidden zero-width/RTL-override Unicode, wildcard tool permissions

```bash
/canary:audit             # report only, human-readable
/canary:audit --json      # machine-readable report
/canary:audit --record    # also log a summary line per flagged extension
/canary:audit --strict    # exit 2 if anything CRITICAL was found (for CI)
```

Every flagged extension gets a 0-100 risk score (LOW / MEDIUM / HIGH / CRITICAL). It's report-only by default — nothing is modified, and nothing is written to your leak log unless you pass `--record`. Canary's own plugin directory is excluded automatically, since it legitimately ships the pattern library this scan is built on.

---

## Demo Mode

Try before you leak — every generator below has a `--demo` mode that renders realistic-but-entirely-fake data (reserved IP ranges, RFC-reserved example domains, synthetic keys) and never touches your real `leaks.jsonl`:

```bash
python3 canary/scripts/dashboard.py --demo
# or, from inside a session:
/canary:leaked demo

python3 canary/scripts/wrapped.py --demo
# or:
/canary:wrapped 30d demo
```

<p align="center">
  <img src="images/canary-wrapped-demo.png" alt="Canary Wrapped demo scene, &quot;The Number&quot;: 136 exposures over the last 30 days, grade F, 666.2 risk points, verdict &quot;Feathers everywhere. Certified oversharer.&quot;" width="420" />
</p>
<!-- Static screenshot of one Canary Wrapped --demo scene (this repo can't
     render an animated GIF directly). canary/demo/canary-demo.tape — a
     VHS tape, dev-time-only asset — regenerates an animated walkthrough
     of canary-stats, canary-card, a token plant + trip, and the
     dashboard. With vhs/ttyd/ffmpeg installed:
       vhs canary/demo/canary-demo.tape
     which produces canary/demo/canary-demo.gif. -->

The dashboard's demo mode renders the full report — risk-grade ring gauge, weighted privacy report, exposure timeline, 26-week activity heatmap, per-category breakdown, achievements, and a sample tripped tripwire — against ~140 realistic but entirely fake detections, with a "DEMO DATA" ribbon so it's unmistakable. Canary Wrapped's demo mode scrolls the same kind of fake history through a full 7-scene recap. Nothing in either mode touches your real data.

---

## Team Rollout

Drop this into your project's `.claude/settings.json` to auto-enable Canary for every developer:

```json
{
  "extraKnownMarketplaces": {
    "sonomos": {
      "source": { "source": "github", "repo": "sonomoshq/Canary" }
    }
  },
  "enabledPlugins": { "canary@sonomos": true }
}
```

Commit it. Every team member gets prompted to install on their next session. Once everyone's running, `canary-export --team-digest` gives you an anonymized, counts-only summary — no values, paths, or session IDs — that's safe to paste into a team channel to compare progress without anyone's actual secrets ever leaving their own machine.

---

## Privacy and Security

- All data stays on your machine, in Canary's data directory (path shown in its first-run message; `~/.sonomos` when running outside plugin data dirs)
- Values are redacted **at detection time** (first 2 and last 2 characters kept, middle replaced with `••`) — and **re-redacted at write time**: the recording script never assumes a value arrived already redacted, and re-masks anything that still looks raw before it touches disk
- Every hit carries a salted `value_id` (SHA-256 of a per-install salt + the value) so a repeated exposure of the same secret can be deduplicated without storing anything more identifying than what's already there
- Files created with owner-only permissions (`0700` dirs / `0600` files) — including the generated dashboard and Canary Wrapped HTML, and the Canary Tokens registry `canaries.jsonl`. The one deliberate exception is `canary-badge`'s SVG output (`0644` — a badge is meant to be embedded publicly and carries no PII). See [THREAT_MODEL.md](THREAT_MODEL.md) for the full breakdown.
- JSON output constructed with `jq` to prevent injection
- File path validation blocks traversal attacks
- Custom detector patterns (`rules.d/`) are only ever `re.compile`'d, never `eval`'d, and run under a 250ms timeout — see [Custom Detectors](#custom-detectors-rulesd)
- **No network requests. No telemetry. No analytics. Ever** — checked mechanically in CI, not just promised in prose

See [SECURITY.md](SECURITY.md) for vulnerability reporting, and [THREAT_MODEL.md](THREAT_MODEL.md) for an honest account of what Canary's detection layers can and can't guarantee — including the honest, narrower scope of what a Canary Token trip does and doesn't prove.

---

## Why This Exists

Most developers have no idea how much sensitive data they've shared with AI tools.

The answer is almost always *more than you think*.

Canary makes that number visible and persistent. It doesn't block anything. It doesn't redact anything. It just counts — and now, with Canary Tokens, it can prove the moment something crosses the line, instead of just estimating that it probably did. Because you can't fix what you can't see.

**Canary shows you what you've already exposed.** If you want to prevent exposure before it happens, [Sonomos](https://sonomos.ai) detects and masks PII in real time before your data ever leaves your machine.

---

## Contributing

Found a bug? Want to add a detector? PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the detector-addition checklist and fixture-defang conventions.

```bash
git clone https://github.com/sonomoshq/Canary.git
cd Canary
bash tests/test-detectors.sh          # regex detector accuracy
bash tests/test-checksums.sh          # checksum validation tests
bash tests/test-redact.sh             # redaction tests
bash tests/test-no-false-positives.sh # false positive prevention
bash tests/test-corpus.sh             # labeled benchmark corpus + CI recall/false-positive ratchet
bash tests/test-tokens.sh             # Canary Tokens: mint/plant/list/trips/revoke/ack
bash tests/test-rotation.sh           # log rotation: archive+gzip, rollup ledger
python3 canary/scripts/custom_rules.py --selftest   # custom rules.d engine
```

All 7 suites, plus `custom_rules.py --selftest`, must pass. Test fixtures that look like credentials are synthetic and defanged by convention — split across adjacent string literals in the shell suites, `__X__`-spliced in `tests/corpus.json` — specifically so GitHub's push-protection secret scanning doesn't flag the repo whose entire purpose is detecting that shape. Details in [CONTRIBUTING.md](CONTRIBUTING.md).

---

<p align="center">
  <a href="https://sonomos.ai"><strong>Sonomos</strong></a> &mdash; Privacy at the Point of Creation
</p>

<p align="center">
  <sub>MIT License &copy; 2026 Sonomos, Inc.</sub>
</p>
