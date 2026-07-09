<p align="center">
  <img src="images/Canary-readme.png" alt="Canary by Sonomos" width="480" />
</p>

<p align="center">
  <strong>You have no idea how much PII you've fed to Claude.</strong>
</p>

<p align="center">
  <a href="https://github.com/sonomoshq/Canary/actions"><img src="https://github.com/sonomoshq/Canary/actions/workflows/validate.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License" /></a>
  <a href="https://github.com/sonomoshq/Canary/releases"><img src="https://img.shields.io/badge/version-1.4.0-blue" alt="Version" /></a>
  <a href="https://docs.anthropic.com/en/docs/claude-code"><img src="https://img.shields.io/badge/Claude_Code-plugin-8B5CF6" alt="Claude Code Plugin" /></a>
</p>

<p align="center">
  Canary is a privacy plugin for <a href="https://docs.anthropic.com/en/docs/claude-code">Claude Code</a> that counts every piece of sensitive data you expose across all sessions.<br/><br/>
  Credit cards. SSNs. API keys. Emails. Medical records. Crypto wallets. Names. Addresses.<br/><br/>
  <strong>The number only goes up.</strong>
</p>

---

## Install

```bash
/plugin marketplace add sonomoshq/Canary
/plugin install canary@sonomos
```

No API keys. No external services. No config. Two commands and you're running.

---

## What Gets Caught

<table>
<tr>
<td width="50%">

**36 Regex Detectors** (every message + every file write; a few ms typical, tens of ms on PII-dense text)

Real checksum validation where the format actually has one — not just pattern matching:

- **Checksummed:** credit cards (Luhn), IBANs (MOD-97), ABA routing numbers, VINs (MOD-11), NHS numbers (MOD-11), Canadian SINs (Luhn), NPIs (Luhn), DEA numbers
- **Rule-validated (no true checksum exists):** SSNs (SSA exclusion ranges), ITINs (IRS prefix/range)
- **11 vendor secret keys:** GitHub, GitLab, Slack (token + webhook), Stripe, Anthropic, OpenAI, Google, SendGrid, npm, JWTs, private-key blocks
- **Network/contact:** emails, phone numbers, IPv4/IPv6, MAC addresses
- **Other:** DB connection strings, URL-embedded credentials, entropy-gated generic secrets, driver's licenses, Medicare MBIs
- Bitcoin & Ethereum addresses — format-checked only, so these are flagged at *medium* confidence, not high (see [THREAT_MODEL.md](THREAT_MODEL.md))

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

---

## How It Works

```
You type a message
       |
       v
Claude processes it ──> Stop hook fires (async, invisible)
                              |
                    ┌─────────┴─────────┐
               Regex Detectors      Claude Self-Scan
             (36 types + checksums)   (~33 categories,
                                     regex overlap excluded)
                    └─────────┬─────────┘
                              v
                 Canary's data directory / leaks.jsonl
                              ^
                              │
     Claude writes/edits a file ──> PostToolUse hook ──> regex scan of the file
                              │
                 Session start ──> counter, streak & milestones displayed
```

On demand, two more paths feed the same log:

- **`/canary:scan`** — Claude re-reads the whole conversation for the full 70+-category deep scan (the automatic self-scan above only ever looks at the latest message).
- **`/canary:audit`** — turns the *same* detector engine on your **installed** skills, agents, plugins, and MCP configs instead of your conversation. See [Audit Your Plugins](#audit-your-plugins) below.

- **Automatic**: regex runs on every message and every file write/edit; the semantic self-scan runs on every message
- **Local-only**: zero network requests (checked mechanically in CI), no telemetry, no external APIs
- **Non-blocking**: detection runs async, never slows your workflow
- **Persistent**: counter survives restarts, accumulates across all sessions, with clean-session streaks and milestones

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

**CLI tools** (on `PATH` automatically while the plugin is enabled — no separate install step):

```bash
canary-stats                # quick summary
canary-stats --json         # machine-readable

canary-export --csv         # export all detections as CSV (default)
canary-export --json        # export as a JSON array
canary-export --csv -o out.csv   # write to a file instead of stdout
```

---

## Persistent HUD

Canary prints the exact snippet to add — with the correct path for your install — in its first-run welcome message. It looks like this (the path shown is Canary's data directory: `${CLAUDE_PLUGIN_DATA}` when running as an installed plugin, `~/.sonomos` when running outside plugin data dirs):

```json
{
  "statusLine": {
    "type": "command",
    "command": "bash ~/.sonomos/statusline.sh"
  }
}
```

Two layout modes, set via `CANARY_HUD_MODE`:

- **`full`** (default) — a framed 4-5 line HUD: PII counter with a colorblind-safe severity glyph (`✓` 0 / `▲` 1-9 / `‼` 10+), high-confidence count, this-session delta, type diversity, last-detection age, a clean-streak badge, a detector breakdown (regex / llm / audit / files), top 3 categories, and a dashboard link with skill shortcuts.
- **`compact`** — a single line, no frame. Auto-selected when the terminal is under 80 columns.

The HUD also renders **model name, git branch, a context-window usage bar, and session cost** — the same segments a general-purpose statusline would show — so it can be the *only* statusline you configure. Renders are cached (keyed on the leak log's mtime + size): about 13ms on a cache hit, regardless of how large `leaks.jsonl` gets.

---

## Audit Your Plugins

Your conversation isn't the only thing that can leak. Installed skills, agents, and MCP servers run with real permissions — filesystem access, environment variables, sometimes network egress — and a careless or malicious one is a bigger risk than anything you type. `/canary:audit` turns Canary's detection engine on your **installed extensions** instead of your chat:

- **Leaked secrets** — the same 36-detector engine, checking for API keys, tokens, and private keys accidentally committed into a skill or agent file
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

Try before you leak:

```bash
python3 canary/scripts/dashboard.py --demo
# or, from inside a session:
/canary:leaked demo
```

<!-- demo GIF of the dashboard goes here -->

Renders the full dashboard — risk-grade ring gauge, exposure timeline, 26-week activity heatmap, per-category breakdown, achievements — against ~140 realistic but entirely fake detections (reserved IP ranges, RFC-reserved example domains, synthetic keys), with a "DEMO DATA" ribbon so it's unmistakable. Nothing touches your real `leaks.jsonl`.

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

Commit it. Every team member gets prompted to install on their next session.

---

## Privacy and Security

- All data stays on your machine, in Canary's data directory (path shown in its first-run message; `~/.sonomos` when running outside plugin data dirs)
- Values are redacted **at detection time** (first 2 and last 2 characters kept, middle replaced with `••`) — and **re-redacted at write time**: the recording script never assumes a value arrived already redacted, and re-masks anything that still looks raw before it touches disk
- Every hit carries a salted `value_id` (SHA-256 of a per-install salt + the value) so a repeated exposure of the same secret can be deduplicated without storing anything more identifying than what's already there
- Files created with owner-only permissions (`0700` dirs / `0600` files) — see [THREAT_MODEL.md](THREAT_MODEL.md) for the one known exception (the generated dashboard HTML)
- JSON output constructed with `jq` to prevent injection
- File path validation blocks traversal attacks
- **No network requests. No telemetry. No analytics. Ever** — checked mechanically in CI, not just promised in prose

See [SECURITY.md](SECURITY.md) for vulnerability reporting, and [THREAT_MODEL.md](THREAT_MODEL.md) for an honest account of what Canary's detection layers can and can't guarantee.

---

## Why This Exists

Most developers have no idea how much sensitive data they've shared with AI tools.

The answer is almost always *more than you think*.

Canary makes that number visible and persistent. It doesn't block anything. It doesn't redact anything. It just counts. Because you can't fix what you can't see.

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
```

All 5 suites must pass. Test fixtures that look like credentials are synthetic and defanged by convention — split across adjacent string literals in the shell suites, `__X__`-spliced in `tests/corpus.json` — specifically so GitHub's push-protection secret scanning doesn't flag the repo whose entire purpose is detecting that shape. Details in [CONTRIBUTING.md](CONTRIBUTING.md).

---

<p align="center">
  <a href="https://sonomos.ai"><strong>Sonomos</strong></a> &mdash; Privacy at the Point of Creation
</p>

<p align="center">
  <sub>MIT License &copy; 2026 Sonomos, Inc.</sub>
</p>
