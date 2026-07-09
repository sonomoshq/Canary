# 🐤 Sonomos Canary

**A persistent PII exposure counter for Claude Code.**

Every time you interact with Claude, you may be sharing sensitive data — emails, credit card numbers, SSNs, API keys, addresses, medical records, legal identifiers, and more. Canary tracks every piece of PII you expose across all sessions, maintaining a running count that persists forever.

The number only goes up. As of 1.5.0, Canary also fights back: **Canary Tokens** plant decoy secrets and give you a certain alarm the instant one reaches Claude, and **Canary Wrapped** turns the whole history into a shareable recap.

This is the plugin package itself (what `/plugin install` pulls down). For the full pitch, the detector list, the HUD reference, the plugin-audit docs, and the privacy/security model, see the **[root README](../README.md)**.

## Install

```bash
/plugin marketplace add sonomoshq/Canary
/plugin install canary@sonomos
```

## Commands

| Command | Description |
|---------|-------------|
| `/canary:leaked [stats\|reset\|demo]` | Dashboard (default) · text summary · reset (confirms first) · demo data |
| `/canary:scan [full\|quick]` | Claude reads the transcript itself for 70+ semantic PII categories |
| `/canary:audit [--record] [--strict]` | Scan installed skills/agents/plugins/MCP configs for leaked secrets and exfiltration patterns |
| `/canary:token [new\|plant\|list\|trips\|revoke\|ack]` | Mint and plant decoy secrets; get a **certain** alarm the instant one reaches Claude |
| `/canary:wrapped [30d\|90d\|all]` | Generate the shareable Canary Wrapped recap |

CLI tools on `PATH` while the plugin is enabled (see `canary/bin/`):

```bash
canary-stats                # quick summary (weighted grade + regulatory breakdown when jq+taxonomy available)
canary-export --csv|--json  # export detections; --team-digest for an anonymized, counts-only Slack summary
canary-token new|plant|...  # mint/plant/list/trips/revoke/ack decoy secrets
canary-card                 # neofetch-style ANSI summary card, for screenshotting
canary-badge                # offline SVG badge for your repo README
```

## Detection, in brief

- **Regex (automatic, every Stop + every file write/edit):** 36 detector types, checksum-validated where the format supports it — plus your own via `rules.d/*.json` (see `canary/scripts/rules.d.README.md`), no code changes required.
- **Claude self-scan (automatic, zero cost):** semantic categories regex can't catch — names, addresses, legal IDs, medical records, trade secrets — on every Stop hook. Categories the regex layer already owns are excluded here to avoid double-counting.
- **Canary Tokens (active defense, on demand to plant, automatic to detect):** decoy secrets Canary mints itself. A trip is a literal, certain match — not a shape-based guess like every detector above.
- **`/canary:audit` (on demand):** turns the same detector library on your *installed extensions* instead of your conversation.

Every scoring surface — dashboard, HUD, `canary-stats`, `canary-card`, `canary-badge`, Canary Wrapped — computes the same weighted risk score and letter grade from one shared `canary/scripts/taxonomy.json`, so the grade you see never disagrees between tools.

Full architecture, the complete detector list, and the HUD/privacy docs live in the [root README](../README.md).

## Plugin Structure

```
canary/
├── .claude-plugin/plugin.json       # Plugin manifest
├── hooks/hooks.json                 # Stop, PostToolUse, SessionStart hooks
├── scripts/
│   ├── detectors.sh                 # 36 regex detectors with checksum validation
│   ├── custom_rules.py              # User-defined detector rules (rules.d/*.json)
│   ├── rules.d.README.md            # Custom rule schema + worked examples
│   ├── canary-tokens.sh             # Canary Tokens library: mint/plant/trip-detect
│   ├── scan.sh                      # Stop hook: regex + custom rules + token-trip scan
│   ├── scan-file.sh                 # PostToolUse hook: same, for written/edited files
│   ├── session-start.sh             # SessionStart hook: welcome, HUD auto-install,
│   │                                 #   weekly digest, log rotation, streaks
│   ├── statusline.sh                # Rich, cached HUD (sparkline, truecolor, tripwire banner)
│   ├── record-llm-hit.sh            # Record LLM-detected hits safely (jq + re-redaction)
│   ├── audit-plugins.sh             # /canary:audit — scan installed extensions
│   ├── taxonomy.json                # Shared risk-weight/family/persona data model
│   ├── dashboard.py                 # Interactive HTML dashboard generator
│   └── wrapped.py                   # Canary Wrapped shareable recap generator
├── skills/
│   ├── leaked/SKILL.md              # /canary:leaked — dashboard, stats, reset, demo
│   ├── scan/SKILL.md                # /canary:scan — deep conversation scan
│   ├── audit/SKILL.md               # /canary:audit — installed-extension audit
│   ├── token/SKILL.md               # /canary:token — mint/plant/list/trips/revoke/ack
│   └── wrapped/SKILL.md             # /canary:wrapped — shareable recap
├── agents/
│   └── pii-audit.md                 # Cross-session PII audit agent
├── bin/
│   ├── canary-stats                 # CLI: quick PII summary (+ weighted grade)
│   ├── canary-export                # CLI: export to CSV/JSON (+ --team-digest)
│   ├── canary-token                 # CLI: mint/plant/list/trips/revoke/ack
│   ├── canary-card                  # CLI: neofetch-style ANSI summary card
│   └── canary-badge                 # CLI: offline SVG repo badge
├── demo/
│   └── canary-demo.tape             # VHS tape (dev-time only) for the animated demo GIF
├── README.md
├── CHANGELOG.md
└── LICENSE
```

## About Sonomos

[Sonomos](https://sonomos.ai) detects and masks PII *before* it reaches AI. Canary shows you what you've already exposed. Sonomos prevents it.

---

Copyright © 2026 Sonomos Inc. All rights reserved.
