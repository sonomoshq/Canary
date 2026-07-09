# 🐤 Sonomos Canary

**A persistent PII exposure counter for Claude Code.**

Every time you interact with Claude, you may be sharing sensitive data — emails, credit card numbers, SSNs, API keys, addresses, medical records, legal identifiers, and more. Canary tracks every piece of PII you expose across all sessions, maintaining a running count that persists forever.

The number only goes up.

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

CLI tools `canary-stats` and `canary-export` (see `canary/bin/`) are on `PATH` while the plugin is enabled.

## Detection, in brief

- **Regex (automatic, every Stop + every file write/edit):** 36 detector types, checksum-validated where the format supports it.
- **Claude self-scan (automatic, zero cost):** semantic categories regex can't catch — names, addresses, legal IDs, medical records, trade secrets — on every Stop hook. Categories the regex layer already owns are excluded here to avoid double-counting.
- **`/canary:audit` (on demand):** turns the same detector library on your *installed extensions* instead of your conversation.

Full architecture, the complete detector list, and the HUD/privacy docs live in the [root README](../README.md).

## Plugin Structure

```
canary/
├── .claude-plugin/plugin.json       # Plugin manifest
├── hooks/hooks.json                 # Stop, PostToolUse, SessionStart hooks
├── scripts/
│   ├── detectors.sh                 # 36 regex detectors with checksum validation
│   ├── scan.sh                      # Stop hook: regex scan on new transcript messages
│   ├── scan-file.sh                 # PostToolUse hook: scan written/edited files
│   ├── session-start.sh             # SessionStart hook: welcome + summary + streaks
│   ├── statusline.sh                # Rich, cached HUD for the status bar
│   ├── record-llm-hit.sh            # Record LLM-detected hits safely (jq + re-redaction)
│   ├── audit-plugins.sh             # /canary:audit — scan installed extensions
│   └── dashboard.py                 # Interactive HTML dashboard generator
├── skills/
│   ├── leaked/SKILL.md              # /canary:leaked — dashboard, stats, reset, demo
│   ├── scan/SKILL.md                # /canary:scan — deep conversation scan
│   └── audit/SKILL.md               # /canary:audit — installed-extension audit
├── agents/
│   └── pii-audit.md                 # Cross-session PII audit agent
├── bin/
│   ├── canary-stats                 # CLI: quick PII summary
│   └── canary-export                # CLI: export to CSV/JSON
├── README.md
├── CHANGELOG.md
└── LICENSE
```

## About Sonomos

[Sonomos](https://sonomos.ai) detects and masks PII *before* it reaches AI. Canary shows you what you've already exposed. Sonomos prevents it.

---

Copyright © 2026 Sonomos Inc. All rights reserved.
