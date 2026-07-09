---
name: audit
description: Use when the user wants to check installed Claude Code plugins, skills, agents, or MCP configs for leaked secrets or suspicious/exfiltration patterns.
user-invocable: true
disable-model-invocation: true
argument-hint: "[--record|--strict]"
allowed-tools: Bash(bash:*), Bash(cat:*), Bash(jq:*)
---

# Sonomos Extension Audit

Scan every installed skill, agent, plugin, and MCP/settings config for leaked secrets and suspicious exfiltration patterns — the same kind of PII/secret detectors Canary runs on your conversations, turned on the extensions themselves.

Run:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/audit-plugins.sh" $ARGUMENTS
```

`$ARGUMENTS` may be empty (report-only), `--record` (also append one leaks.jsonl summary line per flagged extension), `--strict` (exit 2 if anything CRITICAL was found), or both.

## After it runs

Summarize the findings for the user in your own words:
- Which extensions were flagged, their score/band (LOW/MEDIUM/HIGH/CRITICAL), and the top few findings for each (rule, severity, file:line when available).
- **Never print a raw secret value** — the script's output is already redacted by `detectors.sh`; just relay what it printed.
- If nothing was flagged, say so plainly — that's a good result.

Then suggest concrete next steps based on what was found:
- Rotate any credential that showed up as a leaked secret (API key, token, private key) — assume it's compromised once it's sat in a plugin/skill file.
- For CRITICAL findings (collector-domain, env-harvesting) or a CRITICAL-band extension, recommend removing or disabling that extension until it's been reviewed line by line.
- For a finding that's actually a documented example or an intentional false positive, point out that adding `# canary-ignore` to that line (or, for `.md` files, putting it in a fenced code block introduced by a line containing the word "example") will suppress it on the next run.

## Notes

- This is a report-only tool: it never modifies the scanned files, and only writes to `leaks.jsonl` when `--record` is passed.
- Canary's own plugin directory is skipped automatically — it legitimately ships the detector pattern library this audit is built on.

Copyright © 2026 Sonomos Inc. All rights reserved.
