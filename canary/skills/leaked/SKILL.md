---
name: leaked
description: Use when the user asks what PII they've leaked, wants the exposure dashboard/stats, or wants to reset the counter.
user-invocable: true
disable-model-invocation: true
argument-hint: "[dashboard|stats|reset|demo]"
allowed-tools: Bash(python3:*), Bash(cat:*), Bash(jq:*), Bash(wc:*), Bash(echo:*), Bash(rm:*), Bash(open:*), Bash(xdg-open:*)
---

# Sonomos Leak Counter — Dashboard

Handle the subcommand from $ARGUMENTS:

## `dashboard` or no argument (default)

Generate and open the interactive HTML dashboard:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/dashboard.py"
```

Then give a brief text summary:

```bash
SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
LEAKS="$SONOMOS_DIR/leaks.jsonl"
if [ -f "$LEAKS" ] && [ -s "$LEAKS" ]; then
  TOTAL=$(wc -l < "$LEAKS")
  echo "Total: $TOTAL PII items"
  echo "By type:"
  jq -r '.type' "$LEAKS" | sort | uniq -c | sort -rn | head -10
fi
```

## `demo`

Show the dashboard populated with sample data, so the user can see what it looks like before any real detections exist:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/dashboard.py" --demo
```

## `stats`

Text-only summary without opening a browser. Prefer the bundled tool over inline jq:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/bin/canary-stats"
```

## `reset`

**Ask for confirmation first.** If confirmed:

```bash
SONOMOS_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.sonomos}"
rm -f "$SONOMOS_DIR/leaks.jsonl" "$SONOMOS_DIR/.hud_cache" "$SONOMOS_DIR/.state" \
      "$SONOMOS_DIR/.filescan_index" "$SONOMOS_DIR/.cursor_"*
echo "Leak counter reset to 0."
```

## Detection Architecture

- **Regex detectors (automatic):** checksum-validated pattern matching runs silently on every Stop hook and on every file write/edit. Catches structured PII: credit cards, SSNs, emails, IBANs, crypto addresses, vendor API keys, phone numbers, and more.
- **Claude self-scan (automatic):** Claude scans each new user message for the semantic categories regex can't catch — names, addresses, legal IDs, medical records, trade secrets — on every Stop hook. Run `/canary:scan` for a deeper scan of the full conversation. No API key needed — Claude is the detector.
- **Extension audit (on demand):** `/canary:audit` scans installed skills, agents, plugins, and MCP configs for leaked secrets and suspicious exfiltration patterns.

Never display raw PII values. Always show the redacted `value` field from the leaks file.

Copyright © 2026 Sonomos Inc. All rights reserved.
