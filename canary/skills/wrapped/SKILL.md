---
name: wrapped
description: Use when the user wants a shareable Canary Wrapped / year-in-review / recap of the sensitive data they've exposed, or asks to see or share their stats as a card.
user-invocable: true
disable-model-invocation: false
argument-hint: "[30d|90d|all]"
allowed-tools: Bash(python3:*), Bash(cat:*)
---

# Canary Wrapped

Generate the self-contained, shareable "Wrapped" recap of the sensitive data the user has
exposed to Claude — a Spotify-Wrapped-style HTML page with a big number, a risk grade, top
leaked categories, the worst single day, the longest clean streak, and a persona reveal.

Parse `$ARGUMENTS` for a period and/or `demo`:

- `demo` (in any position) → add `--demo` so the page renders ~140 realistic, fully-fake
  detections instead of real data. Use this when the user has little/no real history yet and
  wants to see what Wrapped looks like, or explicitly asks for a demo/sample.
- `30d` (default), `90d`, or `all` → passed as `--period`.

Run:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/wrapped.py" --period <30d|90d|all, default 30d> [--demo] --no-open
```

(`--no-open` keeps this non-interactive; mention the path so the user can open it themselves,
and drop `--no-open` if the user explicitly asks to launch it in a browser.)

The script prints the output path on success — always relay that exact path back to the user.
Tell them:

- Where the file is (the printed path — normally
  `${CLAUDE_PLUGIN_DATA:-~/.sonomos}/canary-wrapped.html`).
- That it's a single self-contained HTML file, generated locally, with zero network requests —
  nothing was uploaded anywhere.
- That it scrolls through several full-screen "scenes" (cover, the number, top categories,
  biggest spike, cleanest streak, persona, and an install CTA), and each scene is
  screenshot-ready on its own for sharing — screenshot just the one that's most interesting to
  them (the persona reveal is usually the shareable payoff).
- If the period had zero detections, it still renders a clean, celebratory "0 exposures"
  version — that's expected, not a bug.

## Detection Architecture

Wrapped reads the same `leaks.jsonl` detection log as the dashboard (`/canary:leaked`) and
scores it against the same shared taxonomy (`taxonomy.json`), so the grade and persona shown
here always agree with the dashboard's numbers for the same time window.

Never display raw PII values — Wrapped only ever surfaces aggregate counts, dates, and category
names, never a redacted or raw value.

Copyright © 2026 Sonomos Inc. All rights reserved.
