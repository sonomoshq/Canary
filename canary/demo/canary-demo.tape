# canary-demo.tape — VHS tape for Canary's animated demo GIF.
# Copyright © 2026 Sonomos, Inc. All rights reserved.
#
# DEV-TIME ASSET ONLY. This file is never read, executed, or referenced
# by the plugin itself, by any hook/skill/script, or by CI — it exists so
# a maintainer can regenerate marketing material (the animated GIF
# referenced from README.md's Demo Mode section) on demand. vhs, ttyd,
# and ffmpeg are required to RENDER it and are NOT, and must never
# become, runtime dependencies of Canary (which is zero-dep bash + jq +
# python3-stdlib, by design — see THREAT_MODEL.md's Trust Boundary).
#
# Install the renderer (one-time, on your own machine — never in CI):
#   brew install vhs                              # macOS, pulls in ttyd + ffmpeg
#   # or: go install github.com/charmbracelet/vhs@latest
#
# Regenerate:
#   cd /path/to/Canary
#   vhs canary/demo/canary-demo.tape
#
# Produces canary/demo/canary-demo.gif (and a closing still frame,
# canary/demo/canary-demo-final.png). Neither is committed to the repo —
# regenerate locally whenever a showcased command's output changes
# materially, then attach the fresh GIF to the README/release manually.
#
# Zero-network, zero-real-data guarantee for this recording itself:
# every command below runs against a throwaway CLAUDE_PLUGIN_DATA
# directory (a fresh `mktemp -d`, never `~/.sonomos`), the "planted"
# Canary Token is a decoy Canary mints itself (safe-to-commit by design),
# the six seeded leaks.jsonl lines below are hand-written, already-redacted,
# synthetic fixtures (RFC 2606 example.com, reserved-shape fake tokens —
# no real credential ever existed), and the dashboard segment uses
# dashboard.py's own built-in --demo generator. Nothing here reads or
# writes a real install's data.

Require bash
Require python3
Require jq

Output canary/demo/canary-demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 720
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

# ── Silent setup ─────────────────────────────────────────────────────────
# Isolate all state to a scratch dir, put the plugin's own bin/ on PATH
# (mirrors what an installed plugin gets for free), seed a handful of
# synthetic detections so canary-stats/canary-card have something to
# show, and move into a throwaway working directory for the token plant.
Hide
Type `REPO="$PWD"`
Enter
Type `export CLAUDE_PLUGIN_DATA="$(mktemp -d)/sonomos-demo" && mkdir -p "$CLAUDE_PLUGIN_DATA"`
Enter
Type `export PATH="$REPO/canary/bin:$PATH"`
Enter
Type `cat > "$CLAUDE_PLUGIN_DATA/leaks.jsonl" <<'DEMOEOF'
{"type":"github_pat","value":"gh••••••••••••••••34","detector":"regex","confidence":"high","timestamp":"2026-07-02T14:03:00Z","session_id":"demo01","source":"transcript"}
{"type":"email","value":"j.••••@example.com","detector":"regex","confidence":"high","timestamp":"2026-07-03T09:11:00Z","session_id":"demo01","source":"transcript"}
{"type":"aws_access_key","value":"AK••••••••••••1234","detector":"regex","confidence":"high","timestamp":"2026-07-04T22:47:00Z","session_id":"demo02","source":"file:/home/dev/acme/.env.local"}
{"type":"ipv4","value":"19••••••••54","detector":"regex","confidence":"medium","timestamp":"2026-07-05T11:20:00Z","session_id":"demo02","source":"transcript"}
{"type":"credit_card","value":"41••••••••••3456","detector":"regex","confidence":"high","timestamp":"2026-07-06T16:05:00Z","session_id":"demo03","source":"transcript"}
{"type":"jwt","value":"ey••••••••••••••9f","detector":"llm","confidence":"medium","timestamp":"2026-07-07T08:32:00Z","session_id":"demo03","source":"transcript"}
DEMOEOF`
Enter
Type `DEMODIR="$(mktemp -d)" && cd "$DEMODIR"`
Enter
Type `clear`
Enter
Show

# ── canary-stats: weighted grade + regulatory breakdown ─────────────────
Type `canary-stats`
Enter
Sleep 2500ms

# ── canary-card: neofetch-style branded ANSI summary card ───────────────
Type `clear && canary-card`
Enter
Sleep 2500ms

# ── Plant a Canary Token ──────────────────────────────────────────────────
Type `clear && canary-token plant env`
Enter
Sleep 1500ms

Type `cat .env.canary`
Enter
Sleep 1500ms

# ── ...and trip it ────────────────────────────────────────────────────────
# This is the real check scan-file.sh runs on every Write/Edit/NotebookEdit
# (check_text_for_trips), invoked directly here in a subshell so this
# recording can demonstrate a genuine trip without a live Claude Code
# session driving it. The alarm line below is real output, not scripted.
Type `clear && echo "# a file Claude just wrote, quoting the .env it was given:" && cat .env.canary | (source "$REPO/canary/scripts/canary-tokens.sh" && check_text_for_trips - "file:./notes/deploy.md" "demo04" "$PWD")`
Enter
Sleep 2500ms

Type `clear && canary-token trips`
Enter
Sleep 2500ms

# ── canary-card again: the tripwire now shows up in the weighted grade ───
Type `clear && canary-card`
Enter
Sleep 2500ms

# ── Dashboard: full HTML report (opens in a browser — this pane shows
# the CLI side of generating it; --demo never touches real data or the
# leaks.jsonl seeded above) ───────────────────────────────────────────────
Type `clear && python3 "$REPO/canary/scripts/dashboard.py" --demo --no-open`
Enter
Sleep 2500ms

Screenshot canary/demo/canary-demo-final.png
Sleep 1s
