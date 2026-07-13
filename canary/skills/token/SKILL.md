---
name: token
description: Use when the user wants to plant a decoy/tripwire secret, create a canary token, or check whether a planted token has been leaked to Claude.
disable-model-invocation: false
user-invocable: true
argument-hint: "[new|plant|list|trips|revoke|ack] ..."
allowed-tools: Bash(bash:*), Bash(canary-token:*), Bash(cat:*), Bash(jq:*)
---

# Canary Tokens — Active Defense

Every other part of Canary is passive: 38 regex detectors *guess* whether
something looks like PII or a secret, from its shape. Canary Tokens flip
that around. Canary mints a fake-but-realistic secret itself, plants it,
and remembers the exact value it planted. When that exact value later
shows up in something Claude reads, it isn't a guess about shape — it's
a literal string match (`grep -F`) against a value nobody else could have
produced. **38 detectors guess. This one knows.**

A "trip" is recorded at `confidence: certain`, distinct from every other
entry in the leak log, which is at best `high`/`medium`.

## Instructions

Parse `$ARGUMENTS` for a subcommand and dispatch to the `canary-token`
CLI (bundled at `${CLAUDE_PLUGIN_ROOT}/bin/canary-token`, already on
PATH as `canary-token`). Prefer running it directly; fall back to
`bash "${CLAUDE_PLUGIN_ROOT}/bin/canary-token" ...` if the bare command
isn't found.

### `new <aws|card|ssn|env|dburl|freeform> [label]`

Mint a fresh fake decoy and register it as an armed canary — nothing is
written to disk yet.

```bash
canary-token new env "staging API key"
```

For `freeform`, pass the decoy string itself in place of a label:

```bash
canary-token new freeform "Project Nightjar"
```

Types and what each mimics:
- `aws` — an `AKIA...` access key + a paired secret key (also matches Canary's own `aws_access_key`/`aws_secret_key` detectors)
- `card` — a Luhn-valid 16-digit card number (also matches `credit_card`)
- `ssn` — an SSN in the 900-999 area, which the SSA has never issued to a real person, so it can never collide with someone's real SSN
- `env` — a high-entropy API-key-shaped string (also matches `generic_secret` when planted with a keyword like `API_KEY=`)
- `dburl` — a decoy `postgres://user:pass@host/db` connection string (also matches `db_url_credentials`)
- `freeform` — any arbitrary string (a fake codename, trade secret, etc.) — detected only by Canary's certain match, no regex layer involved

Relay the command's own output to the user as-is — that's the one place
the raw value is meant to be shown, since they need it to actually use
the decoy.

### `plant <aws|card|ssn|env|dburl|freeform> [path] [label]`

Mint **and** write a conventional-looking decoy file (`.env.canary`,
`.aws-credentials.canary`, `database.canary.url`, or `canary-<id>.txt`)
into the current directory, or to `[path]` if given.

```bash
canary-token plant env
canary-token plant aws ./config/.aws-credentials.canary
```

Tell the user the planted file is **safe to commit** — that's the whole
point of a canary token — and that Canary will alarm the instant its
contents reach Claude (pasted, read, grepped into context, whatever).

### `list`

Show every canary token, armed and tripped.

### `trips`

Show only tripped canaries — when, from what source, in which session.

### `revoke <id>`

Remove a canary from the registry so it can no longer trip.

### `ack`

Acknowledge current trips, so a HUD/statusline can stop flagging them
as new.

## Why this is CERTAIN, not probabilistic

Every other Canary detector pattern-matches on *shape* (16 digits that
pass Luhn, `AKIA` + 16 chars, an entropy-gated string after `api_key=`)
— it can never be sure a match is the user's real secret rather than a
coincidentally similar string, so it reports `high`/`medium` confidence.
A canary token is different: Canary generated the exact value, so
finding that exact value anywhere is proof positive, not an inference.
That's why a trip is logged at `confidence: "certain"` and
`detector: "canary"` in `leaks.jsonl`, with `value` set to the human
**label** (e.g. `"staging API key"`), never the token itself.

## Important

- NEVER print a canary's raw value in your own summary beyond exactly
  what `new`/`plant` already printed to the user who asked for it —
  don't re-quote it in a recap, a table, or anywhere else.
- `list`/`trips` output shows real (non-redacted) values by design —
  these are fake decoys, not real secrets, so seeing them is expected
  and necessary for the user to recognize what they planted. Still,
  don't gratuitously repeat them back beyond showing the command output.
- A trip is a CERTAIN match on the literal planted string. If the user
  reformats or partially retypes a planted value before it reaches
  Claude, the literal match can miss it — that's an inherent tradeoff
  of certainty over shape-matching, not a bug.

Copyright © 2026 Sonomos Inc. All rights reserved.
