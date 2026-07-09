# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Canary, please report it responsibly. Do not open a public GitHub issue.

**Email:** security@sonomos.ai

Include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Affected components (regex detectors, semantic scan, dashboard, statusline, CLI tools)
- Potential impact
- Any suggested fixes

We'll acknowledge receipt within 48 hours and aim to provide a substantive response within 7 days. Confirmed issues will be patched and coordinated with the reporter before public disclosure.

## Scope

### In Scope

- **Canary plugin code** (regex detectors, semantic scan prompts, dashboard generation, statusline script, CLI tools)
- **Detection data storage** (Canary's data directory — `${CLAUDE_PLUGIN_DATA}` when running as an installed plugin, `~/.sonomos` as the fallback — and all files within)
- **Plugin manifest and hooks** (`.claude-plugin/` directory)
- **Team distribution mechanism** (marketplace registration, project-level settings)
- **CI/CD workflows** (`.github/workflows/`)
- **Test suite** (`tests/`)

### Out of Scope

- Claude Code itself (report to [Anthropic](https://docs.anthropic.com/en/docs/security))
- Third-party dependencies with publicly disclosed CVEs (check if a patch is pending before reporting)
- Social engineering or phishing attacks against contributors
- Denial of service attacks

## What Qualifies

- Data exfiltration from Canary's data directory (detection logs, dashboard data, export files)
- A bypass that allows PII detections to be silently suppressed or tampered with
- Code injection via crafted input that exploits the regex engine or semantic scan parser
- Statusline script vulnerabilities (command injection, path traversal)
- Dashboard HTML generation flaws (XSS, script injection in rendered detection data)
- Insecure file permissions on detection data or exported files
- Plugin manifest manipulation that could escalate privileges within Claude Code
- Secrets or credentials committed to the repository
- CI/CD pipeline vulnerabilities that could compromise published releases

## What Doesn't Qualify

- Detection false positives or false negatives (these are accuracy issues, not security issues; post them in [Discussions](https://github.com/sonomoshq/Canary/discussions) instead)
- Missing detection categories
- Cosmetic issues in the dashboard
- Vulnerabilities requiring physical access to the user's machine
- Outdated dependency versions without a working proof of concept
- Test fixtures that look like credentials — `tests/corpus.json` and the shell test suites use synthetic, defanged, or reserved-range values by convention (see [CONTRIBUTING.md](CONTRIBUTING.md)); none of them are real secrets

## Data Handling

Canary is designed to be fully local. All detection data is stored in Canary's data directory on the user's machine (`${CLAUDE_PLUGIN_DATA}` when running as an installed plugin, `~/.sonomos` as the fallback — see [THREAT_MODEL.md](THREAT_MODEL.md) for the trust boundary this implies). The plugin makes zero network requests. No telemetry, no analytics, no external API calls. The semantic scan runs inside Claude's own context window and does not transmit data to any service beyond what Claude Code already has access to.

Exported data (CSV, JSON) is written to the local filesystem only. The HTML dashboard is a static file generated locally and opened in the user's browser.

If you believe any part of Canary is transmitting data externally in a way that contradicts this policy, that is a critical security issue and should be reported immediately.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release (tagged) | ✅ |
| `main` branch (HEAD) | ✅ |
| All prior commits | ❌ |

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits the vulnerability via email
2. We confirm the issue and begin work on a fix
3. We keep the reporter updated on progress
4. Once patched, we credit the reporter in the release notes (unless they prefer anonymity)
5. Public disclosure happens after the fix is released

We ask for a 90-day window before public disclosure if a fix is in progress.

## A Note on What Canary Handles

Canary processes sensitive data by design. Its entire purpose is to detect PII in Claude Code conversations. This means the detection logs in Canary's data directory will contain references to (and in some cases fragments of) the sensitive data it identified. If you have access to a user's Canary data directory, you have access to a record of their PII exposure.

This is inherent to how the tool works, not a vulnerability. However, any issue that makes this data accessible to unauthorized parties (file permission flaws, exfiltration vectors, unintended network transmission) is absolutely in scope and should be reported.

---

[Sonomos](https://sonomos.ai)
