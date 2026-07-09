#!/usr/bin/env python3
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# custom_rules.py — User-defined detector rules, loaded from
# $SONOMOS_DIR/rules.d/*.json. Python 3 STDLIB ONLY (json, re, os, sys,
# signal, hashlib, time — nothing else). LOCAL-ONLY, ZERO network calls.
#
# ============================================================================
# CLI CONTRACT (this is the integration contract other tools/orchestrators
# rely on — keep it stable):
#
#     python3 custom_rules.py <path-to-textfile>
#
#   Reads the given file's text, applies every enabled rule found under
#   $SONOMOS_DIR/rules.d/*.json (SONOMOS_DIR defaults to
#   $CLAUDE_PLUGIN_DATA, falling back to ~/.sonomos), and prints ONE JSON
#   object per hit to stdout (newline-delimited, i.e. JSONL), in the SAME
#   shape canary/scripts/detectors.sh's emit() produces:
#
#     {"type": "<rule name>",
#      "value": "<redacted>",
#      "detector": "custom",
#      "confidence": "high"|"medium"|"low",
#      "value_id": "<12 hex chars>"}          # omitted if unavailable
#
#   Redaction uses the exact same rule as detectors.sh's redact(): strip
#   whitespace, cap at 64 chars, then <=5 chars -> "••••", else first 2
#   chars + a run of bullet dots (capped at 20, with a "…" marker past the
#   cap) + last 2 chars. Raw matched text is NEVER printed.
#
#   Exit code is ALWAYS 0 for a normal scan — a missing/empty rules.d
#   directory, zero rule files, a malformed rule file, or an unreadable
#   input file are all silently-degrade-and-continue conditions (this is a
#   best-effort second stage in a Stop-hook pipeline; it must never be the
#   thing that breaks the hook). Warnings go to stderr, never stdout.
#   The ONE exception is `--selftest` (see bottom of this file), which
#   exits 1 if any self-test assertion fails, so CI can catch regressions.
#
#   The orchestrator wires this in as an OPTIONAL SECOND STAGE in
#   scan.sh / scan-file.sh: run detectors.sh as today, and ALSO run
#   `python3 custom_rules.py <file>` — but only when rules.d/ exists and
#   is non-empty, so sites with no custom rules pay zero extra cost. This
#   file does not read stdin, does not know about hook JSON, and does not
#   write to leaks.jsonl — it only prints hits; wiring them in is the
#   orchestrator's job.
#
# ============================================================================
# RULE FILE SCHEMA (see canary/scripts/rules.d.README.md for full docs +
# worked examples). A rules.d/*.json file is either:
#   - a single rule object, or
#   - {"rules": [<rule object>, ...]}
#
# Rule object fields:
#   name             string, REQUIRED. Must match ^[a-z][a-z0-9_]{2,40}$
#                    and must NOT collide with a built-in detector type
#                    name from taxonomy.json (rejected with a stderr
#                    warning if it does — this is enforced so a custom
#                    rule can never be confused for, or silently override,
#                    a shipped detector's output type).
#   pattern          string, REQUIRED. A Python `re` pattern. Hard length
#                    cap of 200 chars. Compiled via re.compile ONLY —
#                    never eval/exec'd. Rejected (with a stderr warning)
#                    if it's too long, fails to compile, or matches an
#                    "obviously catastrophic" shape (see
#                    _looks_catastrophic() below) — that heuristic is
#                    best-effort, NOT exhaustive; the real safety net is
#                    the per-rule wall-clock timeout below.
#   flags            list of strings, optional. ALLOWLIST ONLY:
#                    "IGNORECASE", "MULTILINE". Any other value rejects
#                    the whole rule (stderr warning) rather than silently
#                    dropping just the bad flag.
#   context_words    list of strings, optional. If any appears within
#                    `context_window` words before/after a match
#                    (case-insensitive substring test), confidence is
#                    boosted ONE tier (low->medium->high, capped at high).
#   negative_words    list of strings, optional. Same proximity window;
#                    if any appears nearby, confidence is dampened ONE
#                    tier (high->medium->low, floored at low) — this NEVER
#                    drops the hit outright, matching detectors.sh's
#                    placeholder-dampening policy (undercounting is the
#                    failure that matters, not over-counting).
#   context_window   int, optional, default 10. Word-count radius (not
#                    characters) used for context_words/negative_words.
#   validator        one of "luhn" | "mod97" | "aba" | null, optional.
#                    Dispatches to the shipped, stdlib-only validator
#                    functions below — NEVER to user-supplied code of any
#                    kind. If set and the matched text fails validation,
#                    that individual match is dropped (not the whole
#                    rule). Any other value rejects the whole rule.
#   severity         one of "high" | "medium" | "low", REQUIRED. Used as
#                    the hit's base confidence before context
#                    boosting/dampening.
#   sensitivity_class string, optional. Metadata only — not included in
#                    emitted hits; for the orchestrator/dashboard to
#                    merge into its own taxonomy if it chooses to.
#   regulatory_tags  list of strings, optional. Metadata only, see above.
#   risk_weight      int 1-10, optional. Metadata only, see above.
#   enabled          bool, optional, DEFAULTS TO true if omitted. A rule
#                    with enabled: false is skipped silently (not an
#                    error — this is the normal way to disable a rule
#                    without deleting it).
#
# ============================================================================
# SAFETY MEASURES (all implemented below — see the named functions):
#   1. Never eval/exec anything, ever. Patterns go through re.compile only.
#   2. Hard pattern-length cap (200 chars) — _load_rule_file / _compile_rule.
#   3. Heuristic rejection of obviously-catastrophic nested-quantifier /
#      self-overlapping-alternation shapes at LOAD time — _looks_catastrophic().
#   4. Per-rule wall-clock timeout (250ms) via signal.setitimer(ITIMER_REAL,
#      ...) wrapped around match iteration, so one runaway regex that slips
#      past the static heuristic can't stall the 30s Stop hook — on timeout
#      that ONE rule is skipped (for that run), a one-time warning goes to
#      stderr, and every other rule still runs. NOTE: we use
#      signal.setitimer rather than signal.alarm because alarm() only
#      accepts whole seconds — a 250ms budget needs the finer-grained
#      itimer API. Both are the same POSIX signal-based mechanism; this
#      script degrades to "no timeout" gracefully on platforms without
#      SIGALRM (there aren't any relevant to this plugin, but it's cheap
#      insurance).
#   5. context_words/negative_words only ever shift a confidence STRING
#      among {"low","medium","high"} — they can never suppress a hit.
#   6. Local-only: this script never opens a socket, never fetches a URL.
#      Rule files are read from local disk only.
#   7. Matched values are redacted before they are ever written to stdout;
#      the raw matched substring is held only in memory for the duration
#      of one rule's processing.
# ============================================================================

import hashlib
import json
import os
import re
import signal
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMY_PATH = os.path.join(SCRIPT_DIR, "taxonomy.json")

SONOMOS_DIR = os.environ.get("CLAUDE_PLUGIN_DATA") or os.path.expanduser("~/.sonomos")
RULES_DIR = os.path.join(SONOMOS_DIR, "rules.d")
SALT_FILE = os.path.join(SONOMOS_DIR, ".salt")

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
MAX_PATTERN_LEN = 200
ALLOWED_FLAGS = {"IGNORECASE": re.IGNORECASE, "MULTILINE": re.MULTILINE}
ALLOWED_VALIDATORS = {"luhn", "mod97", "aba", None}
ALLOWED_SEVERITIES = {"high", "medium", "low"}
RULE_TIMEOUT_SECONDS = 0.25  # 250ms

_TIERS = ["low", "medium", "high"]

# Detector "type" names built into detectors.sh — a custom rule's `name`
# must not collide with one of these (loaded from taxonomy.json, with a
# small embedded fallback so this still works if taxonomy.json is ever
# missing/unreadable — this script must not hard-depend on it).
_FALLBACK_BUILTIN_TYPES = {
    "credit_card", "email", "iban", "ipv4", "ipv6", "mac_address",
    "bitcoin_address", "ethereum_address", "us_ssn", "aba_routing",
    "url_credentials", "db_url_credentials", "phone_number",
    "us_drivers_license", "aws_access_key", "aws_secret_key", "us_mbi",
    "vin", "github_pat", "gitlab_pat", "slack_token", "slack_webhook",
    "stripe_api_key", "anthropic_api_key", "openai_api_key",
    "google_api_key", "sendgrid_api_key", "npm_token", "jwt",
    "private_key_block", "generic_secret", "nhs_number", "sin_canadian",
    "npi_number", "dea_number", "us_itin",
}


def _load_builtin_type_names():
    try:
        with open(TAXONOMY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        types = data.get("types")
        if isinstance(types, dict) and types:
            return set(types.keys())
    except Exception:
        pass
    return set(_FALLBACK_BUILTIN_TYPES)


BUILTIN_TYPE_NAMES = _load_builtin_type_names()


# ── Redaction (mirrors detectors.sh's redact() exactly) ─────────────────
def redact(value):
    clean = re.sub(r"\s+", "", value)
    if len(clean) > 64:
        clean = clean[:64]
    length = len(clean)
    if length <= 5:
        return "••••"
    mid = length - 4
    ellipsis = ""
    if mid > 20:
        mid = 20
        ellipsis = "…"
    return clean[:2] + ("•" * mid) + ellipsis + clean[-2:]


# ── value_id: salted hash, shared convention with detectors.sh ──────────
def _load_salt():
    try:
        if not os.path.isfile(SALT_FILE) or os.path.getsize(SALT_FILE) == 0:
            os.makedirs(SONOMOS_DIR, exist_ok=True)
            try:
                os.chmod(SONOMOS_DIR, 0o700)
            except OSError:
                pass
            salt_hex = os.urandom(16).hex()
            fd = os.open(SALT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(salt_hex)
        with open(SALT_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def compute_value_id(raw, salt):
    if not salt:
        return None
    digest = hashlib.sha256((salt + raw).encode("utf-8", errors="replace")).hexdigest()
    return digest[:12]


# ── Shipped validators — dispatch target ONLY, never user code ──────────
def _luhn_valid(s):
    digits = re.sub(r"[\s-]", "", s)
    if not digits.isdigit() or not digits:
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _mod97_valid(s):
    iban = re.sub(r"\s", "", s).upper()
    if len(iban) < 5:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric_parts = []
    for ch in rearranged:
        if ch.isalpha():
            numeric_parts.append(str(ord(ch) - 55))
        elif ch.isdigit():
            numeric_parts.append(ch)
        else:
            return False
    numeric = "".join(numeric_parts)
    remainder = 0
    for ch in numeric:
        remainder = (remainder * 10 + int(ch)) % 97
    return remainder == 1


def _aba_valid(s):
    digits = re.sub(r"[\s-]", "", s)
    if len(digits) != 9 or not digits.isdigit():
        return False
    d = [int(c) for c in digits]
    total = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return total % 10 == 0


_VALIDATORS = {"luhn": _luhn_valid, "mod97": _mod97_valid, "aba": _aba_valid}


# ── Catastrophic-backtracking heuristic (best-effort, NOT exhaustive) ───
# Flags two "obvious" shapes:
#   1. A quantified group immediately re-quantified:  (a+)+  (a*)*  (a+)*  (a*)+
#   2. A quantified alternation group with two IDENTICAL branches: (a|a)*
# This intentionally does NOT try to catch subtler ambiguous-alternation
# ReDoS shapes like (a|aa)+ — that's exactly what the runtime timeout
# below exists to catch, and the self-test proves it does.
_NESTED_QUANT_RE = re.compile(r"\([^()]*[+*]\)[+*]")
_QUANTIFIED_GROUP_RE = re.compile(r"\(([^()]*)\)[+*]")


def _looks_catastrophic(pattern):
    if _NESTED_QUANT_RE.search(pattern):
        return True
    for m in _QUANTIFIED_GROUP_RE.finditer(pattern):
        body = m.group(1)
        if "|" in body:
            branches = body.split("|")
            if len(branches) != len(set(branches)):
                return True
    return False


def _shift_confidence(base, boost, dampen):
    try:
        idx = _TIERS.index(base)
    except ValueError:
        idx = 1
    if boost:
        idx += 1
    if dampen:
        idx -= 1
    idx = max(0, min(len(_TIERS) - 1, idx))
    return _TIERS[idx]


def _word_context(text, start, end, window):
    before_words = re.findall(r"\S+", text[:start])[-window:] if window > 0 else []
    after_words = re.findall(r"\S+", text[end:])[:window] if window > 0 else []
    return " ".join(before_words) + " " + " ".join(after_words)


def _contains_any(haystack, words):
    if not words:
        return False
    hl = haystack.lower()
    return any(w.lower() in hl for w in words if w)


# ── Rule loading / validation ────────────────────────────────────────────
class Rule:
    __slots__ = (
        "name", "compiled", "context_words", "negative_words",
        "context_window", "validator", "severity", "source",
    )

    def __init__(self, name, compiled, context_words, negative_words,
                 context_window, validator, severity, source):
        self.name = name
        self.compiled = compiled
        self.context_words = context_words
        self.negative_words = negative_words
        self.context_window = context_window
        self.validator = validator
        self.severity = severity
        self.source = source


def _warn(msg):
    print(f"custom_rules: warning: {msg}", file=sys.stderr)


def _compile_rule(entry, source):
    if not isinstance(entry, dict):
        _warn(f"{source}: rule entry is not an object, skipping")
        return None

    name = entry.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        _warn(f"{source}: rule name {name!r} missing or invalid "
              f"(must match ^[a-z][a-z0-9_]{{2,40}}$), skipping")
        return None
    if name in BUILTIN_TYPE_NAMES:
        _warn(f"{source}: rule name '{name}' collides with a built-in "
              f"detector type name, skipping")
        return None

    pattern = entry.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        _warn(f"{source}: rule '{name}' has no pattern, skipping")
        return None
    if len(pattern) > MAX_PATTERN_LEN:
        _warn(f"{source}: rule '{name}' pattern exceeds {MAX_PATTERN_LEN} "
              f"chars, skipping")
        return None
    if _looks_catastrophic(pattern):
        _warn(f"{source}: rule '{name}' pattern looks like it could cause "
              f"catastrophic backtracking (nested/self-overlapping "
              f"quantifiers), skipping")
        return None

    flags_val = 0
    for flag_name in entry.get("flags", []) or []:
        if flag_name not in ALLOWED_FLAGS:
            _warn(f"{source}: rule '{name}' uses disallowed flag "
                  f"{flag_name!r} (allowed: {sorted(ALLOWED_FLAGS)}), "
                  f"skipping rule")
            return None
        flags_val |= ALLOWED_FLAGS[flag_name]

    try:
        compiled = re.compile(pattern, flags_val)
    except re.error as e:
        _warn(f"{source}: rule '{name}' pattern failed to compile: {e}, "
              f"skipping")
        return None

    validator = entry.get("validator")
    if validator not in ALLOWED_VALIDATORS:
        _warn(f"{source}: rule '{name}' has unknown validator "
              f"{validator!r} (allowed: luhn, mod97, aba, null), skipping")
        return None

    severity = entry.get("severity")
    if severity not in ALLOWED_SEVERITIES:
        _warn(f"{source}: rule '{name}' severity {severity!r} must be one "
              f"of high/medium/low, skipping")
        return None

    context_words = entry.get("context_words") or []
    negative_words = entry.get("negative_words") or []
    if not isinstance(context_words, list) or not isinstance(negative_words, list):
        _warn(f"{source}: rule '{name}' context_words/negative_words must "
              f"be lists, skipping")
        return None

    context_window = entry.get("context_window", 10)
    if not isinstance(context_window, int) or isinstance(context_window, bool) or context_window < 0:
        _warn(f"{source}: rule '{name}' context_window must be a "
              f"non-negative int, skipping")
        return None

    risk_weight = entry.get("risk_weight")
    if risk_weight is not None and (not isinstance(risk_weight, int) or not (1 <= risk_weight <= 10)):
        _warn(f"{source}: rule '{name}' risk_weight must be an int 1-10, "
              f"skipping")
        return None

    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        _warn(f"{source}: rule '{name}' enabled must be a bool, skipping")
        return None
    if not enabled:
        return None  # quietly disabled, not an error

    return Rule(
        name=name,
        compiled=compiled,
        context_words=context_words,
        negative_words=negative_words,
        context_window=context_window,
        validator=validator,
        severity=severity,
        source=source,
    )


def load_rules(rules_dir=RULES_DIR):
    rules = []
    if not os.path.isdir(rules_dir):
        return rules
    try:
        filenames = sorted(f for f in os.listdir(rules_dir) if f.endswith(".json"))
    except OSError as e:
        _warn(f"could not list {rules_dir}: {e}")
        return rules

    for fname in filenames:
        path = os.path.join(rules_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            _warn(f"{path}: failed to parse ({e}), skipping file")
            continue

        if isinstance(data, dict) and "rules" in data:
            entries = data["rules"]
            if not isinstance(entries, list):
                _warn(f"{path}: 'rules' must be a list, skipping file")
                continue
        elif isinstance(data, dict):
            entries = [data]
        elif isinstance(data, list):
            entries = data
        else:
            _warn(f"{path}: unrecognized rule file shape, skipping file")
            continue

        for entry in entries:
            rule = _compile_rule(entry, path)
            if rule is not None:
                rules.append(rule)

    return rules


# ── Per-rule wall-clock timeout ──────────────────────────────────────────
class _RuleTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _RuleTimeout()


_HAS_SIGALRM = hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")


def _scan_with_timeout(rule, text):
    """Return the list of re.Match objects for rule.compiled over text,
    or None if the rule timed out (250ms wall-clock budget)."""
    if not _HAS_SIGALRM:
        return list(rule.compiled.finditer(text))
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, RULE_TIMEOUT_SECONDS)
    try:
        return list(rule.compiled.finditer(text))
    except _RuleTimeout:
        return None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


# ── Scanning ──────────────────────────────────────────────────────────────
def scan_text(text, rules, salt=None):
    """Apply every rule to text, returning a list of hit dicts (already
    redacted, in emit()-compatible shape). Never raises."""
    hits = []
    seen = set()
    warned_timeout = set()

    for rule in rules:
        matches = _scan_with_timeout(rule, text)
        if matches is None:
            if rule.name not in warned_timeout:
                _warn(f"rule '{rule.name}' exceeded its "
                      f"{int(RULE_TIMEOUT_SECONDS * 1000)}ms budget and was "
                      f"skipped for this run")
                warned_timeout.add(rule.name)
            continue

        for m in matches:
            raw = m.group(0)
            if not raw:
                continue

            if rule.validator:
                validator_fn = _VALIDATORS[rule.validator]
                try:
                    if not validator_fn(raw):
                        continue
                except Exception:
                    continue

            key = (rule.name, raw)
            if key in seen:
                continue
            seen.add(key)

            ctx = _word_context(text, m.start(), m.end(), rule.context_window)
            boost = _contains_any(ctx, rule.context_words)
            dampen = _contains_any(ctx, rule.negative_words)
            confidence = _shift_confidence(rule.severity, boost, dampen)

            hit = {
                "type": rule.name,
                "value": redact(raw),
                "detector": "custom",
                "confidence": confidence,
            }
            if salt:
                vid = compute_value_id(raw, salt)
                if vid:
                    hit["value_id"] = vid
            hits.append(hit)

    return hits


def main(argv):
    if len(argv) < 2:
        print("usage: python3 custom_rules.py <path-to-textfile>", file=sys.stderr)
        return 0

    path = argv[1]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        _warn(f"could not read {path}: {e}")
        return 0

    if not text:
        return 0

    try:
        rules = load_rules()
        if not rules:
            return 0
        salt = _load_salt()
        hits = scan_text(text, rules, salt)
        for hit in hits:
            print(json.dumps(hit, ensure_ascii=False))
    except Exception as e:  # never let an unexpected error break the hook
        _warn(f"unexpected error, no hits emitted: {e}")
    return 0


# ============================================================================
# SELF-TESTS — run with `python3 custom_rules.py --selftest`. Exercises the
# safety machinery (name collision, pattern length cap, catastrophic-regex
# heuristic, runtime timeout, validator dispatch) and the schema/rule-shape
# handling WITHOUT needing a real rules.d directory on disk, so CI can run
# this in any environment. Exits 1 if any assertion fails, 0 otherwise —
# this is the one path in this file where a non-zero exit is intentional.
# ============================================================================
def _run_selftests():
    import tempfile

    passed = 0
    failed = 0

    def check(label, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS: {label}")
        else:
            failed += 1
            print(f"  FAIL: {label}")

    # -- redact() shape --
    check("redact: <=5 chars fully masked", redact("ab12") == "••••")
    check("redact: first2+dots+last2", redact("EMP-123456") == "EM" + ("•" * 6) + "56")
    long_val = "A" * 80
    check("redact: 64-char truncation + 20-dot cap + ellipsis",
          redact(long_val) == "AA" + ("•" * 20) + "…" + "AA")

    # -- validators --
    check("luhn: valid Visa test number", _luhn_valid("4532015112830366"))
    check("luhn: invalid number rejected", not _luhn_valid("4532015112830367"))
    check("mod97: valid German IBAN", _mod97_valid("DE89370400440532013000"))
    check("mod97: invalid IBAN rejected", not _mod97_valid("DE89370400440532013001"))
    check("aba: valid routing number", _aba_valid("021000021"))
    check("aba: invalid routing number rejected", not _aba_valid("021000022"))

    # -- catastrophic-shape heuristic --
    check("heuristic flags (a+)+", _looks_catastrophic(r"(a+)+"))
    check("heuristic flags (a*)*", _looks_catastrophic(r"(a*)*"))
    check("heuristic flags (a|a)*", _looks_catastrophic(r"(a|a)*"))
    check("heuristic allows a normal pattern", not _looks_catastrophic(r"\bEMP-\d{6}\b"))
    check("heuristic allows a common quantified alternation",
          not _looks_catastrophic(r"(foo|bar)+"))

    # -- rule compilation: name collision with a built-in type --
    with_collision = _compile_rule(
        {"name": "email", "pattern": r"\bx\b", "severity": "low", "enabled": True},
        "<selftest>",
    )
    check("rule named 'email' rejected (collides with built-in type)",
          with_collision is None)

    # -- rule compilation: pattern length cap --
    too_long = _compile_rule(
        {"name": "too_long_rule", "pattern": "a" * (MAX_PATTERN_LEN + 1),
         "severity": "low", "enabled": True},
        "<selftest>",
    )
    check("overlong pattern rejected", too_long is None)

    # -- rule compilation: catastrophic pattern rejected at load time --
    catastrophic = _compile_rule(
        {"name": "catastrophic_rule", "pattern": r"(a+)+$",
         "severity": "low", "enabled": True},
        "<selftest>",
    )
    check("catastrophic pattern rejected at load", catastrophic is None)

    # -- rule compilation: disallowed flag rejected --
    bad_flag = _compile_rule(
        {"name": "bad_flag_rule", "pattern": r"\bx\b", "flags": ["DOTALL"],
         "severity": "low", "enabled": True},
        "<selftest>",
    )
    check("disallowed regex flag rejected", bad_flag is None)

    # -- rule compilation: disallowed validator rejected --
    bad_validator = _compile_rule(
        {"name": "bad_validator_rule", "pattern": r"\bx\b",
         "validator": "os.system", "severity": "low", "enabled": True},
        "<selftest>",
    )
    check("disallowed validator name rejected", bad_validator is None)

    # -- rule compilation: enabled defaults to True when omitted --
    default_enabled = _compile_rule(
        {"name": "default_enabled_rule", "pattern": r"\bx\b", "severity": "low"},
        "<selftest>",
    )
    check("enabled defaults to true when omitted", default_enabled is not None)

    # -- rule compilation: enabled: false is skipped quietly --
    disabled = _compile_rule(
        {"name": "disabled_rule", "pattern": r"\bx\b", "severity": "low",
         "enabled": False},
        "<selftest>",
    )
    check("enabled: false rule compiles to None (quietly skipped)", disabled is None)

    # -- end-to-end: valid rule matches and redacts --
    emp_rule = _compile_rule(
        {"name": "employee_id", "pattern": r"\bEMP-\d{6}\b",
         "context_words": ["employee", "staff"],
         "negative_words": ["example", "sample"],
         "severity": "medium", "enabled": True},
        "<selftest>",
    )
    check("employee_id rule compiles", emp_rule is not None)
    if emp_rule is not None:
        hits = scan_text("the employee record shows EMP-482913 on file",
                          [emp_rule], salt="")
        check("employee_id rule fires exactly once", len(hits) == 1)
        if hits:
            check("hit shape matches emit() contract",
                  set(hits[0].keys()) <= {"type", "value", "detector", "confidence", "value_id"}
                  and hits[0]["type"] == "employee_id"
                  and hits[0]["detector"] == "custom")
            check("context_word ('employee') boosts medium->high",
                  hits[0]["confidence"] == "high")
            check("raw value never appears in output",
                  "482913" not in hits[0]["value"])

        # negative_words dampens instead of dropping
        hits2 = scan_text("e.g. a sample employee id EMP-482913 for docs",
                          [emp_rule], salt="")
        check("negative_words dampens but does NOT drop the hit",
              len(hits2) == 1)
        if hits2:
            # both an "employee" context word AND "sample"/"e.g." negative
            # words are present here -> boost and dampen cancel out net,
            # landing back at the rule's base severity ("medium").
            check("boost + dampen roughly cancel back to base severity",
                  hits2[0]["confidence"] == "medium")

    # -- validator drops a failing match without dropping the rule --
    cc_rule = _compile_rule(
        {"name": "loyalty_number", "pattern": r"\b\d{16}\b",
         "validator": "luhn", "severity": "medium", "enabled": True},
        "<selftest>",
    )
    check("loyalty_number rule compiles", cc_rule is not None)
    if cc_rule is not None:
        hits3 = scan_text("valid: 4532015112830366 invalid: 1234567890123456",
                           [cc_rule], salt="")
        check("validator keeps the Luhn-valid match and drops the invalid one",
              len(hits3) == 1)

    # -- runtime timeout: a pattern that SLIPS PAST the static heuristic
    # (branches "a"/"aa" aren't identical, so _looks_catastrophic doesn't
    # flag it) but is genuinely catastrophic at match time on adversarial
    # input. Proves the 250ms wall-clock timeout is the real safety net,
    # and that OTHER rules still run when one rule times out. --
    if _HAS_SIGALRM:
        slow_rule = _compile_rule(
            {"name": "slow_rule", "pattern": r"(a|aa)+$",
             "severity": "low", "enabled": True},
            "<selftest>",
        )
        fast_rule = _compile_rule(
            {"name": "fast_rule", "pattern": r"\bEMP-\d{6}\b",
             "severity": "high", "enabled": True},
            "<selftest>",
        )
        check("slow_rule (ambiguous alternation) NOT caught by static heuristic",
              slow_rule is not None)
        if slow_rule is not None and fast_rule is not None:
            adversarial = ("a" * 32) + "!  employee EMP-482913"
            import io
            import contextlib
            stderr_buf = io.StringIO()
            with contextlib.redirect_stderr(stderr_buf):
                hits4 = scan_text(adversarial, [slow_rule, fast_rule], salt="")
            check("slow_rule times out and contributes no hits",
                  all(h["type"] != "slow_rule" for h in hits4))
            check("fast_rule still fires after slow_rule timed out",
                  any(h["type"] == "fast_rule" for h in hits4))
            check("timeout warning was printed to stderr",
                  "slow_rule" in stderr_buf.getvalue() and "budget" in stderr_buf.getvalue())
    else:
        print("  SKIP: SIGALRM/setitimer unavailable on this platform, "
              "skipping runtime-timeout tests")

    # -- rule file shapes: single object vs {"rules": [...]} --
    with tempfile.TemporaryDirectory() as tmp:
        single_path = os.path.join(tmp, "single.json")
        with open(single_path, "w", encoding="utf-8") as f:
            json.dump(
                {"name": "single_shape_rule", "pattern": r"\bZZZ\d{3}\b",
                 "severity": "low", "enabled": True},
                f,
            )
        multi_path = os.path.join(tmp, "multi.json")
        with open(multi_path, "w", encoding="utf-8") as f:
            json.dump(
                {"rules": [
                    {"name": "multi_shape_rule_a", "pattern": r"\bYYY\d{3}\b",
                     "severity": "low", "enabled": True},
                    {"name": "multi_shape_rule_b", "pattern": r"\bXXX\d{3}\b",
                     "severity": "low", "enabled": True},
                ]},
                f,
            )
        loaded = load_rules(tmp)
        loaded_names = {r.name for r in loaded}
        check("single-object rule file shape loads",
              "single_shape_rule" in loaded_names)
        check("{'rules': [...]} file shape loads both entries",
              {"multi_shape_rule_a", "multi_shape_rule_b"} <= loaded_names)

    # -- no rules dir at all -> empty, no crash --
    empty = load_rules(os.path.join(tempfile.gettempdir(),
                                     "canary-selftest-nonexistent-rules-dir"))
    check("nonexistent rules dir yields an empty rule list", empty == [])

    print("")
    print("===============================")
    print(f"Results: {passed} passed, {failed} failed")
    print("===============================")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(_run_selftests())
    sys.exit(main(sys.argv))
