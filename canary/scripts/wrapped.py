#!/usr/bin/env python3
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# wrapped.py — Generates "Canary Wrapped", a self-contained, shareable,
# Spotify-Wrapped-style HTML recap of the sensitive data a developer has
# exposed to Claude, sourced from ${CLAUDE_PLUGIN_DATA:-~/.sonomos}/leaks.jsonl.
#
# Hard constraints (mirrors dashboard.py):
#   - Python 3 standard library ONLY. No third-party imports, ever.
#   - Output is a single self-contained HTML file with ZERO external network
#     requests: no @import, no CDN fonts/scripts, no remote images or fetches.
#     System font stacks only. Plain <a href> links to sonomos.ai/GitHub are
#     fine — they only fire on a user click, never on page load.
#   - Must never crash on malformed or legacy leaks.jsonl rows (missing
#     fields, wrong types, garbage JSON), a missing/corrupt taxonomy.json, or
#     a zero-detection period. Every field read is defensive.
#   - Every dynamic string that reaches the HTML is escaped with html.escape.
#     The embedded JSON data island additionally escapes "</" so it can never
#     break out of its <script> tag. Client-side JS updates existing DOM via
#     textContent only — never innerHTML — for anything derived from data.
#   - Scoring/persona math is defined once, canonically, in taxonomy.json
#     (next to this file) and MUST match dashboard.py's model so a grade or
#     persona never disagrees across Canary surfaces.
#
# Deliberately does NOT import dashboard.py — reads leaks.jsonl directly to
# avoid coupling the two self-contained generators together.
#
# Usage: python3 wrapped.py [--period 30d|90d|all] [--out PATH] [--demo]
#                            [--no-open] [--print-path-only]

import argparse
import html
import json
import os
import random
import sys
import webbrowser
from collections import Counter
from datetime import datetime, timedelta

# ═════════════════════════════════════════════════════════════════════════
# Paths
# ═════════════════════════════════════════════════════════════════════════

SONOMOS_DIR = os.environ.get("CLAUDE_PLUGIN_DATA") or os.path.expanduser("~/.sonomos")
LEAKS_FILE = os.path.join(SONOMOS_DIR, "leaks.jsonl")
DEFAULT_OUTPUT_FILE = os.path.join(SONOMOS_DIR, "canary-wrapped.html")
TAXONOMY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "taxonomy.json")

# ═════════════════════════════════════════════════════════════════════════
# Constants
# ═════════════════════════════════════════════════════════════════════════

MONTH_ABBR = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

PERIOD_CHOICES = ("30d", "90d", "all")
PERIOD_LABELS = {"30d": "Last 30 Days", "90d": "Last 90 Days", "all": "All Time"}
PERIOD_DEMO_DAYS = {"30d": 30, "90d": 90, "all": 180}

# Words that should render fully uppercase in a human-readable type label.
_ACRONYMS = {
    "aws", "ssn", "iban", "jwt", "gcp", "vin", "mrn", "pat", "ip", "id",
    "aba", "ein", "fein", "itin", "dea", "npi", "nhs", "sin", "mbi", "bic",
    "swift", "imei", "udid", "mac", "uuid", "url", "api", "jwk", "otp",
    "us", "cvv", "npm", "db", "icd10", "uk", "nino",
}
# Words with a specific mixed-case spelling.
_SPECIAL_WORDS = {
    "github": "GitHub", "gitlab": "GitLab", "oauth": "OAuth",
    "openai": "OpenAI", "metamask": "MetaMask",
}

# Family accent colors — reuses dashboard.py's dark-theme palette so Wrapped
# and the dashboard read as one product.
FAMILY_COLORS = {
    "Identity": "#0086b7", "Financial": "#006fbc", "Crypto": "#506ed8",
    "Legal": "#9573f5", "Medical": "#997de0", "Technical": "#935697",
    "Network": "#c96195", "Organizational": "#af5070", "Tripwire": "#f0555a",
    "Other": "#7d8593",
}
CLASS_COLORS = {
    "secret": "#935697", "pci": "#006fbc", "phi": "#997de0", "crypto": "#506ed8",
    "network": "#c96195", "financial": "#006fbc", "organizational": "#af5070",
    "pii": "#0086b7", "public": "#7d8593",
}
GRADE_SEV = {"A+": "good", "A": "good", "B": "mid", "C": "mid", "D": "bad", "F": "bad"}
GRADE_VERDICTS = {
    "A+": "Immaculate. Not a feather out of place.",
    "A": "Barely a chirp. You're mostly fine.",
    "B": "The canary's getting restless.",
    "C": "Feathers are flying. Time to clean house.",
    "D": "The canary is not okay.",
    "F": "Feathers everywhere. Certified oversharer.",
}

# ═════════════════════════════════════════════════════════════════════════
# Taxonomy defaults — used only if taxonomy.json is missing or corrupt.
# Mirrors the canonical shape documented in taxonomy.json's _scoring /
# _personas comments so Wrapped keeps working (in a degraded, generic way)
# even without the shared file next to it.
# ═════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIDENCE_MULTIPLIER = {"high": 1.0, "medium": 0.6, "low": 0.3, "certain": 1.0}
DEFAULT_GRADE_BANDS = [
    {"grade": "A+", "max": 0}, {"grade": "A", "max": 8}, {"grade": "B", "max": 25},
    {"grade": "C", "max": 75}, {"grade": "D", "max": 250},
]
DEFAULT_GRADE_FALLBACK = "F"
DEFAULT_TYPE_INFO = {"family": "Other", "sensitivity_class": "pii", "regulatory_tags": [], "risk_weight": 3}
DEFAULT_PERSONAS = [
    {"cond": "clean", "label": "The Untouchable", "emoji": "\U0001F54A️", "blurb": "Nothing leaked. The canary sings."},
    {"cond": "tripped", "label": "The Tripwire", "emoji": "\U0001F3AF", "blurb": "You planted a trap and walked right into it."},
    {"cond": "class:secret", "label": "The Secret Sprinkler", "emoji": "\U0001F510", "blurb": "Keys, tokens, and credentials everywhere you go."},
    {"cond": "class:pci", "label": "The Cardholder", "emoji": "\U0001F4B3", "blurb": "Card numbers keep finding their way into the chat."},
    {"cond": "class:phi", "label": "The Chart Leaker", "emoji": "\U0001FA7A", "blurb": "Protected health data, out in the open."},
    {"cond": "class:crypto", "label": "The Crypto Cowboy", "emoji": "\U0001F920", "blurb": "Wallets and chains, shared without a second thought."},
    {"cond": "night", "label": "The Night Owl", "emoji": "\U0001F989", "blurb": "Your worst leaks happen after midnight."},
    {"cond": "polyglot", "label": "The Polyglot Leaker", "emoji": "\U0001F310", "blurb": "A little bit of every kind of sensitive data."},
    {"cond": "oversharer", "label": "The Oversharer", "emoji": "\U0001F4E2", "blurb": "The number just keeps going up."},
    {"cond": "family:Identity", "label": "The Introducer", "emoji": "\U0001F44B", "blurb": "Names, emails, and IDs are your specialty."},
    {"cond": "family:Financial", "label": "The Big Spender", "emoji": "\U0001F4B8", "blurb": "Follow the money — it's in your transcripts."},
    {"cond": "family:Network", "label": "The Broadcaster", "emoji": "\U0001F4E1", "blurb": "Addresses and endpoints, freely shared."},
    {"cond": "family:Technical", "label": "The Secret Sprinkler", "emoji": "\U0001F510", "blurb": "Keys, tokens, and credentials everywhere you go."},
    {"cond": "default", "label": "The Canary", "emoji": "\U0001F424", "blurb": "Watching what you share, one message at a time."},
]
DEFAULT_TAXONOMY = {
    "confidence_multiplier": DEFAULT_CONFIDENCE_MULTIPLIER,
    "grade_bands": DEFAULT_GRADE_BANDS,
    "grade_fallback": DEFAULT_GRADE_FALLBACK,
    "personas": DEFAULT_PERSONAS,
    "default": DEFAULT_TYPE_INFO,
    "types": {},
}

MAX_ALL_WINDOW_DAYS = 3650  # guard against a pathological/garbage far-past timestamp

_LOCAL_OFFSET = datetime.now().astimezone().utcoffset() or timedelta(0)

# ═════════════════════════════════════════════════════════════════════════
# Small helpers
# ═════════════════════════════════════════════════════════════════════════


def esc(value):
    """html.escape every dynamic value before it reaches the page."""
    return html.escape(str(value), quote=True)


def human_type_label(t):
    if not t:
        return "Unknown"
    words = str(t).replace("_", " ").split()
    if not words:
        return "Unknown"
    out = []
    for w in words:
        lw = w.lower()
        if lw in _SPECIAL_WORDS:
            out.append(_SPECIAL_WORDS[lw])
        elif lw in _ACRONYMS:
            out.append(lw.upper())
        else:
            out.append(lw.capitalize())
    return " ".join(out)


def fmt_int(n):
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "0"


def fmt_score(s):
    try:
        s = float(s)
    except (TypeError, ValueError):
        return "0"
    if abs(s - round(s)) < 1e-9:
        return fmt_int(int(round(s)))
    return f"{s:,.1f}"


def fmt_date(d):
    if d is None:
        return ""
    return f"{MONTH_ABBR[d.month - 1]} {d.day}, {d.year}"


def fmt_range(start, end):
    if start is None or end is None:
        return ""
    if start == end:
        return fmt_date(start)
    return f"{fmt_date(start)} – {fmt_date(end)}"


# ═════════════════════════════════════════════════════════════════════════
# Taxonomy — shared scoring / persona model (see taxonomy.json _scoring and
# _personas comments; every surface, including dashboard.py, MUST implement
# this identically so a grade or persona never disagrees across tools).
# ═════════════════════════════════════════════════════════════════════════


def load_taxonomy():
    try:
        with open(TAXONOMY_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return dict(DEFAULT_TAXONOMY)
    if not isinstance(data, dict):
        return dict(DEFAULT_TAXONOMY)

    out = dict(DEFAULT_TAXONOMY)
    for key in ("confidence_multiplier", "grade_bands", "grade_fallback", "personas", "default", "types"):
        if key in data and data[key] is not None:
            out[key] = data[key]
    if not isinstance(out.get("types"), dict):
        out["types"] = {}
    if not isinstance(out.get("personas"), list) or not out["personas"]:
        out["personas"] = DEFAULT_PERSONAS
    if not isinstance(out.get("grade_bands"), list) or not out["grade_bands"]:
        out["grade_bands"] = DEFAULT_GRADE_BANDS
    if not isinstance(out.get("confidence_multiplier"), dict):
        out["confidence_multiplier"] = DEFAULT_CONFIDENCE_MULTIPLIER
    if not isinstance(out.get("default"), dict):
        out["default"] = DEFAULT_TYPE_INFO
    if not isinstance(out.get("grade_fallback"), str) or not out["grade_fallback"]:
        out["grade_fallback"] = DEFAULT_GRADE_FALLBACK
    return out


def get_type_info(taxonomy, t):
    types = taxonomy.get("types")
    info = types.get(t) if isinstance(types, dict) else None
    if not isinstance(info, dict):
        info = taxonomy.get("default")
        if not isinstance(info, dict):
            info = DEFAULT_TYPE_INFO
    family = info.get("family")
    family = family if isinstance(family, str) and family else "Other"
    sensitivity_class = info.get("sensitivity_class")
    sensitivity_class = sensitivity_class if isinstance(sensitivity_class, str) and sensitivity_class else "pii"
    risk_weight = info.get("risk_weight")
    risk_weight = risk_weight if isinstance(risk_weight, (int, float)) and not isinstance(risk_weight, bool) else 3
    return {"family": family, "sensitivity_class": sensitivity_class, "risk_weight": risk_weight}


def get_confidence_multiplier(taxonomy, conf):
    mult = taxonomy.get("confidence_multiplier")
    if not isinstance(mult, dict):
        mult = DEFAULT_CONFIDENCE_MULTIPLIER
    v = mult.get(conf)
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else 1.0


def compute_risk_score(taxonomy, records):
    """S = sum over all hits of (risk_weight * confidence_multiplier)."""
    total = 0.0
    for r in records:
        info = get_type_info(taxonomy, r["type"])
        mult = get_confidence_multiplier(taxonomy, r["confidence"])
        total += info["risk_weight"] * mult
    return total


def compute_grade(taxonomy, score):
    """First grade_bands entry (scanned top to bottom) whose max >= score.
    Because bands are ordered ascending and A+'s max is 0, this naturally
    yields A+ only when score == 0 exactly. Falls back to grade_fallback if
    score exceeds every band's max."""
    bands = taxonomy.get("grade_bands")
    if not isinstance(bands, list) or not bands:
        bands = DEFAULT_GRADE_BANDS
    for band in bands:
        if not isinstance(band, dict):
            continue
        mx = band.get("max")
        grade = band.get("grade")
        if isinstance(mx, (int, float)) and not isinstance(mx, bool) and isinstance(grade, str) and mx >= score:
            return grade
    fb = taxonomy.get("grade_fallback")
    return fb if isinstance(fb, str) and fb else DEFAULT_GRADE_FALLBACK


def compute_persona_context(records, taxonomy):
    total = len(records)
    distinct_types = len(set(r["type"] for r in records))
    class_counts = Counter()
    family_counts = Counter()
    night_hits = 0
    tripped = False
    for r in records:
        info = get_type_info(taxonomy, r["type"])
        class_counts[info["sensitivity_class"]] += 1
        family_counts[info["family"]] += 1
        if r["type"] == "canary_tripped":
            tripped = True
        if r["dt_utc"] is not None:
            local_dt = r["dt_utc"] + _LOCAL_OFFSET
            if 0 <= local_dt.hour < 5:
                night_hits += 1
    night = (total > 0) and (night_hits / total >= 0.3)
    dominant_class = class_counts.most_common(1)[0][0] if class_counts else None
    dominant_family = family_counts.most_common(1)[0][0] if family_counts else None
    return {
        "total": total, "distinct_types": distinct_types,
        "dominant_class": dominant_class, "dominant_family": dominant_family,
        "night": night, "tripped": tripped,
    }


def compute_persona(taxonomy, ctx):
    personas = taxonomy.get("personas")
    if not isinstance(personas, list) or not personas:
        personas = DEFAULT_PERSONAS
    for p in personas:
        if not isinstance(p, dict):
            continue
        cond = p.get("cond", "")
        if cond == "clean" and ctx["total"] == 0:
            return p
        if cond == "tripped" and ctx["tripped"]:
            return p
        if isinstance(cond, str) and cond.startswith("class:") and ctx["dominant_class"] == cond[len("class:"):]:
            return p
        if cond == "night" and ctx["night"]:
            return p
        if cond == "polyglot" and ctx["distinct_types"] >= 12:
            return p
        if cond == "oversharer" and ctx["total"] >= 100:
            return p
        if isinstance(cond, str) and cond.startswith("family:") and ctx["dominant_family"] == cond[len("family:"):]:
            return p
        if cond == "default":
            return p
    return personas[-1] if personas else DEFAULT_PERSONAS[-1]


def get_persona_accent(persona, ctx):
    cond = (persona or {}).get("cond", "")
    if cond == "clean":
        return "#3ddc84"
    if cond == "tripped":
        return "#f0555a"
    if cond == "night":
        return "#4fc1e9"
    dom_class = ctx.get("dominant_class")
    if dom_class in CLASS_COLORS:
        return CLASS_COLORS[dom_class]
    return "#e8a33d"


def get_family_accent(family):
    return FAMILY_COLORS.get(family, "#7d8593")


# ═════════════════════════════════════════════════════════════════════════
# Data loading — NEVER crash on malformed input (mirrors dashboard.py)
# ═════════════════════════════════════════════════════════════════════════


def load_leaks_raw(path):
    """Read leaks.jsonl, tolerating blank lines and broken JSON."""
    if not path or not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
    except OSError:
        return []
    return out


def _safe_str(v, default=""):
    if v is None:
        return default
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float, bool)):
        return str(v)
    return default


def _parse_timestamp(ts):
    """Best-effort ISO8601 'Z' parse. Returns a naive UTC datetime or None."""
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.fromisoformat(s[:19])
        except ValueError:
            return None
    if dt.tzinfo is not None:
        dt = (dt - dt.utcoffset()).replace(tzinfo=None)
    return dt


def normalize_record(raw):
    """Turn one arbitrary dict (possibly missing every field) into a safe,
    fully-defaulted record. Never raises."""
    if not isinstance(raw, dict):
        return None
    rec_type = _safe_str(raw.get("type")).strip() or "unknown"
    confidence = raw.get("confidence")
    confidence = confidence if isinstance(confidence, str) and confidence else "unknown"
    ts_raw = raw.get("timestamp")
    dt_utc = _parse_timestamp(ts_raw) if isinstance(ts_raw, str) else None
    return {"type": rec_type, "confidence": confidence, "dt_utc": dt_utc}


def load_leaks():
    return [r for r in (normalize_record(x) for x in load_leaks_raw(LEAKS_FILE)) if r]


# ═════════════════════════════════════════════════════════════════════════
# Period windowing
# ═════════════════════════════════════════════════════════════════════════


def compute_window(period, records, now_utc):
    """Returns (window_start_date, window_end_date), both inclusive."""
    today = now_utc.date()
    if period == "30d":
        return today - timedelta(days=29), today
    if period == "90d":
        return today - timedelta(days=89), today
    dates = [r["dt_utc"].date() for r in records if r.get("dt_utc") is not None]
    if dates:
        start = min(dates)
        if (today - start).days > MAX_ALL_WINDOW_DAYS:
            start = today - timedelta(days=MAX_ALL_WINDOW_DAYS)
    else:
        start = today
    return start, today


def filter_by_period(records, period, window_start, window_end):
    if period == "all":
        return list(records)
    out = []
    for r in records:
        dt = r.get("dt_utc")
        if dt is None:
            continue
        d = dt.date()
        if window_start <= d <= window_end:
            out.append(r)
    return out


# ═════════════════════════════════════════════════════════════════════════
# Aggregation — the four shareable "moments"
# ═════════════════════════════════════════════════════════════════════════


def compute_top_categories(records, taxonomy, n=3):
    counts = Counter(r["type"] for r in records)
    out = []
    for t, c in counts.most_common(n):
        info = get_type_info(taxonomy, t)
        out.append({"type": t, "label": human_type_label(t), "count": c, "family": info["family"]})
    return out


def compute_biggest_spike(records, taxonomy):
    daily = Counter(r["dt_utc"].date() for r in records if r.get("dt_utc") is not None)
    if not daily:
        return None
    best_day, best_count = max(daily.items(), key=lambda kv: (kv[1], kv[0]))
    day_types = Counter(
        r["type"] for r in records
        if r.get("dt_utc") is not None and r["dt_utc"].date() == best_day
    )
    dominant_type = day_types.most_common(1)[0][0] if day_types else "unknown"
    family = get_type_info(taxonomy, dominant_type)["family"]
    return {"date": best_day, "count": best_count, "type": dominant_type,
            "label": human_type_label(dominant_type), "family": family}


def compute_cleanest_streak(records, window_start, window_end):
    if window_start is None or window_end is None or window_start > window_end:
        return {"days": 0, "start": None, "end": None}
    span_days = (window_end - window_start).days + 1
    if span_days > MAX_ALL_WINDOW_DAYS:
        window_start = window_end - timedelta(days=MAX_ALL_WINDOW_DAYS)

    daily = Counter(r["dt_utc"].date() for r in records if r.get("dt_utc") is not None)
    best_len, best_start, best_end = 0, None, None
    cur_len, cur_start = 0, None
    d = window_start
    while d <= window_end:
        if daily.get(d, 0) == 0:
            if cur_len == 0:
                cur_start = d
            cur_len += 1
            if cur_len > best_len:
                best_len, best_start, best_end = cur_len, cur_start, d
        else:
            cur_len = 0
        d += timedelta(days=1)
    return {"days": best_len, "start": best_start, "end": best_end}


# ═════════════════════════════════════════════════════════════════════════
# Demo data generator — reserved / safe values ONLY, same approach as
# dashboard.py's --demo (4111-family test cards, 555-01xx phones,
# 198.51.100.x IPs, invalid-block SSNs, ghp_/sk-ant- fakes, @example.com).
# Never touches real user data or leaks.jsonl.
# ═════════════════════════════════════════════════════════════════════════

_HEXDIGITS = "0123456789abcdef"
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _redact(raw):
    """Mirrors detectors.sh redact(): first2 + bullets + last2."""
    clean = "".join(raw.split())
    if len(clean) <= 5:
        return "••••"
    return clean[:2] + ("•" * (len(clean) - 4)) + clean[-2:]


def _luhn_check_digit(partial_digits):
    digits = [int(c) for c in partial_digits]
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def _demo_value_generators(rng):
    def credit_card():
        prefix = "41111111111" + str(rng.randint(0, 9))
        chk = _luhn_check_digit(prefix + "0")
        return _redact(prefix + str(chk))

    def phone_number():
        area = rng.choice(["212", "415", "312", "404", "646", "702", "512", "206"])
        return _redact(f"{area}5550{rng.randint(100, 199)}"[:10])

    def ipv4():
        return _redact(f"198.51.100.{rng.randint(1, 254)}")

    def us_ssn():
        raw = f"9{rng.randint(0,9)}{rng.randint(0,9)}{rng.randint(0,9)}{rng.randint(0,9)}{rng.randint(1000,9999)}"
        return _redact(raw)

    def github_pat():
        return _redact("ghp_" + "".join(rng.choice(_ALNUM) for _ in range(16)))

    def gitlab_pat():
        return _redact("glpat-" + "".join(rng.choice(_ALNUM) for _ in range(16)))

    def anthropic_api_key():
        return _redact("sk-ant-api03-" + "".join(rng.choice(_ALNUM) for _ in range(20)))

    def openai_api_key():
        return _redact("sk-proj-" + "".join(rng.choice(_ALNUM) for _ in range(20)))

    def google_api_key():
        return _redact("AIzaSy" + "".join(rng.choice(_ALNUM) for _ in range(28)))

    def stripe_api_key():
        return _redact("sk_test_" + "".join(rng.choice(_ALNUM) for _ in range(24)))

    def npm_token():
        return _redact("npm_" + "".join(rng.choice(_ALNUM) for _ in range(30)))

    def slack_webhook():
        return _redact("https://hooks.slack.com/services/T000000/B000000/" + "".join(rng.choice(_ALNUM) for _ in range(24)))

    def db_url_credentials():
        return _redact(f"postgres://demo_user:demo_pw_{rng.randint(1000,9999)}@db.internal:5432/app")

    def jwt():
        seg = lambda n: "".join(rng.choice(_ALNUM) for _ in range(n))
        return _redact(f"eyJ{seg(12)}.{seg(20)}.{seg(16)}")

    def email():
        local = rng.choice(["j.doe", "test.user", "info", "a.smith", "demo.account", "r.chen"])
        return _redact(f"{local}@example.com")

    def aws_access_key():
        return _redact("AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(16)))

    def bitcoin_address():
        return _redact("1" + "".join(rng.choice(_ALNUM) for _ in range(33)))

    def ethereum_address():
        return _redact("0x" + "".join(rng.choice(_HEXDIGITS) for _ in range(40)))

    def seed_phrase():
        # The canonical all-zero BIP39 test mnemonic — a well-known, public,
        # non-functional placeholder used throughout crypto test suites.
        return _redact("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

    def iban():
        return _redact("GB" + "".join(str(rng.randint(0, 9)) for _ in range(2)) + "NWBK" + "".join(str(rng.randint(0, 9)) for _ in range(14)))

    def us_bank_account():
        return _redact("".join(str(rng.randint(0, 9)) for _ in range(10)))

    def street_address():
        num = rng.randint(100, 9999)
        return _redact(f"{num} Fictional St Springfield")

    def date_of_birth():
        return _redact(f"19{rng.randint(60,99)}-0{rng.randint(1,9)}-1{rng.randint(0,9)}")

    def us_drivers_license():
        state = rng.choice(["NY", "CA", "TX", "WA", "MA"])
        return _redact(state + "".join(str(rng.randint(0, 9)) for _ in range(8)))

    def medical_record_mrn():
        return _redact("MRN" + "".join(str(rng.randint(0, 9)) for _ in range(7)))

    def diagnosis_code_icd10():
        return _redact(rng.choice(["Z00.00", "E11.9", "J45.909", "I10", "M54.5"]))

    def case_number():
        return _redact(f"{rng.randint(2020,2026)}-CV-{rng.randint(10000,99999)}")

    def employee_data():
        return _redact("Employee record: salary band " + rng.choice(["L4", "L5", "L6", "M2"]))

    def trade_secret():
        return _redact("internal roadmap doc v" + str(rng.randint(1, 9)))

    def customer_data():
        return _redact(f"customer_{rng.randint(1000,9999)} record")

    return {
        "credit_card": credit_card, "phone_number": phone_number, "ipv4": ipv4,
        "us_ssn": us_ssn, "github_pat": github_pat, "gitlab_pat": gitlab_pat,
        "anthropic_api_key": anthropic_api_key, "openai_api_key": openai_api_key,
        "google_api_key": google_api_key, "stripe_api_key": stripe_api_key,
        "npm_token": npm_token, "slack_webhook": slack_webhook,
        "db_url_credentials": db_url_credentials, "jwt": jwt, "email": email,
        "aws_access_key": aws_access_key, "bitcoin_address": bitcoin_address,
        "ethereum_address": ethereum_address, "seed_phrase": seed_phrase, "iban": iban,
        "us_bank_account": us_bank_account, "street_address": street_address,
        "date_of_birth": date_of_birth, "us_drivers_license": us_drivers_license,
        "medical_record_mrn": medical_record_mrn, "diagnosis_code_icd10": diagnosis_code_icd10,
        "case_number": case_number, "employee_data": employee_data,
        "trade_secret": trade_secret, "customer_data": customer_data,
    }


# (type, relative weight) — skewed toward Technical/secret types so the demo
# reads as authentic "dev leaked API keys to an AI" content, with enough
# spread across other families for a believable polyglot tail.
DEMO_TYPES = [
    ("github_pat", 9), ("gitlab_pat", 5), ("anthropic_api_key", 7), ("openai_api_key", 7),
    ("aws_access_key", 5), ("stripe_api_key", 4), ("google_api_key", 4), ("jwt", 6),
    ("slack_webhook", 3), ("db_url_credentials", 5), ("npm_token", 3),
    ("email", 10), ("us_ssn", 3), ("us_drivers_license", 2), ("date_of_birth", 2),
    ("ipv4", 6), ("phone_number", 5), ("street_address", 3),
    ("credit_card", 4), ("iban", 2), ("us_bank_account", 2),
    ("bitcoin_address", 3), ("ethereum_address", 3), ("seed_phrase", 1),
    ("medical_record_mrn", 2), ("diagnosis_code_icd10", 1),
    ("employee_data", 2), ("trade_secret", 1), ("customer_data", 2),
    ("case_number", 1),
]


def generate_demo_leaks(total_days):
    """~140 realistic, fully-fake detections spread across total_days, with
    two spike days and one guaranteed clean streak so every Wrapped scene
    has something worth screenshotting. Never touches real user data."""
    rng = random.Random(1337)
    value_fns = _demo_value_generators(rng)
    type_names = [t for t, _ in DEMO_TYPES]
    type_weights = [w for _, w in DEMO_TYPES]

    sessions = [f"demo{rng.getrandbits(48):012x}" for _ in range(5)]
    projects = ["/home/dev/acme-webapp", "/home/dev/side-project-x",
                "/home/dev/client-portal", "/home/dev/internal-tools"]
    session_project = {s: projects[i % len(projects)] for i, s in enumerate(sessions)}

    today = datetime.utcnow().date()

    spike_pool = list(range(2, max(3, total_days - 2)))
    spike_offsets = set(rng.sample(spike_pool, min(2, len(spike_pool)))) if spike_pool else set()

    clean_run_len = min(rng.randint(4, 9), max(2, total_days // 4))
    candidates = [
        o for o in range(0, max(1, total_days - clean_run_len))
        if not any(abs(o + k - s) <= 1 for k in range(clean_run_len) for s in spike_offsets)
    ]
    clean_start = rng.choice(candidates) if candidates else 0
    clean_offsets = set(range(clean_start, min(total_days, clean_start + clean_run_len)))

    day_weights = {}
    for offset in range(total_days):
        if offset in spike_offsets:
            day_weights[offset] = rng.randint(14, 24)
        elif offset in clean_offsets:
            day_weights[offset] = 0
        else:
            day_weights[offset] = rng.choices([0, 1, 2, 3, 4, 5, 6], weights=[10, 18, 20, 20, 15, 10, 7])[0]

    target_total = 140
    adjustable = [o for o in range(total_days) if o not in spike_offsets and o not in clean_offsets]
    guard = 0
    while adjustable and sum(day_weights.values()) < target_total - 4 and guard < 2000:
        day_weights[rng.choice(adjustable)] += 1
        guard += 1
    guard = 0
    while adjustable and sum(day_weights.values()) > target_total + 10 and guard < 2000:
        o = rng.choice(adjustable)
        if day_weights[o] > 0:
            day_weights[o] -= 1
        guard += 1

    records = []
    for offset, count in day_weights.items():
        day = today - timedelta(days=offset)
        for _ in range(count):
            hour, minute, second = rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59)
            ts = f"{day.isoformat()}T{hour:02d}:{minute:02d}:{second:02d}Z"
            type_name = rng.choices(type_names, weights=type_weights)[0]
            value = value_fns[type_name]()
            confidence = rng.choices(["high", "medium", "low"], weights=[70, 25, 5])[0]
            session_id = rng.choice(sessions)
            cwd = session_project.get(session_id, "")
            source = "transcript"
            roll = rng.random()
            if roll < 0.12:
                source = f"file:{cwd or '/home/dev/project'}/.env.local"
            elif roll < 0.16:
                source = f"file:{cwd or '/home/dev/project'}/config/secrets.yml"
            records.append({
                "type": type_name, "value": value, "confidence": confidence,
                "timestamp": ts, "session_id": session_id, "value_id": None,
                "source": source, "cwd": cwd,
            })
    rng.shuffle(records)
    return records


# ═════════════════════════════════════════════════════════════════════════
# CSS — dark, cinematic, "Wrapped" aesthetic with Carbon-style terminal
# chrome. Scroll-snapped, full-viewport, near-square scenes.
# ═════════════════════════════════════════════════════════════════════════

CSS_TEXT = """
:root {
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
  --font-sans: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;

  --bg: #0b0e12;
  --panel: #12161c;
  --panel-2: #171c24;
  --border: #232a35;
  --text: #e7ebf1;
  --text-dim: #8b94a6;
  --text-faint: #5a6273;

  --amber: #e8a33d;
  --cyan: #4fc1e9;
  --good: #3ddc84;
  --critical: #f0555a;
  --audit: #a99bd6;

  --accent: #e8a33d;
  --shadow: 0 24px 70px rgba(0,0,0,0.55);
  --radius: 20px;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; max-width: 100%; overflow-x: hidden; height: 100%; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-sans);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
.mono { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }

/* ── Scroll snap wrapper ─────────────────────────────── */
.wrapped-scroll {
  height: 100vh;
  height: 100dvh;
  overflow-y: auto;
  overflow-x: hidden;
  scroll-snap-type: y mandatory;
  scroll-behavior: smooth;
}
.wrapped-scroll::-webkit-scrollbar { width: 6px; }
.wrapped-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
@media (prefers-reduced-motion: reduce) {
  .wrapped-scroll { scroll-behavior: auto; }
}

/* ── Scenes ──────────────────────────────────────────── */
.scene {
  height: 100vh;
  height: 100dvh;
  scroll-snap-align: start;
  scroll-snap-stop: always;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  padding: 26px;
  background:
    radial-gradient(circle at 22% 18%, color-mix(in srgb, var(--accent) 20%, transparent) 0%, transparent 55%),
    radial-gradient(circle at 82% 85%, color-mix(in srgb, var(--accent) 12%, transparent) 0%, transparent 50%),
    var(--bg);
}

/* ── The screenshottable "card" ─────────────────────── */
.scene-card {
  width: min(560px, 92vw);
  aspect-ratio: 1 / 1;
  max-height: 88vh;
  margin: auto;
  display: flex;
  flex-direction: column;
  border-radius: var(--radius);
  background: linear-gradient(175deg, var(--panel) 0%, var(--panel-2) 100%);
  border: 1px solid var(--border);
  box-shadow: var(--shadow), 0 0 0 1px rgba(255,255,255,0.02) inset;
  overflow: hidden;
  position: relative;
}

.corner { position: absolute; width: 18px; height: 18px; pointer-events: none; opacity: 0.35; }
.corner-tl { top: 10px; left: 10px; border-top: 2px solid var(--accent); border-left: 2px solid var(--accent); border-top-left-radius: 6px; }
.corner-tr { top: 10px; right: 10px; border-top: 2px solid var(--accent); border-right: 2px solid var(--accent); border-top-right-radius: 6px; }
.corner-bl { bottom: 10px; left: 10px; border-bottom: 2px solid var(--accent); border-left: 2px solid var(--accent); border-bottom-left-radius: 6px; }
.corner-br { bottom: 10px; right: 10px; border-bottom: 2px solid var(--accent); border-right: 2px solid var(--accent); border-bottom-right-radius: 6px; }

.screenshot-hint {
  position: absolute; bottom: 44px; right: 16px;
  font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.4px;
  color: var(--text-faint); opacity: 0.6; pointer-events: none;
}

/* ── Terminal chrome ─────────────────────────────────── */
.term-titlebar {
  display: flex; align-items: center; gap: 10px;
  height: 34px; flex-shrink: 0; padding: 0 12px;
  background: rgba(255,255,255,0.03);
  border-bottom: 1px solid var(--border);
}
.term-dots { display: flex; gap: 6px; flex-shrink: 0; }
.dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.dot-r { background: #ff5f56; }
.dot-y { background: #ffbd2e; }
.dot-g { background: #27c93f; }
.term-title {
  flex: 1; min-width: 0; text-align: center; font-family: var(--font-mono); font-size: 11px;
  color: var(--text-faint); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  padding-right: 28px;
}

.term-body {
  flex: 1; min-height: 0; display: flex; flex-direction: column; align-items: center;
  justify-content: center; text-align: center; gap: 12px; padding: clamp(16px, 4vw, 32px);
  overflow-y: auto;
}

.card-footer {
  flex-shrink: 0; display: flex; align-items: center; justify-content: space-between;
  padding: 10px 16px; border-top: 1px solid var(--border); background: rgba(255,255,255,0.02);
}
.footer-brand { font-family: var(--font-mono); font-size: 10px; letter-spacing: 1px; color: var(--text-faint); }
.footer-scene { font-family: var(--font-mono); font-size: 10px; color: var(--text-faint); }

.demo-ribbon {
  position: fixed; top: 20px; right: -52px; width: 210px;
  background: var(--critical); color: #1a0505; font-weight: 700; font-size: 11px;
  letter-spacing: 1.5px; text-align: center; padding: 4px 0; transform: rotate(45deg);
  box-shadow: 0 2px 10px rgba(0,0,0,0.35); z-index: 70; pointer-events: none;
}

/* ── Typography ──────────────────────────────────────── */
.eyebrow {
  font-family: var(--font-mono); font-size: 11px; letter-spacing: 2.5px; text-transform: uppercase;
  color: var(--accent);
}
.wrapped-title { font-size: clamp(22px, 5.5vw, 32px); font-weight: 800; margin: 0; line-height: 1.15; }
.wrapped-sub { font-size: 14px; color: var(--text-dim); max-width: 40ch; margin: 0 auto; }
.wrapped-verdict { font-size: 15px; color: var(--text); font-style: italic; }
.wrapped-giant {
  font-family: var(--font-mono); font-weight: 800; font-size: clamp(56px, 15vw, 116px);
  line-height: 1; color: var(--text); letter-spacing: -2px;
  text-shadow: 0 0 40px color-mix(in srgb, var(--accent) 55%, transparent);
}
.wrapped-giant-emoji { font-size: clamp(64px, 18vw, 132px); line-height: 1; }
.grade-letter {
  font-family: var(--font-mono); font-weight: 800; font-size: clamp(64px, 17vw, 128px);
  line-height: 1;
}
.grade-letter.sev-good { color: var(--good); text-shadow: 0 0 40px rgba(61,220,132,0.45); }
.grade-letter.sev-mid { color: var(--amber); text-shadow: 0 0 40px rgba(232,163,61,0.45); }
.grade-letter.sev-bad { color: var(--critical); text-shadow: 0 0 40px rgba(240,85,90,0.45); }
.tag-pill {
  display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 0.6px; color: var(--text-dim);
  border: 1px solid var(--border); background: var(--panel-2); border-radius: 999px;
  padding: 5px 13px;
}
.tag-pill .fam-dot { width: 7px; height: 7px; }

/* ── Cover ───────────────────────────────────────────── */
.cover-bird { font-size: clamp(48px, 14vw, 84px); line-height: 1; }
.chevron-down {
  position: absolute; bottom: 50px; left: 50%; transform: translateX(-50%);
  font-size: 20px; color: var(--text-faint); animation: bob 1.8s ease-in-out infinite;
}
@keyframes bob { 0%,100% { transform: translate(-50%, 0); opacity: 0.5; } 50% { transform: translate(-50%, 6px); opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .chevron-down { animation: none; } }

/* ── Podium (top categories) ────────────────────────── */
.podium { display: flex; flex-direction: column; gap: 10px; width: 100%; max-width: 380px; }
.podium-row {
  display: flex; align-items: center; gap: 12px; text-align: left;
  background: var(--panel-2); border: 1px solid var(--border); border-radius: 12px;
  padding: 10px 14px;
}
.podium-rank { font-size: 20px; width: 28px; flex-shrink: 0; text-align: center; }
.podium-info { flex: 1; min-width: 0; }
.podium-label { font-size: 14px; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 7px; }
.podium-family { font-size: 10.5px; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.6px; margin-top: 2px; }
.podium-count { font-family: var(--font-mono); font-weight: 800; font-size: 20px; color: var(--text); flex-shrink: 0; }
.fam-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex-shrink: 0; }

/* ── Persona ─────────────────────────────────────────── */
.persona-emoji { font-size: clamp(64px, 18vw, 132px); line-height: 1; }
.scene.in-view .persona-emoji { animation: personaPop 0.7s cubic-bezier(.2,1.4,.4,1); }
@keyframes personaPop { 0% { transform: scale(0.4); opacity: 0; } 100% { transform: scale(1); opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .scene.in-view .persona-emoji { animation: none; } }

/* ── Closing / CTA ───────────────────────────────────── */
.cta-code {
  font-family: var(--font-mono); font-size: 13px; color: var(--good);
  background: #05070a; border: 1px solid var(--border); border-radius: 10px;
  padding: 12px 16px; max-width: 100%; overflow-x: auto; white-space: nowrap;
}
.cta-code .prompt { color: var(--text-faint); }
.closing-tagline { font-size: 16px; font-weight: 700; color: var(--text); }
.closing-link { font-size: 12px; color: var(--text-dim); }
.closing-link a { color: var(--cyan); text-decoration: none; }
.closing-link a:hover { text-decoration: underline; }

/* ── Nav rail ────────────────────────────────────────── */
.wrapped-nav {
  position: fixed; top: 50%; right: 16px; transform: translateY(-50%);
  display: flex; flex-direction: column; gap: 9px; z-index: 60;
}
.nav-dot {
  width: 8px; height: 8px; border-radius: 50%; background: var(--border);
  border: 1px solid var(--text-faint); display: block; text-indent: -9999px;
  transition: background 0.2s, transform 0.2s;
}
.nav-dot:hover { background: var(--text-dim); }
.nav-dot.active { background: var(--accent); border-color: var(--accent); transform: scale(1.3); }
@media (prefers-reduced-motion: reduce) { .nav-dot { transition: none; } }

@media (max-width: 480px) {
  .scene-card { aspect-ratio: auto; width: 94vw; max-height: none; }
  .scene { height: auto; min-height: 100vh; min-height: 100dvh; padding: 20px 12px; }
  .wrapped-nav { top: auto; bottom: 10px; right: 50%; transform: translateX(50%); flex-direction: row; }
  .wrapped-nav.mobile-hide { display: none; }
  .screenshot-hint { display: none; }
  .demo-ribbon { position: static; width: 100%; transform: none; border-radius: 0; padding: 5px 0; font-size: 10px; box-shadow: none; }
}
"""

# ═════════════════════════════════════════════════════════════════════════
# Client JS — count-up + in-view reveal + nav highlighting, all driven by
# one IntersectionObserver. Reads the JSON data island via textContent only
# and never writes HTML back with innerHTML.
# ═════════════════════════════════════════════════════════════════════════

MAIN_JS = """(function(){
'use strict';

var reduced = false;
try { reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) {}

// Native #fragment navigation does not reliably scroll a nested overflow
// container (the .wrapped-scroll wrapper, not <body>) into position across
// browsers, so deep links to a single scene are handled explicitly here.
// behavior:'instant' (not 'auto') is required: .wrapped-scroll declares
// scroll-behavior:smooth in CSS, and per spec a JS 'auto' scroll defers to
// that CSS property — turning this into an animated scroll that a fast
// screenshot (or a user's very next paint) would catch mid-flight at the
// wrong position.
try {
  if (location.hash) {
    var deepLinkTarget = document.getElementById(location.hash.slice(1));
    if (deepLinkTarget && deepLinkTarget.classList.contains('scene')) {
      deepLinkTarget.scrollIntoView({ behavior: 'instant', block: 'start' });
    }
  }
} catch (e) {}

function formatNum(n){
  var neg = n < 0;
  n = Math.round(Math.abs(n));
  var s = String(n);
  var out = '';
  for (var i = 0; i < s.length; i++) {
    if (i > 0 && (s.length - i) % 3 === 0) out += ',';
    out += s[i];
  }
  return (neg ? '-' : '') + out;
}

function animateCountUp(el){
  var target = parseFloat(el.getAttribute('data-target'));
  if (isNaN(target)) return;
  var finalText = el.textContent;
  if (reduced) return;
  var isInt = Math.abs(target - Math.round(target)) < 1e-9;
  var duration = 1100;
  var start = null;
  function step(ts){
    if (start === null) start = ts;
    var progress = Math.min(1, (ts - start) / duration);
    var eased = 1 - Math.pow(1 - progress, 3);
    var current = target * eased;
    el.textContent = isInt ? formatNum(current) : current.toFixed(1);
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      el.textContent = finalText;
    }
  }
  window.requestAnimationFrame(step);
}

var scenes = document.querySelectorAll('.scene');
var navDots = document.querySelectorAll('.nav-dot');

if ('IntersectionObserver' in window) {
  var io = new IntersectionObserver(function(entries){
    entries.forEach(function(entry){
      if (!entry.isIntersecting) return;
      var el = entry.target;
      el.classList.add('in-view');
      var id = el.getAttribute('id');
      navDots.forEach(function(d){
        var isActive = d.getAttribute('href') === '#' + id;
        d.classList.toggle('active', isActive);
      });
      if (!reduced) {
        var counters = el.querySelectorAll('.countup');
        for (var i = 0; i < counters.length; i++) {
          var c = counters[i];
          if (!c.getAttribute('data-animated')) {
            c.setAttribute('data-animated', '1');
            animateCountUp(c);
          }
        }
      }
    });
  }, { threshold: 0.5 });
  scenes.forEach(function(s){ io.observe(s); });
} else if (navDots.length) {
  navDots[0].classList.add('active');
}
})();"""


# ═════════════════════════════════════════════════════════════════════════
# Scene rendering
# ═════════════════════════════════════════════════════════════════════════


def wrap_scene(scene_id, idx, total_scenes, term_title, accent_hex, body_html):
    return f"""
<section id="{esc(scene_id)}" class="scene" style="--accent:{accent_hex}">
  <div class="scene-card">
    <div class="term-titlebar">
      <span class="term-dots"><span class="dot dot-r"></span><span class="dot dot-y"></span><span class="dot dot-g"></span></span>
      <span class="term-title mono">{esc(term_title)}</span>
    </div>
    <div class="term-body">
      {body_html}
    </div>
    <div class="card-footer">
      <span class="footer-brand">\U0001F424 CANARY WRAPPED</span>
      <span class="footer-scene mono">{idx} / {total_scenes}</span>
    </div>
    <span class="corner corner-tl" aria-hidden="true"></span>
    <span class="corner corner-tr" aria-hidden="true"></span>
    <span class="corner corner-bl" aria-hidden="true"></span>
    <span class="corner corner-br" aria-hidden="true"></span>
    <span class="screenshot-hint" aria-hidden="true">\U0001F4F8 screenshot this</span>
  </div>
</section>"""


def render_nav(scene_ids_labels):
    links = "".join(
        f'<a class="nav-dot" href="#{esc(sid)}" aria-label="{esc(label)}"></a>'
        for sid, label in scene_ids_labels
    )
    return f'<nav class="wrapped-nav" aria-label="Wrapped scenes">{links}</nav>'


def render_cover(ctx, idx, total_scenes):
    demo_note = " (demo data)" if ctx["demo"] else ""
    body = f"""
      <div class="cover-bird" aria-hidden="true">\U0001F424</div>
      <h1 class="wrapped-title">Canary Wrapped</h1>
      <span class="tag-pill">{esc(ctx['period_label'])}{esc(demo_note)}</span>
      <p class="wrapped-sub">Here's what you shared with Claude.</p>
      <div class="chevron-down" aria-hidden="true">↓</div>"""
    return wrap_scene("scene-cover", idx, total_scenes,
                       f"canary@wrapped:~$ ./wrapped.sh --period {ctx['period']}",
                       "#e8a33d", body)


def render_number(ctx, idx, total_scenes):
    sev = GRADE_SEV.get(ctx["grade"], "bad")
    verdict = GRADE_VERDICTS.get(ctx["grade"], GRADE_VERDICTS["F"])
    body = f"""
      <span class="eyebrow">The Number</span>
      <div class="wrapped-giant countup" data-target="{ctx['total']}">{esc(fmt_int(ctx['total']))}</div>
      <p class="wrapped-sub">exposures &middot; {esc(ctx['period_label'])}</p>
      <div class="grade-letter sev-{sev}">{esc(ctx['grade'])}</div>
      <p class="wrapped-verdict">{esc(verdict)}</p>
      <span class="tag-pill">{esc(fmt_score(ctx['score']))} risk points</span>"""
    accent = {"good": "#3ddc84", "mid": "#e8a33d", "bad": "#f0555a"}[sev]
    return wrap_scene("scene-number", idx, total_scenes,
                       f"canary@wrapped:~$ cat risk_score.txt  # grade {ctx['grade']}",
                       accent, body)


def render_categories(ctx, idx, total_scenes):
    top = ctx["top_categories"]
    if not top:
        body = """
      <span class="eyebrow">Top Categories</span>
      <h2 class="wrapped-title">Nothing to rank</h2>
      <p class="wrapped-sub">No categorized exposures this period.</p>"""
        return wrap_scene("scene-categories", idx, total_scenes,
                           "canary@wrapped:~$ sort leaks.jsonl | uniq -c", "#7d8593", body)

    medals = ["\U0001F947", "\U0001F948", "\U0001F949"]
    rows = []
    for i, cat in enumerate(top):
        medal = medals[i] if i < len(medals) else f"#{i+1}"
        color = get_family_accent(cat["family"])
        rows.append(f"""
        <div class="podium-row">
          <span class="podium-rank" aria-hidden="true">{medal}</span>
          <div class="podium-info">
            <div class="podium-label"><span class="fam-dot" style="background:{color}"></span>{esc(cat['label'])}</div>
            <div class="podium-family">{esc(cat['family'])}</div>
          </div>
          <span class="podium-count countup" data-target="{cat['count']}">{esc(fmt_int(cat['count']))}</span>
        </div>""")
    accent = get_family_accent(top[0]["family"])
    body = f"""
      <span class="eyebrow">Top Categories</span>
      <h2 class="wrapped-title">Where it came from</h2>
      <div class="podium">{''.join(rows)}</div>
      <p class="wrapped-sub">{esc(fmt_int(ctx['distinct_types']))} distinct types touched this period</p>"""
    return wrap_scene("scene-categories", idx, total_scenes,
                       "canary@wrapped:~$ sort leaks.jsonl | uniq -c | sort -rn", accent, body)


def render_spike(ctx, idx, total_scenes):
    spike = ctx["spike"]
    if not spike:
        body = """
      <span class="eyebrow">Biggest Spike</span>
      <h2 class="wrapped-title">No dated activity</h2>
      <p class="wrapped-sub">Nothing to spotlight for this period.</p>"""
        return wrap_scene("scene-spike", idx, total_scenes,
                           "canary@wrapped:~$ awk '{print $1}' leaks.jsonl | sort | uniq -c | sort -rn | head -1",
                           "#7d8593", body)
    body = f"""
      <span class="eyebrow">Biggest Spike</span>
      <div class="wrapped-giant countup" data-target="{spike['count']}">{esc(fmt_int(spike['count']))}</div>
      <p class="wrapped-sub">items leaked in a single day</p>
      <p class="wrapped-verdict">On {esc(fmt_date(spike['date']))}, that's what happened.</p>
      <span class="tag-pill"><span class="fam-dot" style="background:{get_family_accent(spike['family'])}"></span>mostly {esc(spike['label'])}</span>"""
    return wrap_scene("scene-spike", idx, total_scenes,
                       f"canary@wrapped:~$ grep {esc(spike['date'].isoformat())} leaks.jsonl | wc -l",
                       "#f0555a", body)


def render_streak(ctx, idx, total_scenes):
    streak = ctx["streak"]
    days = streak["days"]
    if days > 0 and streak["start"] and streak["end"]:
        sub = f"clean streak &middot; {esc(fmt_range(streak['start'], streak['end']))}"
        verdict = "Your best run."
    else:
        sub = "not a single clean day this period"
        verdict = "Every day had at least one leak."
    body = f"""
      <span class="eyebrow">Cleanest Streak</span>
      <div class="wrapped-giant countup" data-target="{days}">{esc(fmt_int(days))}</div>
      <p class="wrapped-sub">{sub}</p>
      <p class="wrapped-verdict">{esc(verdict)}</p>"""
    return wrap_scene("scene-streak", idx, total_scenes,
                       "canary@wrapped:~$ ./longest_zero_run.sh --period " + ctx["period"],
                       "#3ddc84", body)


def render_persona(ctx, idx, total_scenes):
    p = ctx["persona"]
    accent = ctx["persona_accent"]
    persona_emoji = p.get("emoji") or "\U0001F424"
    body = f"""
      <span class="eyebrow">Your Canary Persona</span>
      <div class="persona-emoji" aria-hidden="true">{esc(persona_emoji)}</div>
      <h2 class="wrapped-title">{esc(p.get('label','The Canary'))}</h2>
      <p class="wrapped-sub">{esc(p.get('blurb',''))}</p>"""
    return wrap_scene("scene-persona", idx, total_scenes,
                       "canary@wrapped:~$ ./whoami.sh --persona", accent, body)


def render_closing(ctx, idx, total_scenes):
    body = """
      <div class="cover-bird" aria-hidden="true">\U0001F424</div>
      <p class="closing-tagline">The number only goes up.</p>
      <div class="cta-code mono"><span class="prompt">$</span> /plugin marketplace add sonomoshq/Canary</div>
      <p class="closing-link">Real-time PII masking before data leaves your machine &rarr; <a href="https://sonomos.ai">sonomos.ai</a></p>"""
    return wrap_scene("scene-closing", idx, total_scenes,
                       "canary@wrapped:~$ ./install.sh", "#4fc1e9", body)


def render_clean_hero(ctx, idx, total_scenes):
    body = f"""
      <span class="eyebrow">The Number</span>
      <div class="wrapped-giant countup" data-target="0">0</div>
      <p class="wrapped-sub">exposures &middot; {esc(ctx['period_label'])}</p>
      <div class="grade-letter sev-good">A+</div>
      <p class="wrapped-verdict">A clean {esc(ctx['period_label'].lower())}. The canary never sang.</p>"""
    return wrap_scene("scene-clean", idx, total_scenes,
                       "canary@wrapped:~$ wc -l leaks.jsonl  # 0", "#3ddc84", body)


# ═════════════════════════════════════════════════════════════════════════
# Full document assembly
# ═════════════════════════════════════════════════════════════════════════


def build_data_island(ctx):
    payload = {
        "period": ctx["period"],
        "total": ctx["total"],
        "grade": ctx["grade"],
        "score": ctx["score"],
        "demo": ctx["demo"],
        "persona": ctx["persona"].get("label") if ctx["persona"] else None,
    }
    raw = json.dumps(payload, separators=(",", ":"))
    safe = raw.replace("</", "<\\/")
    return f'<script type="application/json" id="wrapped-data">{safe}</script>'


def generate_html(period, records_all, taxonomy, demo, now_utc, now_local):
    window_start, window_end = compute_window(period, records_all, now_utc)
    period_records = filter_by_period(records_all, period, window_start, window_end)

    total = len(period_records)
    score = compute_risk_score(taxonomy, period_records)
    grade = compute_grade(taxonomy, score)
    persona_ctx = compute_persona_context(period_records, taxonomy)
    persona = compute_persona(taxonomy, persona_ctx)
    persona_accent = get_persona_accent(persona, persona_ctx)
    top_categories = compute_top_categories(period_records, taxonomy, 3)
    spike = compute_biggest_spike(period_records, taxonomy)
    streak = compute_cleanest_streak(period_records, window_start, window_end)

    ctx = {
        "period": period,
        "period_label": PERIOD_LABELS.get(period, period),
        "window_start": window_start, "window_end": window_end,
        "total": total, "score": score, "grade": grade,
        "distinct_types": persona_ctx["distinct_types"],
        "top_categories": top_categories, "spike": spike, "streak": streak,
        "persona": persona, "persona_accent": persona_accent,
        "demo": demo,
    }

    scenes_html = []
    if total == 0:
        renderers = [render_cover, render_clean_hero, render_persona, render_closing]
        scene_meta = [("scene-cover", "Cover"), ("scene-clean", "The Number"),
                      ("scene-persona", "Persona"), ("scene-closing", "Get Canary")]
    else:
        renderers = [render_cover, render_number, render_categories, render_spike,
                     render_streak, render_persona, render_closing]
        scene_meta = [("scene-cover", "Cover"), ("scene-number", "The Number"),
                      ("scene-categories", "Top Categories"), ("scene-spike", "Biggest Spike"),
                      ("scene-streak", "Cleanest Streak"), ("scene-persona", "Persona"),
                      ("scene-closing", "Get Canary")]

    n = len(renderers)
    for i, fn in enumerate(renderers, start=1):
        scenes_html.append(fn(ctx, i, n))

    nav_html = render_nav(scene_meta)
    demo_ribbon = '<div class="demo-ribbon" aria-hidden="true">DEMO DATA</div>' if demo else ""
    data_island_html = build_data_island(ctx)

    generated_label = f"{fmt_date(now_local.date())} · {now_local.strftime('%H:%M')} (local)"

    parts = []
    parts.append("<!DOCTYPE html>\n")
    parts.append('<html lang="en">\n<head>\n')
    parts.append('<meta charset="utf-8">\n')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">\n')
    parts.append('<meta name="color-scheme" content="dark">\n')
    parts.append(f"<title>\U0001F424 Canary Wrapped — {esc(ctx['period_label'])}</title>\n")
    parts.append('<meta name="description" content="Here’s what you shared with Claude — generated locally, never uploaded.">\n')
    parts.append("<style>")
    parts.append(CSS_TEXT)
    parts.append("</style>\n")
    parts.append("</head>\n<body>\n")
    parts.append(demo_ribbon)
    parts.append('<div class="wrapped-scroll">\n')
    parts.append("".join(scenes_html))
    parts.append("\n</div>\n")
    parts.append(nav_html)
    parts.append("\n")
    parts.append(data_island_html)
    parts.append(f"\n<!-- Generated {esc(generated_label)} -->\n")
    parts.append("<script>")
    parts.append(MAIN_JS)
    parts.append("</script>\n")
    parts.append("</body>\n</html>\n")
    return "".join(parts)


# ═════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════


def _has_display():
    if not sys.platform.startswith("linux"):
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def build_argparser():
    p = argparse.ArgumentParser(
        prog="wrapped.py",
        description="Generate Canary Wrapped — a shareable, Spotify-Wrapped-style recap "
                     "of the sensitive data you've exposed to Claude.",
    )
    p.add_argument("--period", choices=PERIOD_CHOICES, default="30d",
                    help="Time window to summarize (default: 30d).")
    p.add_argument("--out", metavar="PATH", default=None,
                    help=f"Output HTML path (default: {DEFAULT_OUTPUT_FILE})")
    p.add_argument("--demo", action="store_true",
                    help="Ignore real data and render ~140 realistic fake detections.")
    p.add_argument("--no-open", action="store_true",
                    help="Do not open the result in a browser after generating it.")
    p.add_argument("--print-path-only", action="store_true",
                    help="Write the file, print its path, and never attempt to open it.")
    return p


def main():
    args = build_argparser().parse_args()

    out_path = args.out or DEFAULT_OUTPUT_FILE
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    taxonomy = load_taxonomy()
    now_utc = datetime.utcnow()
    now_local = datetime.now()

    if args.demo:
        total_days = PERIOD_DEMO_DAYS.get(args.period, 30)
        raw_records = generate_demo_leaks(total_days)
    else:
        raw_records = load_leaks_raw(LEAKS_FILE)

    records_all = [r for r in (normalize_record(x) for x in raw_records) if r]

    html_doc = generate_html(args.period, records_all, taxonomy, args.demo, now_utc, now_local)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    # Wrapped embeds aggregate counts derived from real detection data —
    # owner-only, like the rest of the data directory.
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass

    should_open = (not args.no_open) and (not args.print_path_only) and _has_display()
    if should_open:
        try:
            webbrowser.open("file://" + os.path.abspath(out_path))
        except Exception:
            pass

    print(out_path)


if __name__ == "__main__":
    main()
