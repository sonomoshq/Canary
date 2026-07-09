#!/usr/bin/env python3
# Copyright © 2026 Sonomos, Inc.
# All rights reserved.
#
# dashboard.py — Generates Canary's self-contained HTML PII exposure dashboard
# from ${CLAUDE_PLUGIN_DATA:-~/.sonomos}/leaks.jsonl.
#
# Hard constraints:
#   - Python 3 standard library ONLY. No third-party imports, ever.
#   - Output is a single self-contained HTML file with ZERO external network
#     requests: no @import, no CDN fonts/scripts, no remote images or fetches.
#     System font stacks only.
#   - Must never crash on malformed or legacy leaks.jsonl rows (missing
#     fields, wrong types, garbage JSON). Every field read is defensive.
#   - Every dynamic string that reaches the HTML is escaped with html.escape.
#     The embedded JSON data island additionally escapes "</" so it can
#     never break out of its <script> tag. Client-side JS builds the DOM via
#     createElement/textContent — never innerHTML — for anything derived
#     from stored data.
#
# Usage: python3 dashboard.py [--out PATH] [--no-open] [--demo] [--print-path-only]

import argparse
import calendar
import html
import json
import os
import random
import sys
import webbrowser
from collections import Counter
from datetime import date, datetime, timedelta

# ═════════════════════════════════════════════════════════════════════════
# Paths
# ═════════════════════════════════════════════════════════════════════════

SONOMOS_DIR = os.environ.get("CLAUDE_PLUGIN_DATA") or os.path.expanduser("~/.sonomos")
LEAKS_FILE = os.path.join(SONOMOS_DIR, "leaks.jsonl")
CONFIG_FILE = os.path.join(SONOMOS_DIR, "config.json")
DEFAULT_OUTPUT_FILE = os.path.join(SONOMOS_DIR, "dashboard.html")

# ═════════════════════════════════════════════════════════════════════════
# Constants
# ═════════════════════════════════════════════════════════════════════════

MONTH_ABBR = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
WEEKDAY_ABBR = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

VALID_DETECTORS = ("regex", "llm", "audit")
VALID_CONFIDENCE = ("high", "medium")

# Family display order (fixed — never reordered, it's the categorical key).
FAMILY_ORDER = [
    "Identity", "Financial", "Crypto", "Legal", "Medical",
    "Technical", "Network", "Organizational", "Other",
]

# categorize_type mapping — existing product mapping, extended per spec:
#   sendgrid_api_key: Financial -> Technical
#   nhs_number:       Identity  -> Medical
#   + new Technical types (gitlab_pat, slack_webhook, anthropic_api_key,
#     openai_api_key, google_api_key, npm_token, private_key_block,
#     db_url_credentials)
CATEGORY_MAP = {
    "Identity": [
        "name", "entity_name", "email", "us_ssn", "us_passport", "date_of_birth",
        "us_drivers_license", "national_id", "tin_non_us",
        "sin_canadian", "us_itin", "passport_non_us", "license_plate", "us_mbi",
    ],
    "Financial": [
        "credit_card", "iban", "aba_routing", "us_bank_account", "swift_bic",
        "stripe_api_key", "twilio_credentials",
        "us_ein_fein", "financial_records",
    ],
    "Crypto": [
        "bitcoin_address", "ethereum_address", "private_key", "seed_phrase",
        "wallet_key", "xpub_key", "monero_address", "ripple_address",
        "solana_address", "metamask_key", "exchange_api_key", "txid",
        "private_key_hex",
    ],
    "Legal": [
        "case_number", "attorney_number", "court_order", "litigation_id",
        "contract_number", "patent_number", "trademark", "legal_entity",
        "settlement_ref", "subpoena", "deposition", "evidence_id",
        "witness_id", "filing_number",
    ],
    "Medical": [
        "medical_record_mrn", "health_plan_id", "dea_number", "npi_number",
        "diagnosis_code_icd10", "procedure_code_cpt", "vin", "nhs_number",
    ],
    "Technical": [
        "jwt", "oauth_token", "gcp_key", "azure_key", "aws_access_key",
        "aws_secret_key", "generic_secret", "generic_api_key",
        "github_pat", "slack_token", "mac_address", "uuid", "imei",
        "serial_number", "android_id", "iphone_udid", "url_credentials",
        "sendgrid_api_key", "gitlab_pat", "slack_webhook", "anthropic_api_key",
        "openai_api_key", "google_api_key", "npm_token", "private_key_block",
        "db_url_credentials",
    ],
    "Network": [
        "ipv4", "ipv6", "geolocation", "street_address", "zip_code", "phone_number",
    ],
    "Organizational": [
        "customer_data", "employee_data", "third_party_data",
        "trade_secret", "internal_comms", "credentials_compound",
    ],
}
_TYPE_TO_FAMILY = {t: fam for fam, types in CATEGORY_MAP.items() for t in types}

# Words that should render fully uppercase in a human-readable type label.
_ACRONYMS = {
    "aws", "ssn", "iban", "jwt", "gcp", "vin", "mrn", "pat", "ip", "id",
    "aba", "ein", "fein", "itin", "dea", "npi", "nhs", "sin", "mbi", "bic",
    "swift", "imei", "udid", "mac", "uuid", "url", "api", "jwk", "otp",
    "us", "cvv", "npm", "db",
}
# Words with a specific mixed-case spelling.
_SPECIAL_WORDS = {
    "github": "GitHub", "gitlab": "GitLab", "oauth": "OAuth",
    "openai": "OpenAI", "metamask": "MetaMask",
}

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


def categorize_type(t):
    return _TYPE_TO_FAMILY.get(t, "Other")


def fmt_int(n):
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "0"


def fmt_date_short(d):
    return f"{MONTH_ABBR[d.month - 1]} {d.day}"


def fmt_month_year(d):
    return f"{MONTH_ABBR[d.month - 1]} {d.year}"


def sev_key(n):
    """Severity bucket at the mandated thresholds: 0 / 1-9 / 10+."""
    if n <= 0:
        return "good"
    if n < 10:
        return "mid"
    return "bad"


def risk_grade(total):
    if total <= 0:
        return ("A+", "good")
    if total <= 4:
        return ("A", "good")
    if total <= 9:
        return ("B", "mid")
    if total <= 24:
        return ("C", "mid")
    if total <= 99:
        return ("D", "bad")
    return ("F", "bad")


_GRADE_VERDICT = {
    "A+": "Clean. The canary sings.",
    "A": "Barely a chirp.",
    "B": "The canary's getting restless.",
    "C": "Feathers are flying.",
    "D": "The canary is not okay.",
    "F": "Feathers everywhere.",
}


def grade_verdict(letter):
    return _GRADE_VERDICT.get(letter, "Feathers everywhere.")


# ═════════════════════════════════════════════════════════════════════════
# Data loading — NEVER crash on malformed input
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
                # non-dict JSON (list/number/string/etc.) is silently skipped —
                # it is not a valid detection record.
    except OSError:
        return []
    return out


def load_config(path):
    default = {"llm_scan_enabled": True}
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            obj = json.loads(f.read())
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, OSError, ValueError):
        pass
    return default


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
        # Try a bare "YYYY-MM-DD..." prefix as a last resort.
        try:
            dt = datetime.fromisoformat(s[:19])
        except ValueError:
            return None
    if dt.tzinfo is not None:
        # Normalize to naive UTC for consistent arithmetic everywhere else.
        dt = (dt - dt.utcoffset()).replace(tzinfo=None)
    return dt


def normalize_record(raw):
    """Turn one arbitrary dict (possibly missing every field) into a safe,
    fully-defaulted record. Never raises."""
    if not isinstance(raw, dict):
        return None

    rec_type = _safe_str(raw.get("type")).strip() or "unknown"
    value = _safe_str(raw.get("value")).strip() or "••••"

    detector = raw.get("detector")
    detector = detector if detector in VALID_DETECTORS else "unknown"

    confidence = raw.get("confidence")
    confidence = confidence if confidence in VALID_CONFIDENCE else "unknown"

    ts_raw = raw.get("timestamp")
    dt_utc = _parse_timestamp(ts_raw) if isinstance(ts_raw, str) else None

    session_id = _safe_str(raw.get("session_id")).strip()

    value_id = raw.get("value_id")
    value_id = value_id.strip() if isinstance(value_id, str) and value_id.strip() else None

    source = _safe_str(raw.get("source")).strip()
    cwd = _safe_str(raw.get("cwd")).strip()

    family = categorize_type(rec_type)

    return {
        "type": rec_type,
        "type_label": human_type_label(rec_type),
        "family": family,
        "value": value,
        "detector": detector,
        "confidence": confidence,
        "dt_utc": dt_utc,          # datetime or None
        "session_id": session_id,  # "" if absent
        "value_id": value_id,      # None if absent
        "source": source,          # "" if absent
        "cwd": cwd,                # "" if absent
    }


def load_leaks():
    return [r for r in (normalize_record(x) for x in load_leaks_raw(LEAKS_FILE)) if r]


# ═════════════════════════════════════════════════════════════════════════
# Demo data generator — reserved / safe values ONLY
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
        raw = prefix + str(chk)
        return _redact(raw)

    def phone_number():
        area = rng.choice(["212", "415", "312", "404", "646", "702", "512"])
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

    def email():
        local = rng.choice(["j.doe", "test.user", "info", "a.smith", "demo.account", "r.chen"])
        return _redact(f"{local}@example.com")

    def aws_access_key():
        return _redact("AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(16)))

    def bitcoin_address():
        return _redact("1" + "".join(rng.choice(_ALNUM) for _ in range(33)))

    def ethereum_address():
        return _redact("0x" + "".join(rng.choice(_HEXDIGITS) for _ in range(40)))

    def iban():
        return _redact("GB" + "".join(str(rng.randint(0, 9)) for _ in range(2)) + "NWBK" + "".join(str(rng.randint(0, 9)) for _ in range(14)))

    def jwt():
        seg = lambda n: "".join(rng.choice(_ALNUM) for _ in range(n))
        return _redact(f"eyJ{seg(12)}.{seg(20)}.{seg(16)}")

    def street_address():
        num = rng.randint(100, 9999)
        return _redact(f"{num} Fictional St Springfield")

    def medical_record_mrn():
        return _redact("MRN" + "".join(str(rng.randint(0, 9)) for _ in range(7)))

    def case_number():
        return _redact(f"{rng.randint(2020,2026)}-CV-{rng.randint(10000,99999)}")

    def employee_data():
        return _redact("Employee record: salary band " + rng.choice(["L4", "L5", "L6", "M2"]))

    def us_drivers_license():
        state = rng.choice(["NY", "CA", "TX", "WA", "MA"])
        return _redact(state + "".join(str(rng.randint(0, 9)) for _ in range(8)))

    def slack_webhook():
        return _redact("https://hooks.slack.com/services/T000000/B000000/" + "".join(rng.choice(_ALNUM) for _ in range(24)))

    def db_url_credentials():
        return _redact(f"postgres://demo_user:demo_pw_{rng.randint(1000,9999)}@db.internal:5432/app")

    return {
        "credit_card": credit_card,
        "phone_number": phone_number,
        "ipv4": ipv4,
        "us_ssn": us_ssn,
        "github_pat": github_pat,
        "gitlab_pat": gitlab_pat,
        "anthropic_api_key": anthropic_api_key,
        "openai_api_key": openai_api_key,
        "email": email,
        "aws_access_key": aws_access_key,
        "bitcoin_address": bitcoin_address,
        "ethereum_address": ethereum_address,
        "iban": iban,
        "jwt": jwt,
        "street_address": street_address,
        "medical_record_mrn": medical_record_mrn,
        "case_number": case_number,
        "employee_data": employee_data,
        "us_drivers_license": us_drivers_license,
        "slack_webhook": slack_webhook,
        "db_url_credentials": db_url_credentials,
    }


# (type, typical_detector, typical_confidence)
_DEMO_TYPE_SPECS = [
    ("credit_card", "regex", "high"),
    ("phone_number", "regex", "medium"),
    ("ipv4", "regex", "medium"),
    ("us_ssn", "regex", "high"),
    ("github_pat", "regex", "high"),
    ("gitlab_pat", "regex", "high"),
    ("anthropic_api_key", "regex", "high"),
    ("openai_api_key", "regex", "high"),
    ("email", "regex", "high"),
    ("aws_access_key", "regex", "high"),
    ("bitcoin_address", "regex", "high"),
    ("ethereum_address", "regex", "high"),
    ("iban", "regex", "high"),
    ("jwt", "llm", "medium"),
    ("street_address", "llm", "high"),
    ("medical_record_mrn", "llm", "high"),
    ("case_number", "llm", "high"),
    ("employee_data", "llm", "high"),
    ("us_drivers_license", "llm", "medium"),
    ("slack_webhook", "regex", "high"),
    ("db_url_credentials", "llm", "high"),
]


def generate_demo_leaks():
    """~140 realistic, fully-fake detections across 40 days / 3 spikes /
    6 sessions / 21 types / both detectors. Never touches real user data."""
    rng = random.Random(1337)
    value_fns = _demo_value_generators(rng)

    sessions = [f"demo{rng.getrandbits(48):012x}" for _ in range(6)]
    projects = [
        "/home/dev/acme-webapp", "/home/dev/side-project-x",
        "/home/dev/client-portal", "/home/dev/internal-tools",
        "/home/dev/data-pipeline",
    ]
    session_project = {s: projects[i % len(projects)] for i, s in enumerate(sessions)}

    today = date.today()
    total_days = 40
    spike_days = set(rng.sample(range(3, total_days - 3), 3))

    day_weights = {}
    for offset in range(total_days):
        if offset in spike_days:
            day_weights[offset] = rng.randint(12, 18)
        else:
            day_weights[offset] = rng.choices([0, 1, 2, 3, 4, 5], weights=[14, 20, 24, 22, 13, 7])[0]

    # Nudge the total toward the ~140 target regardless of random variance.
    target_total = 140
    non_spike_offsets = [o for o in range(total_days) if o not in spike_days]
    guard = 0
    while sum(day_weights.values()) < target_total - 4 and guard < 1000:
        day_weights[rng.choice(non_spike_offsets)] += 1
        guard += 1
    guard = 0
    while sum(day_weights.values()) > target_total + 10 and guard < 1000:
        o = rng.choice(non_spike_offsets)
        if day_weights[o] > 0:
            day_weights[o] -= 1
        guard += 1

    records = []
    repeatable = []  # list of (value_id, type_name, value)

    for offset, count in day_weights.items():
        day = today - timedelta(days=offset)
        for _ in range(count):
            hour = rng.randint(0, 23)
            minute = rng.randint(0, 59)
            second = rng.randint(0, 59)
            ts = f"{day.isoformat()}T{hour:02d}:{minute:02d}:{second:02d}Z"

            session_id = rng.choices(sessions, weights=[3, 2, 2, 1, 1, 1])[0]
            cwd = session_project[session_id] if rng.random() < 0.9 else ""

            reuse = rng.random() < 0.20 and repeatable
            if reuse:
                value_id, type_name, value = rng.choice(repeatable)
            else:
                type_name, typical_det, typical_conf = rng.choice(_DEMO_TYPE_SPECS)
                value = value_fns[type_name]()
                has_id = rng.random() < 0.85
                value_id = f"{rng.getrandbits(48):012x}" if has_id else None
                if has_id and rng.random() < 0.35:
                    repeatable.append((value_id, type_name, value))

            if reuse:
                typical_det = next((d for t, d, c in _DEMO_TYPE_SPECS if t == type_name), "regex")
                typical_conf = next((c for t, d, c in _DEMO_TYPE_SPECS if t == type_name), "high")

            detector = typical_det
            if rng.random() < 0.12:
                detector = "llm" if typical_det == "regex" else "regex"
            confidence = typical_conf if rng.random() < 0.85 else ("medium" if typical_conf == "high" else "high")

            source = "transcript"
            r = rng.random()
            if r < 0.12:
                source = f"file:{cwd or '/home/dev/project'}/.env.local"
            elif r < 0.16:
                source = f"file:{cwd or '/home/dev/project'}/config/secrets.yml"

            records.append({
                "type": type_name,
                "value": value,
                "detector": detector,
                "confidence": confidence,
                "timestamp": ts,
                "session_id": session_id,
                "value_id": value_id,
                "source": source,
                "cwd": cwd,
            })

    # Sprinkle a handful of explicit "audit" detector rows so that code path
    # (and its table badge) is exercised in the demo.
    for _ in range(8):
        type_name, _, _ = rng.choice(_DEMO_TYPE_SPECS)
        offset = rng.randint(0, total_days - 1)
        day = today - timedelta(days=offset)
        ts = f"{day.isoformat()}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:00Z"
        session_id = rng.choice(sessions)
        records.append({
            "type": type_name,
            "value": value_fns[type_name](),
            "detector": "audit",
            "confidence": "high",
            "timestamp": ts,
            "session_id": session_id,
            "value_id": f"{rng.getrandbits(48):012x}",
            "source": "audit:pii-audit-agent",
            "cwd": session_project[session_id],
        })

    rng.shuffle(records)
    return records


# ═════════════════════════════════════════════════════════════════════════
# Aggregation
# ═════════════════════════════════════════════════════════════════════════


def _bucket_timeline(dated):
    """dated: list of (date, is_regex). Returns (buckets, granularity).
    Auto-buckets by day -> week -> k-month so bucket count never exceeds ~60,
    regardless of history span. Gap days are filled with zero."""
    if not dated:
        return [], "day"

    dates = [d for d, _ in dated]
    min_d, max_d = min(dates), max(dates)
    total_days = (max_d - min_d).days + 1

    if total_days <= 60:
        granularity = "day"
        starts = [min_d + timedelta(days=i) for i in range(total_days)]

        def key_fn(d):
            return d
    elif -(-total_days // 7) <= 60:  # ceil div
        granularity = "week"
        n_buckets = -(-total_days // 7)
        starts = [min_d + timedelta(days=7 * i) for i in range(n_buckets)]

        def key_fn(d):
            idx = (d - min_d).days // 7
            idx = max(0, min(idx, n_buckets - 1))
            return starts[idx]
    else:
        total_months = (max_d.year - min_d.year) * 12 + (max_d.month - min_d.month) + 1
        k = max(1, -(-total_months // 60))
        granularity = f"{k}mo"
        n_buckets = -(-total_months // k)
        starts = []
        for i in range(n_buckets):
            off = i * k
            y = min_d.year + (min_d.month - 1 + off) // 12
            m = (min_d.month - 1 + off) % 12 + 1
            starts.append(date(y, m, 1))

        def key_fn(d):
            months_off = (d.year - min_d.year) * 12 + (d.month - min_d.month)
            idx = months_off // k
            idx = max(0, min(idx, n_buckets - 1))
            return starts[idx]

    regex_by_bucket = Counter()
    other_by_bucket = Counter()
    for d, is_regex in dated:
        b = key_fn(d)
        if is_regex:
            regex_by_bucket[b] += 1
        else:
            other_by_bucket[b] += 1

    buckets = [
        {"start": b, "regex": regex_by_bucket.get(b, 0), "other": other_by_bucket.get(b, 0)}
        for b in starts
    ]
    return buckets, granularity


def _bucket_label(start, granularity):
    if granularity == "day":
        return fmt_date_short(start)
    if granularity == "week":
        return fmt_date_short(start)
    return fmt_month_year(start)


def _build_heatmap(daily_counts, today):
    """26 weeks (Monday-start) x 7 days, last-26-week grid ending this week."""
    current_monday = today - timedelta(days=today.weekday())
    start_monday = current_monday - timedelta(weeks=25)

    window_days = [start_monday + timedelta(days=i) for i in range(26 * 7)]
    nonzero = [daily_counts.get(d, 0) for d in window_days if daily_counts.get(d, 0) > 0 and d <= today]
    max_count = max(nonzero) if nonzero else 1

    def level_for(c):
        if c <= 0:
            return 0
        if max_count <= 1:
            return 4
        frac = c / max_count
        if frac <= 0.25:
            return 1
        if frac <= 0.5:
            return 2
        if frac <= 0.75:
            return 3
        return 4

    cols = []
    month_labels = []  # (col_index, label)
    last_month = None
    for col in range(26):
        col_dates = []
        for row in range(7):
            d = start_monday + timedelta(weeks=col, days=row)
            future = d > today
            count = 0 if future else daily_counts.get(d, 0)
            col_dates.append({
                "date": d,
                "count": count,
                "level": None if future else level_for(count),
                "future": future,
            })
            if row == 0:
                mkey = (d.year, d.month)
                if mkey != last_month:
                    month_labels.append((col, MONTH_ABBR[d.month - 1]))
                    last_month = mkey
        cols.append(col_dates)

    return {"cols": cols, "month_labels": month_labels, "max_count": max_count}


def _compute_achievements(records, total, distinct_types, generated_dt_local):
    has_night = False
    for r in records:
        if r["dt_utc"] is None:
            continue
        try:
            local_dt = r["dt_utc"].replace(tzinfo=None)
            # dt_utc stored naive-UTC; approximate "local" by converting
            # via the system timezone offset captured once per run.
            local_hour = (local_dt + _LOCAL_OFFSET).hour
        except Exception:
            continue
        if 0 <= local_hour < 5:
            has_night = True
            break

    seven_days_ago = generated_dt_local - timedelta(days=7)
    recent = False
    for r in records:
        if r["dt_utc"] is None:
            continue
        local_dt = r["dt_utc"] + _LOCAL_OFFSET
        if local_dt >= seven_days_ago.replace(tzinfo=None):
            recent = True
            break
    clean_week = not recent

    items = [
        {"key": "first_feather", "label": "First Feather", "icon": "\U0001FAB6",
         "desc": "First detection logged", "earned": total >= 1, "good": False},
        {"key": "double_digits", "label": "Double Digits", "icon": "\U0001F522",
         "desc": "10+ detections", "earned": total >= 10, "good": False},
        {"key": "century_club", "label": "Century Club", "icon": "\U0001F4AF",
         "desc": "100+ detections", "earned": total >= 100, "good": False},
        {"key": "polyglot", "label": "Polyglot", "icon": "\U0001F310",
         "desc": "10+ distinct PII types", "earned": distinct_types >= 10, "good": False},
        {"key": "night_shift", "label": "Night Shift", "icon": "\U0001F319",
         "desc": "Caught something in the small hours", "earned": has_night, "good": False},
        {"key": "clean_week", "label": "Clean Week", "icon": "✅",
         "desc": "No detections in the last 7 days", "earned": clean_week, "good": True},
    ]
    return items


_LOCAL_OFFSET = datetime.now().astimezone().utcoffset() or timedelta(0)


def build_aggregates(records, demo, now_local):
    total = len(records)
    high_conf = sum(1 for r in records if r["confidence"] == "high")
    type_counts = Counter(r["type"] for r in records)
    distinct_types = len(type_counts)
    sessions = set(r["session_id"] for r in records if r["session_id"])
    sessions_count = len(sessions)

    value_ids = [r["value_id"] for r in records if r["value_id"]]
    if value_ids:
        unique_values = len(set(value_ids))
    else:
        unique_values = len({(r["type"], r["value"]) for r in records})

    regex_count = sum(1 for r in records if r["detector"] == "regex")
    other_count = total - regex_count
    llm_count = sum(1 for r in records if r["detector"] == "llm")
    audit_count = sum(1 for r in records if r["detector"] == "audit")

    grade_letter, grade_sev = risk_grade(total)

    # type -> {regex, other} split, for category bars
    type_detector_split = {}
    for r in records:
        d = type_detector_split.setdefault(r["type"], {"regex": 0, "other": 0})
        if r["detector"] == "regex":
            d["regex"] += 1
        else:
            d["other"] += 1

    # family groupings
    family_totals = Counter(r["family"] for r in records)
    family_types = {}
    for t, c in type_counts.items():
        fam = categorize_type(t)
        family_types.setdefault(fam, []).append((t, c))
    for fam in family_types:
        family_types[fam].sort(key=lambda tc: -tc[1])

    # timeline
    dated = [(r["dt_utc"].date(), r["detector"] == "regex") for r in records if r["dt_utc"] is not None]
    timeline_buckets, timeline_granularity = _bucket_timeline(dated)

    # heatmap (last 26 weeks ending "today")
    daily_counts = Counter(d for d, _ in dated)
    heatmap = _build_heatmap(daily_counts, now_local.date())

    achievements = _compute_achievements(records, total, distinct_types, now_local)

    # sessions top-5 / projects top-5
    session_counter = Counter(r["session_id"] for r in records if r["session_id"])
    top_sessions = session_counter.most_common(5)
    project_counter = Counter(r["cwd"] for r in records if r["cwd"])
    top_projects = project_counter.most_common(5)

    # repeat counts by value_id
    vid_counter = Counter(r["value_id"] for r in records if r["value_id"])

    return {
        "total": total,
        "high_conf": high_conf,
        "distinct_types": distinct_types,
        "sessions_count": sessions_count,
        "unique_values": unique_values,
        "regex_count": regex_count,
        "other_count": other_count,
        "llm_count": llm_count,
        "audit_count": audit_count,
        "grade_letter": grade_letter,
        "grade_sev": grade_sev,
        "type_counts": type_counts,
        "type_detector_split": type_detector_split,
        "family_totals": family_totals,
        "family_types": family_types,
        "timeline_buckets": timeline_buckets,
        "timeline_granularity": timeline_granularity,
        "heatmap": heatmap,
        "achievements": achievements,
        "top_sessions": top_sessions,
        "top_projects": top_projects,
        "vid_counter": vid_counter,
        "records": records,
        "demo": demo,
        "now_local": now_local,
    }


# ═════════════════════════════════════════════════════════════════════════
# Rendering — HTML fragments (every dynamic value escaped)
# ═════════════════════════════════════════════════════════════════════════


def render_header(agg, generated_label):
    demo_ribbon = ""
    if agg["demo"]:
        demo_ribbon = '<div class="demo-ribbon" aria-hidden="true">DEMO DATA</div>'
    return f"""
<div class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <span class="brand-logo">\U0001F424 CANARY</span>
      <span class="brand-sub">PII Exposure Report</span>
    </div>
    <div class="topbar-right">
      <span class="generated-at">Generated {esc(generated_label)}</span>
      <button type="button" id="theme-toggle" class="theme-toggle" aria-label="Toggle theme">\U0001F319</button>
    </div>
  </div>
</div>
{demo_ribbon}"""


def render_llm_warning():
    return """
<div class="container">
  <div class="llm-warning">
    <strong>LLM scanning is disabled.</strong> Semantic categories &mdash; names, addresses,
    legal IDs, medical records, trade secrets, crypto keys, and more &mdash; are not being
    detected right now. Only regex-pattern PII is being caught.
    Enable it in <code>config.json</code> at your Sonomos data directory
    &rarr; <code>"llm_scan_enabled": true</code>.
  </div>
</div>"""


def render_ring_gauge(agg):
    total = agg["total"]
    regex_c = agg["regex_count"]
    other_c = agg["other_count"]
    r = 78
    circumference = 2 * 3.14159265358979 * r
    regex_share = (regex_c / total) if total else 0
    other_share = 1 - regex_share if total else 0
    amber_len = circumference * regex_share
    cyan_len = circumference * other_share

    digits = len(fmt_int(total))
    font_size = 46 if digits <= 3 else (40 if digits <= 5 else 32)

    return f"""
      <svg viewBox="0 0 200 200" class="ring-gauge" role="img" aria-label="{esc(fmt_int(total))} total PII exposures">
        <g transform="rotate(-90 100 100)">
          <circle class="ring-track" cx="100" cy="100" r="{r}" />
          <circle class="ring-amber" cx="100" cy="100" r="{r}"
            stroke-dasharray="{amber_len:.2f} {circumference - amber_len:.2f}" stroke-dashoffset="0" />
          <circle class="ring-cyan" cx="100" cy="100" r="{r}"
            stroke-dasharray="{cyan_len:.2f} {circumference - cyan_len:.2f}" stroke-dashoffset="{-amber_len:.2f}" />
        </g>
        <text x="100" y="94" text-anchor="middle" class="ring-total" font-size="{font_size}">{esc(fmt_int(total))}</text>
        <text x="100" y="118" text-anchor="middle" class="ring-total-label">exposures</text>
      </svg>
      <div class="ring-legend">
        <span class="legend-item"><span class="legend-dot legend-dot-amber"></span>regex &middot; {esc(fmt_int(regex_c))}</span>
        <span class="legend-item"><span class="legend-dot legend-dot-cyan"></span>LLM + audit &middot; {esc(fmt_int(other_c))}</span>
      </div>"""


def render_hero(agg):
    letter = agg["grade_letter"]
    sev = agg["grade_sev"]
    verdict = grade_verdict(letter)

    tiles = [
        ("High confidence", agg["high_conf"]),
        ("Distinct types", agg["distinct_types"]),
        ("Sessions", agg["sessions_count"]),
        ("Unique values", agg["unique_values"]),
    ]
    tiles_html = "".join(
        f"""<div class="stat-tile sev-{sev_key(v)}">
          <div class="stat-value">{esc(fmt_int(v))}</div>
          <div class="stat-label">{esc(label)}</div>
        </div>""" for label, v in tiles
    )

    return f"""
<div class="container">
  <div class="hero-row">
    <div class="card hero-ring">
      {render_ring_gauge(agg)}
    </div>
    <div class="card hero-grade sev-{sev}">
      <div class="grade-letter">{esc(letter)}</div>
      <div class="grade-verdict prose">{esc(verdict)}</div>
      <div class="grade-sub">{esc(fmt_int(agg['total']))} total &middot; risk grade</div>
    </div>
    <div class="hero-tiles">
      {tiles_html}
    </div>
  </div>
</div>"""


def render_chart_a(agg):
    buckets = agg["timeline_buckets"]
    granularity = agg["timeline_granularity"]
    n = len(buckets)
    if n == 0:
        return ""

    W, H = 1000, 340
    left_pad, right_pad = 16, 16
    top_pad, bottom_pad = 16, 34
    plot_w = W - left_pad - right_pad
    baseline_y = top_pad + (H - top_pad - bottom_pad) / 2.0
    half_h = (H - top_pad - bottom_pad) / 2.0
    max_val = max([1] + [b["regex"] for b in buckets] + [b["other"] for b in buckets])

    def x_at(i):
        return left_pad + (i * plot_w / (n - 1) if n > 1 else plot_w / 2.0)

    def y_amber(i):
        return baseline_y - (buckets[i]["regex"] / max_val) * half_h

    def y_cyan(i):
        return baseline_y + (buckets[i]["other"] / max_val) * half_h

    amber_top = " ".join(f"{x_at(i):.1f},{y_amber(i):.1f}" for i in range(n))
    cyan_bot = " ".join(f"{x_at(i):.1f},{y_cyan(i):.1f}" for i in range(n))
    amber_area = f"M{left_pad},{baseline_y:.1f} L{amber_top} L{x_at(n-1):.1f},{baseline_y:.1f} Z"
    cyan_area = f"M{left_pad},{baseline_y:.1f} L{cyan_bot} L{x_at(n-1):.1f},{baseline_y:.1f} Z"
    amber_line = "M" + amber_top.replace(" ", " L")
    cyan_line = "M" + cyan_bot.replace(" ", " L")

    gridlines = [f'<line x1="{left_pad}" y1="{baseline_y:.1f}" x2="{W-right_pad}" y2="{baseline_y:.1f}" class="chart-baseline" />']
    for frac in (0.25, 0.5, 0.75, 1.0):
        y_up = baseline_y - half_h * frac
        y_dn = baseline_y + half_h * frac
        gridlines.append(f'<line x1="{left_pad}" y1="{y_up:.1f}" x2="{W-right_pad}" y2="{y_up:.1f}" class="chart-grid" />')
        gridlines.append(f'<line x1="{left_pad}" y1="{y_dn:.1f}" x2="{W-right_pad}" y2="{y_dn:.1f}" class="chart-grid" />')

    tick_count = min(7, n)
    if n <= 1:
        tick_idx = [0]
    else:
        tick_idx = sorted(set(round(i * (n - 1) / (tick_count - 1)) for i in range(tick_count)))
    ticks = []
    for pos, i in enumerate(tick_idx):
        label = _bucket_label(buckets[i]["start"], granularity)
        if pos == 0 and i == 0:
            anchor = "start"
        elif pos == len(tick_idx) - 1 and i == n - 1:
            anchor = "end"
        else:
            anchor = "middle"
        ticks.append(f'<text x="{x_at(i):.1f}" y="{H-8}" text-anchor="{anchor}" class="chart-tick">{esc(label)}</text>')

    hover_w = plot_w / n if n else plot_w
    hover_rects = []
    for i in range(n):
        cx = x_at(i)
        label = _bucket_label(buckets[i]["start"], granularity)
        tip = f"{label}: {buckets[i]['regex']} regex, {buckets[i]['other']} llm/audit"
        hover_rects.append(
            f'<rect x="{cx-hover_w/2:.1f}" y="{top_pad}" width="{hover_w:.1f}" height="{H-top_pad-bottom_pad}" '
            f'class="chart-hover"><title>{esc(tip)}</title></rect>'
        )

    gran_label = {"day": "daily", "week": "weekly"}.get(granularity, f"{granularity[:-2]}-month" if granularity.endswith("mo") else granularity)

    return f"""
<div class="container">
  <div class="card">
    <div class="card-title-row">
      <div class="card-title">Exposure over time</div>
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-dot legend-dot-amber"></span>regex</span>
        <span class="legend-item"><span class="legend-dot legend-dot-cyan"></span>LLM + audit</span>
        <span class="legend-note">{esc(gran_label)} buckets</span>
      </div>
    </div>
    <svg viewBox="0 0 {W} {H}" class="chart-a" preserveAspectRatio="none" role="img" aria-label="Exposure over time, regex above baseline, LLM and audit mirrored below">
      {''.join(gridlines)}
      <path d="{amber_area}" class="area-amber" />
      <path d="{cyan_area}" class="area-cyan" />
      <path d="{amber_line}" class="line-amber" fill="none" />
      <path d="{cyan_line}" class="line-cyan" fill="none" />
      {''.join(ticks)}
      {''.join(hover_rects)}
    </svg>
  </div>
</div>"""


def render_chart_b(agg):
    hm = agg["heatmap"]
    cols = hm["cols"]
    month_labels = hm["month_labels"]

    month_cells = []
    label_by_col = dict(month_labels)
    for col in range(26):
        text = esc(label_by_col.get(col, ""))
        month_cells.append(f'<div class="heat-month" style="grid-column:{col+1}">{text}</div>')

    weekday_cells = []
    for row in range(7):
        label = WEEKDAY_ABBR[row][0] if row in (0, 2, 4) else ""
        weekday_cells.append(f'<div class="heat-wd">{esc(label)}</div>')

    grid_cells = []
    for col in range(26):
        for row in range(7):
            cell = cols[col][row]
            if cell["future"]:
                grid_cells.append(f'<div class="heat-cell heat-future" style="grid-column:{col+1};grid-row:{row+1}"></div>')
                continue
            title = f"{fmt_date_short(cell['date'])}: {cell['count']} detection{'s' if cell['count'] != 1 else ''}"
            grid_cells.append(
                f'<div class="heat-cell heat-l{cell["level"]}" style="grid-column:{col+1};grid-row:{row+1}" title="{esc(title)}"></div>'
            )

    # Sessions/projects stack under the heatmap so the left column roughly
    # matches the (much taller) category panel instead of leaving a void.
    return f"""
<div class="container two-col">
  <div class="col-stack">
    <div class="card heatmap-card">
      <div class="card-title">Leak activity</div>
      <div class="heatmap-wrap">
        <div class="heat-months">{''.join(month_cells)}</div>
        <div class="heat-body">
          <div class="heat-weekdays">{''.join(weekday_cells)}</div>
          <div class="heat-grid">{''.join(grid_cells)}</div>
        </div>
        <div class="heat-scale">
          <span>Less</span>
          <span class="heat-cell heat-l0 heat-swatch"></span>
          <span class="heat-cell heat-l1 heat-swatch"></span>
          <span class="heat-cell heat-l2 heat-swatch"></span>
          <span class="heat-cell heat-l3 heat-swatch"></span>
          <span class="heat-cell heat-l4 heat-swatch"></span>
          <span>More</span>
        </div>
      </div>
    </div>
    {render_sessions_projects(agg)}
  </div>
  {render_category_panel(agg, embedded=True)}
</div>"""


def render_category_panel(agg, embedded=False):
    family_totals = agg["family_totals"]
    family_types = agg["family_types"]
    type_detector_split = agg["type_detector_split"]
    max_type_count = max(agg["type_counts"].values()) if agg["type_counts"] else 1

    sections = []
    for fam in FAMILY_ORDER:
        if family_totals.get(fam, 0) <= 0:
            continue
        fam_slug = fam.lower()
        rows = []
        for t, c in family_types.get(fam, []):
            split = type_detector_split.get(t, {"regex": 0, "other": 0})
            regex_pct = (split["regex"] / c * 100) if c else 0
            other_pct = 100 - regex_pct
            bar_w = (c / max_type_count * 100) if max_type_count else 0
            rows.append(f"""
              <div class="cat-row">
                <div class="cat-row-top">
                  <span class="pill pill-type"><span class="pill-dot fam-{fam_slug}"></span>{esc(human_type_label(t))}</span>
                  <span class="cat-row-count">{esc(fmt_int(c))}</span>
                </div>
                <div class="cat-row-bar" style="width:{bar_w:.1f}%">
                  <span class="cat-row-bar-regex" style="width:{regex_pct:.1f}%"></span>
                  <span class="cat-row-bar-other" style="width:{other_pct:.1f}%"></span>
                </div>
              </div>""")
        sections.append(f"""
          <div class="fam-section">
            <div class="fam-header"><span class="fam-dot fam-{fam_slug}"></span>{esc(fam)}<span class="fam-count">{esc(fmt_int(family_totals[fam]))}</span></div>
            {''.join(rows)}
          </div>""")

    inner = f"""
    <div class="card-title">Detections by category</div>
    <div class="cat-panel">{''.join(sections)}</div>"""

    if embedded:
        return f'<div class="card cat-card">{inner}</div>'
    return f'<div class="container"><div class="card cat-card">{inner}</div></div>'


def render_achievements(agg):
    items = []
    for a in agg["achievements"]:
        cls = "earned" if a["earned"] else "unearned"
        if a["earned"] and a["good"]:
            cls += " good"
        items.append(f"""
          <div class="achv {cls}" title="{esc(a['desc'])}">
            <span class="achv-icon">{a['icon']}</span>
            <span class="achv-label">{esc(a['label'])}</span>
          </div>""")
    return f"""
<div class="container">
  <div class="card">
    <div class="card-title">Achievements</div>
    <div class="achv-strip">{''.join(items)}</div>
  </div>
</div>"""


def render_sessions_projects(agg):
    top_sessions = agg["top_sessions"]
    top_projects = agg["top_projects"]
    if not top_sessions and not top_projects:
        return ""

    def bar_rows(items, label_fn, max_c):
        rows = []
        for key, c in items:
            pct = (c / max_c * 100) if max_c else 0
            rows.append(f"""
              <div class="mini-row">
                <span class="mini-label mono">{esc(label_fn(key))}</span>
                <span class="mini-bar-track"><span class="mini-bar" style="width:{pct:.1f}%"></span></span>
                <span class="mini-count">{esc(fmt_int(c))}</span>
              </div>""")
        return "".join(rows)

    panels = []
    if top_sessions:
        max_c = top_sessions[0][1]
        panels.append(f"""
          <div class="card">
            <div class="card-title">Top sessions</div>
            {bar_rows(top_sessions, lambda s: s[:8], max_c)}
          </div>""")
    if top_projects:
        max_c = top_projects[0][1]
        panels.append(f"""
          <div class="card">
            <div class="card-title">Top projects</div>
            {bar_rows(top_projects, lambda p: os.path.basename(p.rstrip('/')) or p, max_c)}
          </div>""")

    return "".join(panels)


def render_table_section(agg):
    return """
<div class="container">
  <div class="card table-card">
    <div class="card-title-row">
      <div class="card-title">All detections</div>
    </div>
    <div class="table-controls">
      <input type="search" id="cnry-search" class="search-input" placeholder="Search type, value, source&hellip;" aria-label="Search detections">
      <div id="cnry-chips" class="chip-groups"></div>
    </div>
    <div class="table-scroll">
      <table id="cnry-table" class="cnry-table">
        <thead>
          <tr>
            <th data-sort="time">Time</th>
            <th data-sort="type">Type</th>
            <th>Value</th>
            <th>Detector</th>
            <th data-sort="confidence">Confidence</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody id="cnry-tbody"></tbody>
      </table>
    </div>
    <div class="table-footer">
      <span id="cnry-range" class="table-range"></span>
      <div id="cnry-pager" class="table-pager"></div>
    </div>
  </div>
</div>"""


def render_empty_state():
    checklist = [
        "Credit cards, bank accounts &amp; routing numbers",
        "SSNs, passports &amp; government IDs",
        "API keys, tokens &amp; private keys",
        "Crypto wallets &amp; seed phrases",
        "Names, emails, phones &amp; addresses",
        "Medical records &amp; legal identifiers",
    ]
    items = "".join(f'<li>{c}</li>' for c in checklist)
    return f"""
<div class="container">
  <div class="empty-state">
    <div class="empty-bird">\U0001F424</div>
    <div class="empty-headline">All clear &mdash; nothing leaked yet.</div>
    <div class="empty-subline prose">Canary is watching: 30+ regex detectors + Claude self-scan on every message.</div>
    <ul class="empty-checklist prose">{items}</ul>
    <div class="empty-cta prose">Try <code>/canary:scan</code> for a deep audit &mdash; or run with <code>--demo</code> to see this dashboard lit up.</div>
  </div>
</div>"""


def render_footer():
    return """
<div class="footer">
  <div class="footer-line">\U0001F424 CANARY &mdash; local-only &middot; zero network requests &middot; MIT</div>
  <div class="footer-line footer-dim prose">by <a href="https://sonomos.ai">Sonomos</a> &mdash; real-time PII masking before data leaves your machine &rarr; <a href="https://sonomos.ai">sonomos.ai</a></div>
</div>"""


# ═════════════════════════════════════════════════════════════════════════
# Data island (client-side table state)
# ═════════════════════════════════════════════════════════════════════════


class _Interner:
    __slots__ = ("map", "list")

    def __init__(self):
        self.map = {}
        self.list = []

    def intern(self, s):
        idx = self.map.get(s)
        if idx is None:
            idx = len(self.list)
            self.map[s] = idx
            self.list.append(s)
        return idx


def _source_display_len_guard(s):
    # Defensive cap so a pathological single value can't blow up payload size.
    return s if len(s) <= 300 else s[:300]


def _utc_epoch_minutes(dt):
    """dt is naive but semantically UTC (see _parse_timestamp). Plain
    datetime.timestamp() on a naive value assumes the *system* local
    timezone, which would silently corrupt every displayed time on any
    machine not running in UTC. calendar.timegm() reads the fields as UTC
    directly, independent of the host's timezone."""
    return calendar.timegm(dt.timetuple()) // 60


def build_table_payload(agg):
    records = agg["records"]
    vid_counter = agg["vid_counter"]

    types_i = _Interner()
    type_labels = []
    type_families = []
    values_i = _Interner()
    sources_i = _Interner()

    det_table = ["regex", "llm", "audit", "unknown"]
    det_index = {d: i for i, d in enumerate(det_table)}
    conf_table = ["high", "medium", "unknown"]
    conf_index = {c: i for i, c in enumerate(conf_table)}

    valid_ts = [r["dt_utc"] for r in records if r["dt_utc"] is not None]
    if valid_ts:
        base_min = _utc_epoch_minutes(min(valid_ts))
    else:
        base_min = 0

    rows = []
    # newest-first by default; client can re-sort, but ship it pre-sorted.
    def sort_key(r):
        return r["dt_utc"] or datetime.min

    for r in sorted(records, key=sort_key, reverse=True):
        t_idx = types_i.intern(r["type"])
        if t_idx == len(type_labels):
            type_labels.append(r["type_label"])
            type_families.append(r["family"])
        v_idx = values_i.intern(_source_display_len_guard(r["value"]))
        s_idx = sources_i.intern(_source_display_len_guard(r["source"]))
        d_idx = det_index.get(r["detector"], det_index["unknown"])
        c_idx = conf_index.get(r["confidence"], conf_index["unknown"])
        rep = vid_counter.get(r["value_id"], 1) if r["value_id"] else 1

        if r["dt_utc"] is not None:
            delta = _utc_epoch_minutes(r["dt_utc"]) - base_min
        else:
            delta = None

        rows.append([delta, t_idx, v_idx, d_idx, c_idx, s_idx, rep])

    return {
        "types": types_i.list,
        "typeLabels": type_labels,
        "typeFamilies": type_families,
        "values": values_i.list,
        "sources": sources_i.list,
        "det": det_table,
        "conf": conf_table,
        "baseMin": base_min,
        "rows": rows,
    }


def render_data_island(agg):
    payload = build_table_payload(agg)
    raw = json.dumps(payload, separators=(",", ":"))
    safe = raw.replace("</", "<\\/")
    return f'<script type="application/json" id="canary-data">{safe}</script>'


# ═════════════════════════════════════════════════════════════════════════
# CSS
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
  --amber-ink: #e8a33d;
  --amber-glow: rgba(232,163,61,0.45);
  --cyan: #4fc1e9;
  --cyan-ink: #4fc1e9;
  --cyan-glow: rgba(79,193,233,0.45);
  --good: #3ddc84;
  --good-ink: #3ddc84;
  --critical: #f0555a;
  --critical-ink: #f6787c;
  --audit: #a99bd6;

  --fam-identity: #0086b7;
  --fam-financial: #006fbc;
  --fam-crypto: #506ed8;
  --fam-legal: #9573f5;
  --fam-medical: #997de0;
  --fam-technical: #935697;
  --fam-network: #c96195;
  --fam-organizational: #af5070;
  --fam-other: #7d8593;

  --heat-0: #161b22;
  --heat-1: #4a3315;
  --heat-2: #7a5518;
  --heat-3: #b17f1a;
  --heat-4: #e8a33d;

  --shadow: 0 4px 24px rgba(0,0,0,0.45);
  --radius: 10px;
}

:root[data-theme="light"] {
  --bg: #f5f3ec;
  --panel: #ffffff;
  --panel-2: #fbf9f4;
  --border: #e5e1d5;
  --text: #1b1c1e;
  --text-dim: #5b5d63;
  --text-faint: #85878d;

  --amber: #e8a33d;
  --amber-ink: #9a6a12;
  --amber-glow: rgba(154,106,18,0.30);
  --cyan: #4fc1e9;
  --cyan-ink: #0e6f90;
  --cyan-glow: rgba(14,111,144,0.28);
  --good: #3ddc84;
  --good-ink: #18854a;
  --critical: #f0555a;
  --critical-ink: #c23434;
  --audit: #6f368b;

  --fam-identity: #0087bb;
  --fam-financial: #0081c6;
  --fam-crypto: #004daa;
  --fam-legal: #2e58cd;
  --fam-medical: #776ae6;
  --fam-technical: #6f368b;
  --fam-network: #a04f98;
  --fam-organizational: #974a7f;
  --fam-other: #6b7280;

  --heat-0: #ebe7dc;
  --heat-1: #f0dbab;
  --heat-2: #e8c073;
  --heat-3: #d9a13f;
  --heat-4: #b5790f;

  --shadow: 0 2px 16px rgba(20,20,20,0.08);
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; max-width: 100%; overflow-x: hidden; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
.prose { font-family: var(--font-sans); }
code { font-family: var(--font-mono); background: var(--panel-2); padding: 2px 6px; border-radius: 4px; font-size: 0.92em; }
.mono { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
a { color: var(--cyan-ink); }

.container { max-width: 1240px; margin: 0 auto; padding: 0 24px; }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
.col-stack { display: flex; flex-direction: column; gap: 16px; min-width: 0; }

.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 22px;
  margin-bottom: 16px;
  box-shadow: var(--shadow);
}
.card-title {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1.4px;
  color: var(--text-dim);
  font-weight: 600;
  margin-bottom: 14px;
}
.card-title-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }
.card-title-row .card-title { margin-bottom: 8px; }

/* ── Topbar ─────────────────────────────────────────── */
.topbar { border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--bg); z-index: 50; }
.topbar-inner { max-width: 1240px; margin: 0 auto; padding: 18px 24px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 16px; }
.brand { display: flex; flex-direction: column; gap: 2px; }
.brand-logo { font-size: 19px; font-weight: 700; letter-spacing: 1px; }
.brand-sub { font-size: 11px; color: var(--text-dim); letter-spacing: 0.5px; }
.topbar-right { display: flex; align-items: center; gap: 14px; }
.generated-at { font-size: 11px; color: var(--text-faint); }
.theme-toggle {
  background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; width: 32px; height: 32px; cursor: pointer; font-size: 14px;
  display: flex; align-items: center; justify-content: center;
}
.theme-toggle:hover { border-color: var(--text-dim); }

.demo-ribbon {
  position: fixed; top: 22px; right: -54px; width: 220px;
  background: var(--critical); color: #1a0505; font-weight: 700; font-size: 12px;
  letter-spacing: 1.5px; text-align: center; padding: 5px 0; transform: rotate(45deg);
  box-shadow: 0 2px 10px rgba(0,0,0,0.35); z-index: 60; pointer-events: none;
}

/* ── LLM warning ────────────────────────────────────── */
.llm-warning {
  background: var(--panel-2); border: 1px solid var(--amber); border-left: 4px solid var(--amber);
  border-radius: var(--radius); padding: 14px 18px; margin: 18px 0; font-size: 13px;
  color: var(--text-dim); line-height: 1.7;
}
.llm-warning strong { color: var(--amber-ink); }

/* ── Hero ───────────────────────────────────────────── */
.hero-row { display: grid; grid-template-columns: 280px 240px 1fr; gap: 16px; margin-top: 22px; align-items: stretch; }
.hero-ring { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
.ring-gauge { width: 100%; max-width: 200px; height: auto; }
.ring-track { fill: none; stroke: var(--border); stroke-width: 16; }
.ring-amber { fill: none; stroke: var(--amber); stroke-width: 16; filter: drop-shadow(0 0 5px var(--amber-glow)); }
.ring-cyan { fill: none; stroke: var(--cyan); stroke-width: 16; filter: drop-shadow(0 0 5px var(--cyan-glow)); }
.ring-total { fill: var(--text); font-family: var(--font-mono); font-weight: 700; }
.ring-total-label { fill: var(--text-faint); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
.ring-legend { display: flex; gap: 14px; margin-top: 10px; flex-wrap: wrap; justify-content: center; }

.legend-item { font-size: 12px; color: var(--text-dim); display: inline-flex; align-items: center; gap: 6px; }
.legend-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.legend-dot-amber { background: var(--amber); box-shadow: 0 0 6px var(--amber-glow); }
.legend-dot-cyan { background: var(--cyan); box-shadow: 0 0 6px var(--cyan-glow); }
.legend-note { font-size: 11px; color: var(--text-faint); }
.chart-legend { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }

.hero-grade { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; gap: 6px; }
.grade-letter { font-size: 56px; font-weight: 700; line-height: 1; }
.hero-grade.sev-good .grade-letter { color: var(--good-ink); }
.hero-grade.sev-mid .grade-letter { color: var(--amber-ink); }
.hero-grade.sev-bad .grade-letter { color: var(--critical-ink); }
.grade-verdict { font-size: 13px; color: var(--text-dim); }
.grade-sub { font-size: 11px; color: var(--text-faint); }

.hero-tiles { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.stat-tile { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 18px; box-shadow: var(--shadow); }
.stat-value { font-size: 26px; font-weight: 700; }
.stat-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
.stat-tile.sev-good .stat-value { color: var(--good-ink); }
.stat-tile.sev-mid .stat-value { color: var(--amber-ink); }
.stat-tile.sev-bad .stat-value { color: var(--critical-ink); }

/* ── Charts ─────────────────────────────────────────── */
.chart-a { width: 100%; height: auto; display: block; }
.area-amber { fill: var(--amber); opacity: 0.22; }
.area-cyan { fill: var(--cyan); opacity: 0.22; }
.line-amber { stroke: var(--amber); stroke-width: 2; filter: drop-shadow(0 0 3px var(--amber-glow)); }
.line-cyan { stroke: var(--cyan); stroke-width: 2; filter: drop-shadow(0 0 3px var(--cyan-glow)); }
.chart-grid { stroke: var(--border); stroke-width: 1; }
.chart-baseline { stroke: var(--text-faint); stroke-width: 1; }
.chart-tick { fill: var(--text-faint); font-size: 11px; font-family: var(--font-mono); }
.chart-hover { fill: transparent; }
.chart-hover:hover { fill: rgba(128,128,128,0.06); }

.heatmap-card { min-width: 0; }
.heatmap-wrap { overflow-x: auto; }
.heat-months { display: grid; grid-template-columns: repeat(26, 15px); gap: 3px; margin-left: 26px; margin-bottom: 3px; min-width: 468px; }
.heat-month { font-size: 10px; color: var(--text-faint); }
.heat-body { display: flex; gap: 6px; min-width: 468px; }
.heat-weekdays { display: grid; grid-template-rows: repeat(7, 15px); gap: 3px; width: 18px; }
.heat-wd { font-size: 9px; color: var(--text-faint); display: flex; align-items: center; }
.heat-grid { display: grid; grid-template-columns: repeat(26, 15px); grid-template-rows: repeat(7, 15px); gap: 3px; }
.heat-cell { width: 15px; height: 15px; border-radius: 3px; background: var(--heat-0); }
.heat-cell.heat-l0 { background: var(--heat-0); }
.heat-cell.heat-l1 { background: var(--heat-1); }
.heat-cell.heat-l2 { background: var(--heat-2); }
.heat-cell.heat-l3 { background: var(--heat-3); }
.heat-cell.heat-l4 { background: var(--heat-4); box-shadow: 0 0 4px var(--amber-glow); }
.heat-future { background: transparent; }
.heat-scale { display: flex; align-items: center; gap: 4px; margin-top: 10px; font-size: 10px; color: var(--text-faint); }
.heat-swatch { width: 11px; height: 11px; }

/* ── Category panel ─────────────────────────────────── */
.cat-card { min-width: 0; }
.fam-section { margin-bottom: 16px; }
.fam-section:last-child { margin-bottom: 0; }
.fam-header {
  font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-dim);
  display: flex; align-items: center; gap: 8px; padding-bottom: 6px; margin-bottom: 8px;
  border-bottom: 1px solid var(--border); font-weight: 600;
}
.fam-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.fam-count { margin-left: auto; font-family: var(--font-mono); color: var(--text-faint); }
.cat-row { margin: 9px 0; }
.cat-row-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px; }
.cat-row-count { font-family: var(--font-mono); font-variant-numeric: tabular-nums; color: var(--text-dim); font-size: 12px; }
.cat-row-bar { height: 5px; border-radius: 3px; overflow: hidden; display: flex; background: var(--panel-2); min-width: 6px; }
.cat-row-bar-regex { background: var(--amber); height: 100%; }
.cat-row-bar-other { background: var(--cyan); height: 100%; }

.pill {
  display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text);
  padding: 3px 9px 3px 6px; border-radius: 999px; border: 1px solid var(--border); background: var(--panel-2);
}
.pill-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.fam-identity { background: var(--fam-identity); }
.fam-financial { background: var(--fam-financial); }
.fam-crypto { background: var(--fam-crypto); }
.fam-legal { background: var(--fam-legal); }
.fam-medical { background: var(--fam-medical); }
.fam-technical { background: var(--fam-technical); }
.fam-network { background: var(--fam-network); }
.fam-organizational { background: var(--fam-organizational); }
.fam-other { background: var(--fam-other); }

/* ── Achievements ───────────────────────────────────── */
.achv-strip { display: flex; flex-wrap: wrap; gap: 10px; }
.achv {
  display: flex; align-items: center; gap: 8px; border: 1px solid var(--border); border-radius: 999px;
  padding: 7px 14px 7px 10px; font-size: 12px; color: var(--text-dim); background: var(--panel-2);
}
.achv-icon { font-size: 15px; filter: grayscale(0.5); opacity: 0.6; }
.achv.earned { border-color: var(--text-dim); color: var(--text); }
.achv.earned .achv-icon { filter: none; opacity: 1; }
.achv.unearned { opacity: 0.55; }
.achv.earned.good { border-color: var(--good); color: var(--good-ink); box-shadow: 0 0 8px var(--amber-glow); }
.achv.earned.good { box-shadow: none; border-color: var(--good); }

/* ── Table ──────────────────────────────────────────── */
.table-card { min-width: 0; }
.table-controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
.search-input {
  background: var(--panel-2); border: 1px solid var(--border); color: var(--text); border-radius: 8px;
  padding: 8px 12px; font-family: var(--font-mono); font-size: 13px; min-width: 220px; flex: 1 1 220px;
}
.search-input:focus { outline: none; border-color: var(--cyan); }
.chip-groups { display: flex; gap: 14px; flex-wrap: wrap; }
.chip-group { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }
.chip-group-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-faint); margin-right: 2px; }
.chip {
  background: var(--panel-2); border: 1px solid var(--border); color: var(--text-dim); border-radius: 999px;
  padding: 4px 11px; font-size: 11px; cursor: pointer; font-family: var(--font-mono);
}
.chip:hover { border-color: var(--text-dim); }
.chip.active { background: var(--cyan); border-color: var(--cyan); color: #041019; font-weight: 600; }

.table-scroll { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }
.cnry-table { width: 100%; border-collapse: collapse; min-width: 720px; }
.cnry-table th {
  text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-faint);
  padding: 10px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; font-weight: 600;
  position: sticky; top: 0; background: var(--panel);
}
.cnry-table th[data-sort] { cursor: pointer; user-select: none; }
.cnry-table th[data-sort]:hover { color: var(--text); }
.cnry-table th.sort-asc::after { content: " \\2191"; }
.cnry-table th.sort-desc::after { content: " \\2193"; }
.cnry-table td { padding: 9px 12px; border-bottom: 1px solid var(--border); font-size: 12.5px; vertical-align: middle; }
.cnry-table tr:last-child td { border-bottom: none; }
.cnry-table tr:hover td { background: var(--panel-2); }
.col-value { letter-spacing: 0.6px; }
.col-time { color: var(--text-dim); white-space: nowrap; }
.col-source { color: var(--text-faint); max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cnry-empty-row { text-align: center; color: var(--text-faint); padding: 28px 12px !important; }

.repeat-badge {
  display: inline-block; background: var(--panel-2); border: 1px solid var(--border); color: var(--text-dim);
  border-radius: 999px; padding: 1px 7px; font-size: 10px; margin-left: 4px;
}

.badge { display: inline-block; border-radius: 999px; padding: 3px 9px; font-size: 10.5px; font-weight: 600; letter-spacing: 0.3px; }
.badge-det-regex { background: rgba(232,163,61,0.15); color: var(--amber-ink); border: 1px solid var(--amber); }
.badge-det-llm { background: rgba(79,193,233,0.15); color: var(--cyan-ink); border: 1px solid var(--cyan); }
.badge-det-audit { background: rgba(169,155,214,0.15); color: var(--audit); border: 1px solid var(--audit); }
.badge-det-unknown { background: var(--panel-2); color: var(--text-faint); border: 1px solid var(--border); }
.badge-conf-high { background: rgba(61,220,132,0.14); color: var(--good-ink); border: 1px solid var(--good); }
.badge-conf-medium { background: var(--panel-2); color: var(--text-dim); border: 1px solid var(--border); }
.badge-conf-unknown { background: var(--panel-2); color: var(--text-faint); border: 1px solid var(--border); }

.table-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 12px; flex-wrap: wrap; gap: 10px; }
.table-range { font-size: 11px; color: var(--text-faint); }
.table-pager { display: flex; align-items: center; gap: 10px; }
.pager-btn { background: var(--panel-2); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 5px 11px; font-size: 12px; cursor: pointer; font-family: var(--font-mono); }
.pager-btn:disabled { opacity: 0.4; cursor: default; }
.pager-btn:not(:disabled):hover { border-color: var(--text-dim); }
.pager-info { font-size: 11px; color: var(--text-faint); }

/* ── Mini panels ────────────────────────────────────── */
.mini-row { display: flex; align-items: center; gap: 10px; margin: 8px 0; }
.mini-label { font-size: 12px; color: var(--text-dim); width: 130px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mini-bar-track { flex: 1; height: 6px; background: var(--panel-2); border-radius: 3px; overflow: hidden; }
.mini-bar { display: block; height: 100%; background: var(--cyan); }
.mini-count { font-family: var(--font-mono); font-size: 12px; color: var(--text-faint); width: 34px; text-align: right; }

/* ── Empty state ────────────────────────────────────── */
.empty-state { text-align: center; padding: 72px 20px 56px; max-width: 560px; margin: 0 auto; }
.empty-bird { font-size: 64px; line-height: 1; margin-bottom: 18px; }
.empty-headline { font-size: 22px; font-weight: 700; margin-bottom: 10px; }
.empty-subline { color: var(--text-dim); font-size: 14px; margin-bottom: 24px; }
.empty-checklist { list-style: none; padding: 0; margin: 0 0 28px; text-align: left; display: inline-block; }
.empty-checklist li { color: var(--text-dim); font-size: 13px; padding: 5px 0 5px 24px; position: relative; }
.empty-checklist li::before { content: "\\2713"; position: absolute; left: 0; color: var(--good-ink); font-weight: 700; }
.empty-cta { font-size: 13px; color: var(--text-faint); }

/* ── Footer ─────────────────────────────────────────── */
.footer { text-align: center; padding: 30px 20px 40px; border-top: 1px solid var(--border); margin-top: 30px; }
.footer-line { font-size: 12px; color: var(--text-dim); margin: 4px 0; }
.footer-dim { color: var(--text-faint); font-size: 11.5px; }
.footer a { color: var(--text-dim); }
.footer a:hover { color: var(--cyan-ink); }

/* ── Responsive ─────────────────────────────────────── */
@media (max-width: 900px) {
  .hero-row { grid-template-columns: 1fr; }
  .two-col { grid-template-columns: 1fr; }
  .hero-tiles { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 640px) {
  .container { padding: 0 14px; }
  .topbar-inner { padding: 14px; }
  .hero-tiles { grid-template-columns: 1fr 1fr; }
  .stat-value { font-size: 21px; }
  .grade-letter { font-size: 44px; }
  .demo-ribbon {
    position: static; width: 100%; transform: none; border-radius: 0;
    padding: 6px 0; font-size: 10px; box-shadow: none;
  }
  .card { padding: 16px; }
  .table-controls { flex-direction: column; align-items: stretch; }
  .search-input { flex: 1 1 auto; min-width: 0; }
  .chip-groups { gap: 10px; }
}

@media print {
  .theme-toggle, .table-controls, .table-pager { display: none; }
  body { background: #fff; color: #000; }
}
"""

# ═════════════════════════════════════════════════════════════════════════
# Client JS — DOM built via createElement/textContent only, never innerHTML
# with stored data. Theme persisted via try/caught localStorage only.
# ═════════════════════════════════════════════════════════════════════════

BOOT_JS = """(function(){
  try {
    var stored = localStorage.getItem('canary-theme');
    if (stored === 'light' || stored === 'dark') {
      document.documentElement.setAttribute('data-theme', stored);
      return;
    }
  } catch (e) {}
  var prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  document.documentElement.setAttribute('data-theme', prefersLight ? 'light' : 'dark');
})();"""

MAIN_JS = """(function(){
'use strict';

function currentTheme(){ return document.documentElement.getAttribute('data-theme') || 'dark'; }
function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('canary-theme', t); } catch(e) {}
  var btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.textContent = t === 'dark' ? '\\uD83C\\uDF19' : '\\u2600';
    btn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
  }
}
var themeBtn = document.getElementById('theme-toggle');
if (themeBtn) {
  applyTheme(currentTheme());
  themeBtn.addEventListener('click', function(){
    applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  });
}

var dataEl = document.getElementById('canary-data');
if (!dataEl) return;
var DATA = null;
try { DATA = JSON.parse(dataEl.textContent || dataEl.innerText || '{}'); } catch (e) { DATA = null; }
if (!DATA || !Array.isArray(DATA.rows) || !DATA.rows.length) return;

function sourceLabel(s){
  if (!s) return '\\u2014';
  if (s === 'transcript') return 'transcript';
  if (s.indexOf('file:') === 0) {
    var p = s.slice(5);
    var parts = p.split('/');
    return parts[parts.length - 1] || p;
  }
  return s;
}

var rows = DATA.rows.map(function(r){
  var ts = (r[0] === null || r[0] === undefined) ? null : (DATA.baseMin + r[0]) * 60000;
  var typeIdx = r[1];
  var src = DATA.sources[r[5]] || '';
  return {
    ts: ts,
    type: DATA.types[typeIdx] || 'unknown',
    typeLabel: DATA.typeLabels[typeIdx] || 'Unknown',
    family: DATA.typeFamilies[typeIdx] || 'Other',
    value: DATA.values[r[2]] || '',
    det: DATA.det[r[3]] || 'unknown',
    conf: DATA.conf[r[4]] || 'unknown',
    source: src,
    sourceLabel: sourceLabel(src),
    rep: r[6] || 1
  };
});
rows.forEach(function(r){
  r.blob = (r.type + ' ' + r.value + ' ' + r.source).toLowerCase();
});

function parseHash(){
  var h = location.hash.replace(/^#/, '');
  var out = { q: '', det: [], conf: [], cat: [], sort: 'time', dir: 'desc', page: 1 };
  if (!h) return out;
  h.split('&').forEach(function(p){
    var eq = p.indexOf('=');
    if (eq < 0) return;
    var k = decodeURIComponent(p.slice(0, eq));
    var v = decodeURIComponent(p.slice(eq + 1));
    if (k === 'q') out.q = v;
    else if (k === 'det') out.det = v ? v.split(',') : [];
    else if (k === 'conf') out.conf = v ? v.split(',') : [];
    else if (k === 'cat') out.cat = v ? v.split(',') : [];
    else if (k === 'sort') out.sort = v;
    else if (k === 'dir') out.dir = v;
    else if (k === 'page') out.page = parseInt(v, 10) || 1;
  });
  return out;
}
function writeHash(){
  var parts = [];
  if (state.q) parts.push('q=' + encodeURIComponent(state.q));
  if (state.det.length) parts.push('det=' + state.det.map(encodeURIComponent).join(','));
  if (state.conf.length) parts.push('conf=' + state.conf.map(encodeURIComponent).join(','));
  if (state.cat.length) parts.push('cat=' + state.cat.map(encodeURIComponent).join(','));
  if (state.sort !== 'time') parts.push('sort=' + state.sort);
  if (state.dir !== 'desc') parts.push('dir=' + state.dir);
  if (state.page !== 1) parts.push('page=' + state.page);
  var hash = parts.length ? '#' + parts.join('&') : '';
  try {
    var url = location.pathname + location.search + hash;
    history.replaceState(null, '', url);
  } catch (e) {}
}

var state = parseHash();
var PAGE_SIZE = 25;

var searchInput = document.getElementById('cnry-search');
var chipsContainer = document.getElementById('cnry-chips');
var tbody = document.getElementById('cnry-tbody');
var rangeEl = document.getElementById('cnry-range');
var pagerEl = document.getElementById('cnry-pager');
var headers = document.querySelectorAll('#cnry-table th[data-sort]');

function el(tag, cls){
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}

function uniqueSorted(list){
  var seen = {};
  var out = [];
  list.forEach(function(x){ if (!seen[x]) { seen[x] = 1; out.push(x); } });
  out.sort();
  return out;
}

function makeChipGroup(title, groupKey, options){
  var wrap = el('div', 'chip-group');
  var lbl = el('span', 'chip-group-label');
  lbl.textContent = title;
  wrap.appendChild(lbl);
  options.forEach(function(opt){
    var btn = el('button', 'chip');
    btn.type = 'button';
    btn.textContent = opt;
    if (state[groupKey].indexOf(opt) !== -1) btn.classList.add('active');
    btn.addEventListener('click', function(){
      var idx = state[groupKey].indexOf(opt);
      if (idx === -1) state[groupKey].push(opt); else state[groupKey].splice(idx, 1);
      state.page = 1;
      btn.classList.toggle('active');
      render();
      writeHash();
    });
    wrap.appendChild(btn);
  });
  return wrap;
}

if (chipsContainer) {
  var detOptions = uniqueSorted(rows.map(function(r){ return r.det; }));
  var confOptions = uniqueSorted(rows.map(function(r){ return r.conf; }));
  var catOptions = uniqueSorted(rows.map(function(r){ return r.family; }));
  if (detOptions.length > 1) chipsContainer.appendChild(makeChipGroup('detector', 'det', detOptions));
  if (confOptions.length > 1) chipsContainer.appendChild(makeChipGroup('confidence', 'conf', confOptions));
  if (catOptions.length > 1) chipsContainer.appendChild(makeChipGroup('category', 'cat', catOptions));
}

if (searchInput) {
  searchInput.value = state.q;
  var debounceTimer = null;
  searchInput.addEventListener('input', function(){
    state.q = searchInput.value;
    state.page = 1;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function(){ render(); writeHash(); }, 200);
  });
}

headers.forEach(function(th){
  th.addEventListener('click', function(){
    var key = th.getAttribute('data-sort');
    if (state.sort === key) state.dir = (state.dir === 'asc') ? 'desc' : 'asc';
    else { state.sort = key; state.dir = 'asc'; }
    state.page = 1;
    render();
    writeHash();
  });
});

function confRank(c){ return c === 'high' ? 2 : (c === 'medium' ? 1 : 0); }

function applyFilters(){
  var q = state.q.trim().toLowerCase();
  return rows.filter(function(r){
    if (q && r.blob.indexOf(q) === -1) return false;
    if (state.det.length && state.det.indexOf(r.det) === -1) return false;
    if (state.conf.length && state.conf.indexOf(r.conf) === -1) return false;
    if (state.cat.length && state.cat.indexOf(r.family) === -1) return false;
    return true;
  });
}

function sortRows(list){
  var dir = state.dir === 'asc' ? 1 : -1;
  var key = state.sort;
  list.sort(function(a, b){
    var av, bv;
    if (key === 'type') { av = a.typeLabel.toLowerCase(); bv = b.typeLabel.toLowerCase(); }
    else if (key === 'confidence') { av = confRank(a.conf); bv = confRank(b.conf); }
    else { av = (a.ts === null ? -Infinity : a.ts); bv = (b.ts === null ? -Infinity : b.ts); }
    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;
    return 0;
  });
  return list;
}

function fmtRelative(ms){
  if (ms === null) return '\\u2014';
  var diff = Date.now() - ms;
  var s = Math.round(diff / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return s + 's ago';
  var m = Math.round(s / 60); if (m < 60) return m + 'm ago';
  var h = Math.round(m / 60); if (h < 24) return h + 'h ago';
  var d = Math.round(h / 24); if (d < 30) return d + 'd ago';
  var mo = Math.round(d / 30); if (mo < 12) return mo + 'mo ago';
  var y = Math.round(mo / 12); return y + 'y ago';
}
function fmtAbsolute(ms){
  if (ms === null) return 'unknown time';
  try { return new Date(ms).toString(); } catch (e) { return 'unknown time'; }
}

function render(){
  var filtered = applyFilters();
  sortRows(filtered);
  var total = filtered.length;
  var pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (state.page > pages) state.page = pages;
  if (state.page < 1) state.page = 1;
  var startIdx = (state.page - 1) * PAGE_SIZE;
  var pageRows = filtered.slice(startIdx, startIdx + PAGE_SIZE);

  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

  if (!pageRows.length) {
    var tr0 = el('tr');
    var td0 = el('td', 'cnry-empty-row');
    td0.setAttribute('colspan', '6');
    td0.textContent = 'No detections match your filters.';
    tr0.appendChild(td0);
    tbody.appendChild(tr0);
  }

  pageRows.forEach(function(r){
    var tr = el('tr');

    var tdTime = el('td', 'col-time');
    tdTime.textContent = fmtRelative(r.ts);
    tdTime.title = fmtAbsolute(r.ts);
    tr.appendChild(tdTime);

    var tdType = el('td');
    var pill = el('span', 'pill pill-type');
    var dot = el('span', 'pill-dot fam-' + r.family.toLowerCase());
    pill.appendChild(dot);
    pill.appendChild(document.createTextNode(r.typeLabel));
    tdType.appendChild(pill);
    tr.appendChild(tdType);

    var tdValue = el('td', 'col-value mono');
    tdValue.appendChild(document.createTextNode(r.value));
    if (r.rep > 1) {
      var rep = el('span', 'repeat-badge');
      rep.textContent = '\\u00d7' + r.rep;
      rep.title = 'same underlying value seen ' + r.rep + ' times';
      tdValue.appendChild(document.createTextNode(' '));
      tdValue.appendChild(rep);
    }
    tr.appendChild(tdValue);

    var tdDet = el('td');
    var detBadge = el('span', 'badge badge-det-' + r.det);
    detBadge.textContent = r.det;
    tdDet.appendChild(detBadge);
    tr.appendChild(tdDet);

    var tdConf = el('td');
    var confBadge = el('span', 'badge badge-conf-' + r.conf);
    confBadge.textContent = r.conf;
    tdConf.appendChild(confBadge);
    tr.appendChild(tdConf);

    var tdSrc = el('td', 'col-source');
    tdSrc.textContent = r.sourceLabel;
    if (r.source) tdSrc.title = r.source;
    tr.appendChild(tdSrc);

    tbody.appendChild(tr);
  });

  if (rangeEl) {
    rangeEl.textContent = total === 0 ? 'Showing 0 of 0' :
      ('Showing ' + (startIdx + 1) + '\\u2013' + Math.min(startIdx + PAGE_SIZE, total) + ' of ' + total);
  }

  if (pagerEl) {
    while (pagerEl.firstChild) pagerEl.removeChild(pagerEl.firstChild);
    var prevBtn = el('button', 'pager-btn');
    prevBtn.type = 'button';
    prevBtn.textContent = '\\u2039 Prev';
    prevBtn.disabled = state.page <= 1;
    prevBtn.addEventListener('click', function(){ state.page--; render(); writeHash(); });
    var info = el('span', 'pager-info');
    info.textContent = 'Page ' + state.page + ' of ' + pages;
    var nextBtn = el('button', 'pager-btn');
    nextBtn.type = 'button';
    nextBtn.textContent = 'Next \\u203a';
    nextBtn.disabled = state.page >= pages;
    nextBtn.addEventListener('click', function(){ state.page++; render(); writeHash(); });
    pagerEl.appendChild(prevBtn);
    pagerEl.appendChild(info);
    pagerEl.appendChild(nextBtn);
  }

  headers.forEach(function(th){
    th.classList.remove('sort-asc', 'sort-desc');
    if (th.getAttribute('data-sort') === state.sort) {
      th.classList.add(state.dir === 'asc' ? 'sort-asc' : 'sort-desc');
    }
  });
}

render();
window.addEventListener('hashchange', function(){ state = parseHash(); render(); });
})();"""


# ═════════════════════════════════════════════════════════════════════════
# Full document assembly
# ═════════════════════════════════════════════════════════════════════════


def generate_html(raw_records, config, demo):
    records = [normalize_record(r) for r in raw_records]
    records = [r for r in records if r]

    now_local = datetime.now()
    agg = build_aggregates(records, demo, now_local)

    generated_label = f"{fmt_date_short(now_local.date())}, {now_local.year} · {now_local.strftime('%H:%M')} (local)"

    llm_scan_enabled = config.get("llm_scan_enabled", True) if isinstance(config, dict) else True
    show_llm_warning = llm_scan_enabled is False

    header_html = render_header(agg, generated_label)
    llm_warning_html = render_llm_warning() if show_llm_warning else ""

    if agg["total"] == 0:
        main_html = render_empty_state()
    else:
        main_html = "".join([
            render_hero(agg),
            render_chart_a(agg),
            render_chart_b(agg),
            render_achievements(agg),
            render_table_section(agg),
        ])

    footer_html = render_footer()
    data_island_html = render_data_island(agg) if agg["total"] > 0 else ""

    parts = []
    parts.append("<!DOCTYPE html>\n")
    parts.append('<html lang="en">\n<head>\n')
    parts.append('<meta charset="utf-8">\n')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">\n')
    parts.append("<script>")
    parts.append(BOOT_JS)
    parts.append("</script>\n")
    parts.append("<title>\U0001F424 CANARY — PII Exposure Report</title>\n")
    parts.append("<style>")
    parts.append(CSS_TEXT)
    parts.append("</style>\n")
    parts.append("</head>\n<body>\n")
    parts.append(header_html)
    parts.append(llm_warning_html)
    parts.append(main_html)
    parts.append(footer_html)
    parts.append(data_island_html)
    parts.append("\n<script>")
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
        prog="dashboard.py",
        description="Generate Canary's self-contained HTML PII exposure dashboard.",
    )
    p.add_argument("--out", metavar="PATH", default=None,
                    help=f"Output HTML path (default: {DEFAULT_OUTPUT_FILE})")
    p.add_argument("--no-open", action="store_true",
                    help="Do not open the dashboard in a browser after generating it.")
    p.add_argument("--demo", action="store_true",
                    help="Ignore real data and render ~140 realistic fake detections.")
    p.add_argument("--print-path-only", action="store_true",
                    help="Write the file, print its path, and never attempt to open it.")
    return p


def main():
    args = build_argparser().parse_args()

    out_path = args.out or DEFAULT_OUTPUT_FILE
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    if args.demo:
        raw_records = generate_demo_leaks()
    else:
        raw_records = load_leaks_raw(LEAKS_FILE)

    config = load_config(CONFIG_FILE)

    html_doc = generate_html(raw_records, config, args.demo)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    # The dashboard embeds redacted detection data — owner-only, like the
    # rest of the data directory.
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
