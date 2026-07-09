#!/usr/bin/env python3
"""score.py — Score the regex detector engine against tests/corpus.json.

Usage: python3 tests/score.py

For each case in corpus.json, runs `bash canary/scripts/detectors.sh "<text>"`
and parses the JSONL hits it prints. Prints a per-case report, then a
machine-parseable summary (consumed by test-corpus.sh):

    RECALL=<float>
    GOLD_CAUGHT=<int>
    GOLD_TOTAL=<int>
    PRESERVE_VIOLATIONS=<int>

Scoring rules (deliberately simple and deterministic — see the spec comment
in corpus.json for the full rationale):

  1. Output is REDACTED, so we cannot match on value text. Every comparison
     is done at the (case, type) level instead of the (case, value) level:
     for each case we collect the SET of "type" strings the detectors
     actually emitted ("hit_types"), independent of how many times or in
     what order they appeared (per-run dedup already collapses repeats).

  2. RECALL: for every case where "expected_miss" is not true, each gold
     entry counts as CAUGHT if its "type" is present in hit_types for that
     case, and MISSED otherwise. Cases with "expected_miss": true are
     excluded entirely from the recall calculation — their gold entries
     document categories that are structurally outside a regex engine's
     reach (e.g. person names), not something this scorer should ever
     expect to pass. recall = total_caught / total_gold across all other
     cases.

  3. PRESERVE VIOLATIONS: for every case (regardless of expected_miss),
     each preserve entry is a (value, type, reason) tuple describing a
     type that must NOT fire for that case. It counts as a VIOLATION if
     its "type" is present in hit_types for that case AND that type is
     not also justified by a gold entry of the same type in the same
     case (i.e. the case wasn't already expecting that type to appear for
     a different, legitimate reason). Because we score at the type level,
     not the value level, this is a conservative approximation — see the
     corpus design note — but every case in corpus.json is deliberately
     built so a case's gold and preserve entries never share a type,
     which makes the approximation exact for this corpus.

If python3 isn't available at all, test-corpus.sh skips this suite
entirely (exit 0) rather than failing — see that script for details.
"""
import json
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
DETECTORS = REPO_ROOT / "canary" / "scripts" / "detectors.sh"
CORPUS = TESTS_DIR / "corpus.json"


def run_detectors(text):
    """Run detectors.sh on text, return the set of "type" values emitted."""
    try:
        proc = subprocess.run(
            ["bash", str(DETECTORS), text],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        print(f"  WARNING: detectors.sh timed out on input: {text[:60]!r}...")
        return set()

    hit_types = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            print(f"  WARNING: non-JSON line from detectors.sh: {line!r}")
            continue
        if "type" in hit:
            hit_types.add(hit["type"])
    return hit_types


def main():
    if not DETECTORS.is_file():
        print(f"ERROR: detectors.sh not found at {DETECTORS}", file=sys.stderr)
        sys.exit(2)
    if not CORPUS.is_file():
        print(f"ERROR: corpus.json not found at {CORPUS}", file=sys.stderr)
        sys.exit(2)

    with open(CORPUS) as f:
        data = json.load(f)

    total_gold = 0
    total_caught = 0
    total_violations = 0

    for case in data["cases"]:
        case_id = case["id"]
        surface = case["surface"]
        # "__X__" is a defang splitter: corpus.json stores secret-shaped
        # fixtures with it embedded so no contiguous secret-like literal
        # exists in the repo (GitHub push protection scans fixtures too).
        text = case["text"].replace("__X__", "")
        gold = case.get("gold", [])
        preserve = case.get("preserve", [])
        expected_miss = bool(case.get("expected_miss", False))

        hit_types = run_detectors(text)
        gold_types_this_case = {g["type"] for g in gold}

        print(f"[{surface}] {case_id}")

        if expected_miss:
            gold_summary = ", ".join(f"{g['type']} (expected_miss)" for g in gold)
            print(f"    gold (excluded from recall): {gold_summary}")
        else:
            for g in gold:
                total_gold += 1
                if g["type"] in hit_types:
                    total_caught += 1
                    print(f"    CAUGHT  gold type={g['type']}")
                else:
                    print(f"    MISSED  gold type={g['type']} (value={g['value']!r})")

        for p in preserve:
            is_violation = p["type"] in hit_types and p["type"] not in gold_types_this_case
            if is_violation:
                total_violations += 1
                print(f"    VIOLATION preserve type={p['type']} fired (reason it should not: {p['reason']})")
            else:
                print(f"    OK      preserve type={p['type']} correctly absent")

    recall = (total_caught / total_gold) if total_gold else 1.0

    print("")
    print("===============================")
    print(f"Gold caught:          {total_caught}/{total_gold}")
    print(f"Recall:               {recall:.4f}")
    print(f"Preserve violations:  {total_violations}")
    print("===============================")

    # Machine-parseable summary for test-corpus.sh
    print(f"RECALL={recall:.4f}")
    print(f"GOLD_CAUGHT={total_caught}")
    print(f"GOLD_TOTAL={total_gold}")
    print(f"PRESERVE_VIOLATIONS={total_violations}")


if __name__ == "__main__":
    main()
