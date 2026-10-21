#!/usr/bin/env python
"""Validate filter-harness pairs against the browser oracle (85% gate)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.browser_oracle import validate_pairs
from xss_ai.pair_schema import Pair

GATE = 0.85


def _load_pairs(path: Path) -> list[Pair]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(Pair.model_validate_json(line))
    return out


def main() -> int:
    raw = ROOT / "data" / "pairs" / "pairs_raw.jsonl"
    if not raw.exists():
        print(f"[error] {raw} not found. Run scripts/02_build_pairs.py first.")
        return 1

    pairs = _load_pairs(raw)
    print(f"[load] {len(pairs)} pairs")
    report = validate_pairs(pairs, sample_fraction=0.1)
    print(f"[validate] checked {report['total_checked']}, overall agreement {report['overall_rate']:.1%}")

    failed_ctxs = [cid for cid, s in report["per_context"].items() if s["rate"] < GATE]
    out = ROOT / "data" / "pairs" / "validation_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[wrote] {out}")

    if failed_ctxs:
        print(f"[GATE FAIL] contexts below {GATE:.0%} agreement: {failed_ctxs}")
        print("Fix or drop these contexts in data/contexts/contexts.yaml before training.")
        return 2
    print(f"[GATE PASS] all contexts >= {GATE:.0%} agreement")
    return 0


if __name__ == "__main__":
    sys.exit(main())
