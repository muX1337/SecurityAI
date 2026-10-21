#!/usr/bin/env python
"""Validate filter-harness pairs against the URL-parser oracle (85% gate).

For open redirect the oracle (check_fires) uses the same filter simulation as
the harness, so agreement is 100% by construction. This script still samples and
reports per-context rates to keep the pipeline symmetrical with the other
vuln-type projects.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from openredirect_ai.oracle.check_fires import check_fires
from openredirect_ai.pair_schema import Pair

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

    import random
    from collections import defaultdict
    rng = random.Random(0)

    by_ctx: dict[str, list[Pair]] = defaultdict(list)
    for p in pairs:
        by_ctx[p.context.id].append(p)

    total_agree = 0
    total_checked = 0
    per_context: dict[str, dict] = {}

    for ctx_id, group in by_ctx.items():
        k = max(1, int(len(group) * 0.1))
        sample = rng.sample(group, min(k, len(group)))
        agree = 0
        for pr in sample:
            fires = check_fires(pr.context, pr.payload)
            if fires:
                agree += 1
        n = len(sample)
        rate = agree / n if n else 0.0
        per_context[ctx_id] = {"agree": agree, "checked": n, "rate": rate}
        total_agree += agree
        total_checked += n

    overall = total_agree / total_checked if total_checked else 0.0
    print(f"[validate] checked {total_checked}, overall agreement {overall:.1%}")

    failed = [cid for cid, s in per_context.items() if s["rate"] < GATE]
    report = {"per_context": per_context, "overall_rate": overall, "total_checked": total_checked}
    out = ROOT / "data" / "pairs" / "validation_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[wrote] {out}")

    if failed:
        print(f"[GATE FAIL] contexts below {GATE:.0%}: {failed}")
        return 2
    print(f"[GATE PASS] all contexts >= {GATE:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
