#!/usr/bin/env python
"""Load validated pairs, split, run quality gates, write train/val/test.jsonl."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from openredirect_ai.filter_harness import write_pairs_jsonl
from openredirect_ai.pair_schema import Pair
from openredirect_ai.splits import run_quality_gates, stratified_split


def _load(path: Path) -> list[Pair]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(Pair.model_validate_json(line))
    return out


def main() -> int:
    src = ROOT / "data" / "pairs" / "pairs_raw.jsonl"
    if not src.exists():
        print(f"[error] {src} missing; run 02_build_pairs.py first.")
        return 1

    pairs = _load(src)
    print(f"[load] {len(pairs)} pairs")

    splits = stratified_split(pairs, seed=0)
    for name in ("train", "val", "test"):
        print(f"[split] {name}: {len(splits[name])}")

    gates = run_quality_gates(splits["train"], splits["test"])
    out_dir = ROOT / "data" / "pairs"
    (out_dir / "gates_report.json").write_text(json.dumps(gates, indent=2), encoding="utf-8")

    write_pairs_jsonl(splits["train"], out_dir / "train.jsonl")
    write_pairs_jsonl(splits["val"], out_dir / "val.jsonl")
    write_pairs_jsonl(splits["test"], out_dir / "test.jsonl")

    if gates["passed"]:
        print("[GATES PASS] splits written")
        return 0
    print("[GATES FAIL] violations:")
    for v in gates["violations"]:
        print("  -", v)
    return 2


if __name__ == "__main__":
    sys.exit(main())
