#!/usr/bin/env python
"""Load validated pairs, dedup on (normalize_for_dedup, context_id), split, run quality gates, write train/val/test.jsonl."""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from crlf_ai.filter_harness import write_pairs_jsonl
from crlf_ai.pair_schema import Pair
from crlf_ai.splits import normalize_for_dedup, run_quality_gates, stratified_split


def _load(path: Path) -> list[Pair]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(Pair.model_validate_json(line))
    return out


def _dedup(pairs: list[Pair]) -> list[Pair]:
    """Dedup on (normalize_for_dedup(payload), context_id), preserving first seen."""
    seen: set[tuple[str, str]] = set()
    out: list[Pair] = []
    for p in pairs:
        key = (normalize_for_dedup(p.payload), p.context.id)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def main() -> int:
    src = ROOT / "data" / "pairs" / "pairs_raw.jsonl"
    if not src.exists():
        print(f"[error] {src} missing; run 02_build_pairs.py first.")
        return 1

    raw = _load(src)
    print(f"[load] {len(raw)} pairs")
    pairs = _dedup(raw)
    print(f"[dedup] {len(pairs)} pairs after (payload, context_id) dedup "
          f"({len(raw) - len(pairs)} removed)")

    splits = stratified_split(pairs, seed=0)
    for name in ("train", "val", "test"):
        print(f"[split] {name}: {len(splits[name])}")

    gates = run_quality_gates(splits["train"], splits["test"])
    out_dir = ROOT / "data" / "pairs"
    (out_dir / "gates_report.json").write_text(json.dumps(gates, indent=2), encoding="utf-8")

    write_pairs_jsonl(splits["train"], out_dir / "train.jsonl")
    write_pairs_jsonl(splits["val"], out_dir / "val.jsonl")
    write_pairs_jsonl(splits["test"], out_dir / "test.jsonl")

    # Summary of context distribution in train
    counts = collections.Counter(p.context.id for p in splits["train"])
    print(f"[train] {len(counts)} distinct contexts, top: "
          f"{counts.most_common(3)}")

    if gates["passed"]:
        print("[GATES PASS] splits written")
        return 0
    print("[GATES FAIL] violations:")
    for v in gates["violations"]:
        print("  -", v)
    return 2


if __name__ == "__main__":
    sys.exit(main())
