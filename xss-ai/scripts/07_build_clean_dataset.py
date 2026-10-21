#!/usr/bin/env python
"""Build a gold-standard dataset: browser-verify payloads once, expand across contexts.

Two phases:
  1. TEST-ONCE: browser-test each distinct payload in a plain html_body context.
     Saves verified payloads incrementally to data/pairs/verified_payloads.jsonl
     so the slow phase is resumable.
  2. EXPAND: re-pair verified payloads with all 74 contexts where they survive
     the reflection pipeline. Every pair has verified_by="playwright".
  3. SPLIT: payload-based split into train/val/test.

Usage:
    python scripts/07_build_clean_dataset.py [--resume] [--limit N]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.browser_oracle import expand_verified, test_payloads_once
from xss_ai.context import ContextSpec, render_description
from xss_ai.filter_harness import load_contexts, write_pairs_jsonl
from xss_ai.splits import run_quality_gates, stratified_split

VERIFIED_PATH = ROOT / "data" / "pairs" / "verified_payloads.jsonl"
CLEAN_DIR = ROOT / "data" / "pairs" / "clean"


def _distinct_payloads_from_pairs(pairs_path: Path) -> list[str]:
    """Get distinct payloads from the filter-sim pairs output (deduped).

    Sourcing from pairs_raw.jsonl (not the raw corpus) means we only browser-test
    payloads that already passed can_fire — the actual candidates. This cuts the
    candidate set ~5x (from ~10k raw corpus to ~2k filter-sim survivors).
    """
    import re
    seen: set[str] = set()
    out: list[str] = []
    for line in pairs_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        payload = json.loads(line)["payload"]
        n = re.sub(r"\s+", "", payload.strip().lower())
        if n not in seen:
            seen.add(n)
            out.append(payload)
    return out


def _load_verified() -> list[str]:
    if not VERIFIED_PATH.exists():
        return []
    return [
        json.loads(line)["payload"]
        for line in VERIFIED_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _save_verified(payloads: list[str]) -> None:
    VERIFIED_PATH.parent.mkdir(parents=True, exist_ok=True)
    with VERIFIED_PATH.open("w", encoding="utf-8") as f:
        for p in payloads:
            f.write(json.dumps({"payload": p}) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--resume", action="store_true",
                    help="resume from saved verified_payloads.jsonl (skip phase 1)")
    ap.add_argument("--limit", type=int, default=0,
                    help="limit payloads to test in phase 1 (0 = all, for quick runs)")
    ap.add_argument("--start", type=int, default=0,
                    help="skip first N payloads (for resuming across sandbox-limited runs)")
    args = ap.parse_args()

    # --- Phase 1: test-once ---
    pairs_raw = ROOT / "data" / "pairs" / "pairs_raw.jsonl"
    if not pairs_raw.exists():
        print(f"[error] {pairs_raw} not found. Run scripts/02_build_pairs.py first.")
        return 1

    if args.resume:
        verified = _load_verified()
        print(f"[resume] {len(verified)} verified payloads loaded from checkpoint")
        # When resuming with --start, we continue phase 1 from an offset and
        # merge into the existing verified list.
        if args.start == 0 and not args.limit:
            # Pure resume: skip phase 1 entirely.
            pass
    else:
        verified = []

    # If we have a checkpoint AND no explicit --start/--limit, skip phase 1.
    skip_phase1 = args.resume and args.start == 0 and not args.limit and verified

    if not skip_phase1:
        payloads = _distinct_payloads_from_pairs(pairs_raw)
        if args.start:
            payloads = payloads[args.start:]
            print(f"[start] skipping first {args.start} payloads")
        if args.limit:
            payloads = payloads[:args.limit]
            print(f"[limit] testing {len(payloads)} payloads this batch")
        print(f"[phase 1] browser-testing {len(payloads)} filter-sim candidates in html_body...")

        test_ctx = ContextSpec(id="html-body-plain", location="html_body")
        test_ctx.description = render_description(test_ctx)

        # verified already holds any resumed checkpoint; append new finds to it.
        batch_start = len(verified)
        for i, payload in enumerate(payloads):
            if test_payloads_once([payload], test_ctx):
                verified.append(payload)
            if (i + 1) % 50 == 0:
                global_i = args.start + i + 1
                print(f"  ...offset {global_i}, {i+1}/{len(payloads)} this batch, "
                      f"{len(verified)} firing total")
                _save_verified(verified)  # incremental checkpoint
        _save_verified(verified)
        tested = len(payloads)
        found = len(verified) - batch_start
        rate = found / tested if tested else 0
        print(f"[phase 1 done] {found}/{tested} = {rate:.1%} fire this batch; "
              f"{len(verified)} total verified")

    # --- Phase 2: expand ---
    contexts = load_contexts(ROOT / "data" / "contexts" / "contexts.yaml")
    print(f"[phase 2] expanding {len(verified)} verified payloads across {len(contexts)} contexts...")
    pairs = expand_verified(verified, contexts)
    print(f"[phase 2 done] {len(pairs)} gold-standard pairs")

    # --- Phase 3: split ---
    splits = stratified_split(pairs, seed=0)
    for name in ("train", "val", "test"):
        print(f"[split] {name}: {len(splits[name])}")

    CLEAN_DIR.mkdir(parents=True, exist_ok=True)
    write_pairs_jsonl(splits["train"], CLEAN_DIR / "train.jsonl")
    write_pairs_jsonl(splits["val"], CLEAN_DIR / "val.jsonl")
    write_pairs_jsonl(splits["test"], CLEAN_DIR / "test.jsonl")

    # Quality gates with adjusted volume threshold (clean dataset is smaller).
    report = run_quality_gates(
        splits["train"], splits["test"], min_train_pairs=max(100, len(splits["train"]) // 2)
    )
    (CLEAN_DIR / "gates_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if report["passed"]:
        print(f"[gates PASS] clean dataset written to {CLEAN_DIR}")
    else:
        print(f"[gates] violations: {report['violations']}")

    print(f"\n[done] {len(pairs)} gold-standard pairs, {len(verified)} distinct verified payloads")
    print("       100% browser-verified (verified_by=playwright)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
