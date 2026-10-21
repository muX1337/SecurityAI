#!/usr/bin/env python
"""Calibrate can_fire against the browser oracle on a small sample.

For each context, sample N payloads that can_fire PREDICTS will fire, run them
through the real browser, and report what fraction actually fire. This is the
fast iteration loop for tightening the heuristic.

Usage:
    python scripts/05_calibrate_can_fire.py [--per-context 5] [--contexts-regex html]
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.browser_oracle import check_fires
from xss_ai.can_fire import can_fire
from xss_ai.context import simulate_reflection
from xss_ai.corpus_loader import load_all_corpora
from xss_ai.filter_harness import load_contexts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-context", type=int, default=5,
                    help="payloads to browser-test per context (default 5)")
    ap.add_argument("--contexts-regex", default="",
                    help="only calibrate contexts whose id matches this regex")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    import re
    ctx_filter = re.compile(args.contexts_regex) if args.contexts_regex else None

    contexts = load_contexts(ROOT / "data" / "contexts" / "contexts.yaml")
    if ctx_filter:
        contexts = [c for c in contexts if ctx_filter.search(c.id)]
    print(f"[contexts] {len(contexts)} to calibrate")

    payloads = load_all_corpora(ROOT / "data" / "raw")
    print(f"[corpus] {len(payloads)} payloads")

    rng = random.Random(args.seed)
    total_predicted = 0
    total_confirmed = 0

    for ctx in contexts:
        # Find payloads can_fire predicts will fire.
        predicted = []
        for p in payloads:
            filtered = simulate_reflection(ctx, p)
            if filtered and can_fire(filtered, ctx.location):
                predicted.append(p)
        if not predicted:
            print(f"  {ctx.id:45s} predicted=0  (no payloads pass can_fire)")
            continue
        sample = rng.sample(predicted, min(args.per_context, len(predicted)))
        confirmed = sum(1 for p in sample if check_fires(ctx, p))
        rate = confirmed / len(sample)
        total_predicted += len(sample)
        total_confirmed += confirmed
        flag = "OK " if rate >= 0.85 else "LOW"
        print(f"  {flag} {ctx.id:43s} {confirmed}/{len(sample)} = {rate:.0%}")

    if total_predicted:
        overall = total_confirmed / total_predicted
        print(f"\n[overall] {total_confirmed}/{total_predicted} = {overall:.1%}")
        print("(target >=85% per context; LOW flags need can_fire tightening)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
