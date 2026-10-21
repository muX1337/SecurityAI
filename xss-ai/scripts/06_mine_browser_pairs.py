#!/usr/bin/env python
"""Source 2b: mine browser-verified pairs to supplement filter-sim output.

Slow (one browser launch per payload tested) but produces gold-standard pairs.
Targets contexts that yield few filter-sim survivors. Output is merged with
pairs_raw.jsonl by the caller (or concatenated manually).

Usage:
    python scripts/06_mine_browser_pairs.py [--per-context 30] [--contexts-regex attr]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.browser_oracle import mine_pairs
from xss_ai.corpus_loader import load_all_corpora
from xss_ai.filter_harness import load_contexts, write_pairs_jsonl


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-context", type=int, default=30,
                    help="max firing payloads to mine per context (default 30)")
    ap.add_argument("--contexts-regex", default="",
                    help="only mine contexts whose id matches this regex")
    args = ap.parse_args()

    import re
    ctx_filter = re.compile(args.contexts_regex) if args.contexts_regex else None

    contexts = load_contexts(ROOT / "data" / "contexts" / "contexts.yaml")
    if ctx_filter:
        contexts = [c for c in contexts if ctx_filter.search(c.id)]
    print(f"[contexts] {len(contexts)} to mine")

    payloads = load_all_corpora(ROOT / "data" / "raw")
    print(f"[corpus] {len(payloads)} payloads (mining until per-context cap hit)")

    mined = mine_pairs(contexts, payloads, per_context_cap=args.per_context)
    print(f"[mined] {len(mined)} browser-verified pairs")

    out = ROOT / "data" / "pairs" / "pairs_mined.jsonl"
    write_pairs_jsonl(mined, out)
    print(f"[wrote] {out}")
    print("Merge with pairs_raw.jsonl before finalizing splits:")
    print("  cat data/pairs/pairs_raw.jsonl data/pairs/pairs_mined.jsonl > data/pairs/pairs_all.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
