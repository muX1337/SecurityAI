#!/usr/bin/env python
"""Generate DPO preference pairs by sampling payloads and browser-testing them.

For each context: sample N candidates, browser-test each, form chosen/rejected pairs.

Usage:
    python scripts/12_generate_preferences.py [--candidates N] [--limit M] [--resume]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.context import ContextSpec
from xss_ai.eval.batched_oracle import BatchedOracle
from xss_ai.generate import generate, load_model
from xss_ai.preference_data import format_for_dpo

OUT_PATH = ROOT / "data" / "pairs" / "dpo" / "preference_pairs.jsonl"
CHECKPOINT_PATH = ROOT / "data" / "pairs" / "dpo" / "checkpoint.json"


def _load_train_contexts(path: Path) -> list[dict]:
    """Load unique context descriptions from the training data."""
    seen: set[str] = set()
    contexts: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        pair = json.loads(line)
        ctx = pair["context"]
        if ctx["description"] not in seen:
            seen.add(ctx["description"])
            contexts.append(ctx)
    return contexts


def _save_checkpoint(done_count: int, done_ids: set[str]) -> None:
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_PATH.write_text(json.dumps({
        "done_count": done_count,
        "done_ids": sorted(done_ids),
    }), encoding="utf-8")


def _load_checkpoint() -> tuple[int, set[str]]:
    if not CHECKPOINT_PATH.exists():
        return 0, set()
    data = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
    return data["done_count"], set(data["done_ids"])


def _append_pairs(pairs: list[dict]) -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("a", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-path", default=str(ROOT / "models" / "xss-qwen1.5b-v2" / "merged"))
    ap.add_argument("--candidates", type=int, default=8,
                    help="payload candidates to sample per context (default 8)")
    ap.add_argument("--limit", type=int, default=0,
                    help="max contexts to process (0 = all)")
    ap.add_argument("--max-pairs-per-context", type=int, default=5,
                    help="max preference pairs to form per context (default 5)")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    # Load contexts
    contexts = _load_train_contexts(ROOT / "data" / "pairs" / "clean" / "train.jsonl")
    print(f"[load] {len(contexts)} unique contexts")

    # Resume
    done_count, done_ids = _load_checkpoint()
    if args.resume:
        print(f"[resume] {done_count} contexts already processed")

    if args.limit:
        contexts = contexts[:args.limit]

    # Load model
    print(f"[model] loading {args.model_path}...")
    model, tokenizer = load_model(args.model_path)

    rng = random.Random(args.seed)
    total_pairs = done_count  # approximate (pairs != contexts)

    with BatchedOracle() as oracle:
        for i, ctx_dict in enumerate(contexts):
            ctx_id = ctx_dict["id"]
            if ctx_id in done_ids:
                continue

            desc = ctx_dict["description"]
            ctx = ContextSpec(**ctx_dict)

            # Sample N candidates
            candidates = generate(
                model, tokenizer, desc,
                strategy="sampling", n=args.candidates,
                temperature=0.8, top_p=0.9,
            )

            if len(candidates) < 2:
                done_ids.add(ctx_id)
                done_count += 1
                continue

            # Browser-test each candidate
            firing: list[str] = []
            non_firing: list[str] = []
            for payload in candidates:
                if oracle.check_fires(ctx, payload):
                    firing.append(payload)
                else:
                    non_firing.append(payload)

            # Form preference pairs: chosen from firing, rejected from non_firing
            pairs = []
            if firing and non_firing:
                rng.shuffle(firing)
                rng.shuffle(non_firing)
                for j in range(min(len(firing), len(non_firing), args.max_pairs_per_context)):
                    pairs.append(format_for_dpo(desc, firing[j], non_firing[j]))

            if pairs:
                _append_pairs(pairs)
                total_pairs += len(pairs)

            done_ids.add(ctx_id)
            done_count += 1

            if (done_count) % 5 == 0:
                _save_checkpoint(done_count, done_ids)
                print(f"  ...{done_count}/{len(contexts)} contexts, {total_pairs} pairs total")

    _save_checkpoint(done_count, done_ids)
    print(f"[done] {done_count} contexts processed, {total_pairs} preference pairs generated")
    print(f"[wrote] {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
