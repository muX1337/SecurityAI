#!/usr/bin/env python
"""Evaluate training checkpoints by browser execution success on val contexts.

For each checkpoint:
  1. Load the checkpoint adapter
  2. Generate a payload for a sample of val contexts (greedy)
  3. Test each generated payload in the browser oracle
  4. Report execution success rate

The checkpoint with the highest success rate is the one to ship.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.browser_oracle import check_fires
from xss_ai.context import ContextSpec
from xss_ai.generate import generate, load_model


def evaluate_checkpoint(checkpoint_dir: str, val_pairs: list, sample_size: int = 20) -> dict:
    """Evaluate one checkpoint: generate payloads for val contexts, browser-test them."""
    print(f"\n[eval] checkpoint: {checkpoint_dir}")

    model, tokenizer = load_model(checkpoint_dir)

    import random
    rng = random.Random(42)
    sample = rng.sample(val_pairs, min(sample_size, len(val_pairs)))

    fired = 0
    tested = 0
    for pair in sample:
        desc = pair["context"]["description"]
        ctx = ContextSpec(**{k: v for k, v in pair["context"].items()})

        payloads = generate(model, tokenizer, desc, strategy="greedy", n=1)
        if not payloads:
            print(f"  MISS (no payload generated): {desc[:60]}")
            continue

        tested += 1
        fires = check_fires(ctx, payloads[0])
        if fires:
            fired += 1
        status = "FIRE" if fires else "MISS"
        print(f"  {status}: {payloads[0][:50]}")

    rate = fired / tested if tested else 0.0
    print(f"[eval] {checkpoint_dir}: {fired}/{tested} = {rate:.1%} execution success")
    return {"checkpoint": checkpoint_dir, "fired": fired, "tested": tested, "rate": rate}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default=str(ROOT / "models" / "xss-qwen1.5b-v1"),
                    help="parent directory containing checkpoint subdirs")
    ap.add_argument("--sample-size", type=int, default=20,
                    help="val contexts to test per checkpoint")
    ap.add_argument("--val-path", default=str(ROOT / "data" / "pairs" / "clean" / "val.jsonl"))
    args = ap.parse_args()

    # Load val pairs
    val_pairs = []
    for line in Path(args.val_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            val_pairs.append(json.loads(line))
    print(f"[load] {len(val_pairs)} val pairs")

    # Find all checkpoint directories (subdirs with adapter_model.safetensors)
    model_dir = Path(args.model_dir)
    checkpoints = sorted([
        d for d in model_dir.iterdir()
        if d.is_dir() and (d / "adapter_model.safetensors").exists()
    ]) if model_dir.exists() else []

    if not checkpoints:
        print(f"[error] no checkpoints found in {model_dir}")
        return 1

    print(f"[checkpoints] found {len(checkpoints)}: {[d.name for d in checkpoints]}")

    results = []
    for ckpt in checkpoints:
        result = evaluate_checkpoint(str(ckpt), val_pairs, args.sample_size)
        results.append(result)

    # Rank by execution success
    results.sort(key=lambda r: r["rate"], reverse=True)
    print("\n=== CHECKPOINT RANKING (by browser execution success) ===")
    for r in results:
        print(f"  {r['rate']:.1%}  {r['checkpoint']}")

    best = results[0]
    print(f"\n[BEST] {best['checkpoint']} at {best['rate']:.1%}")

    # Save report
    report_path = model_dir / "checkpoint_eval_report.json"
    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[wrote] {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
