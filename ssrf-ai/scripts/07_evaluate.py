#!/usr/bin/env python
"""Run the SSRF evaluation harness against the trained model.

Usage:
    python scripts/07_evaluate.py [--model-path PATH] [--max-t1 N]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ssrf_ai.eval.harness import EvalConfig, run_evaluation
from ssrf_ai.eval.report import generate_report
from ssrf_ai.generate import load_model


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate the SSRF payload model")
    ap.add_argument("--model-path", default=str(ROOT / "models" / "ssrf-qwen1.5b-v1" / "final"))
    ap.add_argument("--test-path", default=str(ROOT / "data" / "pairs" / "test.jsonl"))
    ap.add_argument("--max-t1", type=int, default=0, help="max T1 pairs (0=all)")
    ap.add_argument("--max-t2", type=int, default=10)
    ap.add_argument("--output-dir", default="")
    args = ap.parse_args()

    out_dir = Path(args.output_dir) if args.output_dir else ROOT / "reports" / "eval-v1"

    print(f"[eval] model: {args.model_path}")
    print(f"[eval] output: {out_dir}")

    print("[eval] loading model...")
    model, tokenizer = load_model(args.model_path)

    config = EvalConfig(
        model_path=args.model_path,
        test_path=args.test_path,
        max_t1=args.max_t1,
        max_t2=args.max_t2,
    )

    results = run_evaluation(model, tokenizer, config)

    generate_report(results, out_dir)
    print(f"\n[done] report written to {out_dir}")

    t1 = results.get("t1", {})
    t2 = results.get("t2", {})
    sec = results.get("secondary", {})
    print("\n=== SUMMARY ===")
    print(f"  T1 Synthetic:  {t1.get('rate', 0):.1%} (target {t1.get('target', 0):.0%}) {'PASS' if t1.get('passed') else 'FAIL'}")
    print(f"  T2 Held-out:   {t2.get('rate', 0):.1%} (target {t2.get('target', 0):.0%}) {'PASS' if t2.get('passed') else 'FAIL'}")
    print(f"  Valid URL:     {sec.get('valid_url_rate', 0):.1%} (target {sec.get('url_target', 0):.0%}) {'PASS' if sec.get('url_passed') else 'FAIL'}")
    print(f"  Diversity:     {sec.get('diversity_score', 0):.2f} (target {sec.get('diversity_target', 0):.2f}) {'PASS' if sec.get('diversity_passed') else 'FAIL'}")
    print(f"  Refusal Rate:  {sec.get('refusal_rate', 0):.1%}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
