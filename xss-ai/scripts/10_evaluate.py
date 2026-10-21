#!/usr/bin/env python
"""Run the XSS-AI evaluation harness against a trained model.

Usage:
    python scripts/10_evaluate.py [--model-path PATH] [--max-t1 N] [--max-t2 N]

Outputs JSON + markdown report to reports/<date>-v1/.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.eval.harness import EvalConfig, run_evaluation
from xss_ai.eval.report import generate_report
from xss_ai.generate import load_model


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate the XSS payload model")
    ap.add_argument("--model-path", default=str(ROOT / "models" / "xss-qwen1.5b-v1" / "merged"),
                    help="path to the merged model directory")
    ap.add_argument("--test-path", default=str(ROOT / "data" / "pairs" / "clean" / "test.jsonl"),
                    help="path to test.jsonl")
    ap.add_argument("--max-t1", type=int, default=0,
                    help="max T1 pairs to test (0 = all 565)")
    ap.add_argument("--max-t2", type=int, default=15,
                    help="max T2 held-out contexts to test (default 15)")
    ap.add_argument("--output-dir", default="",
                    help="output directory (default: reports/<date>-v1)")
    args = ap.parse_args()

    # Output directory
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        date_str = datetime.now(UTC).strftime("%Y-%m-%d")
        out_dir = ROOT / "reports" / f"{date_str}-v1"

    print(f"[eval] model: {args.model_path}")
    print(f"[eval] output: {out_dir}")

    # Load model
    print("[eval] loading model...")
    model, tokenizer = load_model(args.model_path)

    # Configure
    config = EvalConfig(
        model_path=args.model_path,
        test_path=args.test_path,
        max_t1=args.max_t1,
        max_t2=args.max_t2,
    )

    # Run evaluation
    results = run_evaluation(model, tokenizer, config)

    # Generate report
    generate_report(results, out_dir)
    print(f"\n[done] report written to {out_dir}")
    print(f"  - {out_dir / 'eval_report.json'}")
    print(f"  - {out_dir / 'eval_report.md'}")

    # Print summary
    t1 = results.get("t1", {})
    t2 = results.get("t2", {})
    sec = results.get("secondary", {})
    print("\n=== SUMMARY ===")
    print(f"  T1 Synthetic:     {t1.get('rate', 0):.1%} (target {t1.get('target', 0):.0%}) {'PASS' if t1.get('passed') else 'FAIL'}")
    print(f"  T2 Held-out:      {t2.get('rate', 0):.1%} (target {t2.get('target', 0):.0%}) {'PASS' if t2.get('passed') else 'FAIL'}")
    print(f"  Valid Syntax:     {sec.get('valid_syntax_rate', 0):.1%} (target {sec.get('syntax_target', 0):.0%}) {'PASS' if sec.get('syntax_passed') else 'FAIL'}")
    print(f"  Diversity:        {sec.get('diversity_score', 0):.2f} (target {sec.get('diversity_target', 0):.2f}) {'PASS' if sec.get('diversity_passed') else 'FAIL'}")
    print(f"  Refusal Rate:     {sec.get('refusal_rate', 0):.1%}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
