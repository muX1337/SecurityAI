#!/usr/bin/env python
"""T3 evaluation: test the trained model against real DVWA XSS endpoints.

Requires DVWA running at http://127.0.0.1:8080:
    docker compose -f src/labs/docker-compose.yml up -d

Usage:
    python scripts/11_eval_t3_dvwa.py [--model-path PATH]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.eval.report import generate_report
from xss_ai.eval.t3_real_apps import T3Config, run_t3_dvwa


def main() -> int:
    ap = argparse.ArgumentParser(description="T3: Evaluate model against real DVWA")
    ap.add_argument("--model-path", default=str(ROOT / "models" / "xss-qwen1.5b-v2" / "merged"),
                    help="path to merged model")
    ap.add_argument("--output-dir", default=str(ROOT / "reports" / "t3-dvwa"),
                    help="output directory for the report")
    args = ap.parse_args()

    print(f"[t3] model: {args.model_path}")
    print(f"[t3] output: {args.output_dir}")

    # Load model
    print("[t3] loading model...")
    from xss_ai.generate import load_model
    model, tokenizer = load_model(args.model_path)

    # Launch browser (Playwright)
    print("[t3] launching browser...")
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    browser = pw.chromium.launch()

    # Run T3
    config = T3Config()
    results = {"model_path": args.model_path, "t3": {}}

    try:
        t3_results = run_t3_dvwa(model, tokenizer, browser, config)
        results["t3"] = t3_results
    finally:
        browser.close()
        pw.stop()

    # Generate report
    out_dir = Path(args.output_dir)
    generate_report(results, out_dir)
    print(f"\n[t3] report written to {out_dir}")

    # Print summary
    t3 = results["t3"]
    print("\n=== T3 DVWA RESULTS ===")
    print(f"  Total tested: {t3.get('total', 0)}")
    print(f"  Fired: {t3.get('fired', 0)}")
    print(f"  Rate: {t3.get('rate', 0):.1%}")
    for ctx_id, stats in t3.get("per_context", {}).items():
        status = "FIRE" if stats["fired"] else "miss"
        print(f"    {status:4s}  {ctx_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
