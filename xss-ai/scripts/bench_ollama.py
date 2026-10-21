#!/usr/bin/env python
"""Benchmark: Ollama (Qwen2.5:14b) vs fine-tuned 1.5B on XSS contexts.

Tests the exact contexts where our 1.5B model scored 0%:
  - Attribute breakout (attr_dq)
  - Brackets stripped (html-body-strip-ltgt)
  - URL parameter injection

Usage:
    python scripts/bench_ollama.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.ollama_generate import generate_and_verify

TESTS = [
    {
        "name": "HTML body (baseline — 1.5B scored 100%)",
        "desc": "Input is reflected into the HTML body (element content).",
        "ctx_location": "html_body",
    },
    {
        "name": "Attribute breakout (1.5B scored 0%)",
        "desc": "Input is reflected into a double-quoted HTML attribute value in an input tag.",
        "ctx_location": "attr_dq",
    },
    {
        "name": "Brackets stripped (1.5B scored 0%)",
        "desc": "Input is reflected into HTML body. The angle brackets are stripped by the server. Quotes allowed.",
        "ctx_location": "html_body",
    },
    {
        "name": "URL parameter (1.5B scored 0%)",
        "desc": "Input is reflected into a URL parameter (href attribute of a link).",
        "ctx_location": "url_param",
    },
]


def main() -> int:
    print("=" * 60)
    print("Ollama XSS Payload Benchmark")
    print("=" * 60)

    total_fired = 0
    total_tested = 0

    for test in TESTS:
        print(f"\n{'─' * 40}")
        print(f"TEST: {test['name']}")
        print(f"{'─' * 40}")

        results = generate_and_verify(test["desc"], n=5)

        fired = sum(1 for r in results if r.get("fires"))
        total_fired += fired
        total_tested += len(results)

        rate = fired / len(results) if results else 0
        print(f"\n  Result: {fired}/{len(results)} = {rate:.0%}")

    print(f"\n{'=' * 60}")
    print(f"OVERALL: {total_fired}/{total_tested} = "
          f"{total_fired/total_tested:.0%}" if total_tested else "no results")
    print(f"{'=' * 60}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
