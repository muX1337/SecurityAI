#!/usr/bin/env python
"""Build (context, payload) pairs from the filter harness (Source 1)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.corpus_loader import load_all_corpora
from xss_ai.filter_harness import generate_pairs, load_contexts, write_pairs_jsonl


def main() -> int:
    raw_dir = ROOT / "data" / "raw"
    contexts_path = ROOT / "data" / "contexts" / "contexts.yaml"
    out_dir = ROOT / "data" / "pairs"
    out_dir.mkdir(parents=True, exist_ok=True)

    contexts = load_contexts(contexts_path)
    print(f"[contexts] {len(contexts)} loaded")

    payloads = load_all_corpora(raw_dir)
    print(f"[corpus] {len(payloads)} unique payloads")

    pairs = generate_pairs(contexts, payloads, per_context_cap=300)
    print(f"[pairs] {len(pairs)} generated (filter_sim)")

    out = out_dir / "pairs_raw.jsonl"
    write_pairs_jsonl(pairs, out)
    print(f"[wrote] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
