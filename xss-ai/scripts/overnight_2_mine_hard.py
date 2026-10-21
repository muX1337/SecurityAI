#!/usr/bin/env python
"""Overnight job 2: Browser-mine XSS payloads for hard-filter contexts.

Mines payloads that actually fire in heavily-filtered contexts where the
model currently scores 0%: escape_angle_brackets, strip_angle_brackets,
attr_dq (attribute breakout), url_param, js_string contexts.

Uses the full corpus (10k+ payloads) with the browser oracle.
Resumable via checkpoint.

Usage:
    python scripts/overnight_2_mine_hard.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.browser_oracle import check_fires
from xss_ai.corpus_loader import load_all_corpora
from xss_ai.filter_harness import load_contexts
from xss_ai.pair_schema import Pair, Provenance

# These are the context IDs where the model scored 0% in eval
# Mining these will produce payloads that fire in hard-filter contexts
HARD_CONTEXT_IDS = {
    "html-body-escape-ltgt",
    "html-body-strip-lgt-block-script",
    "html-body-escape-lgt-block-script",
    "attr-dq-plain",
    "attr-dq-strip-lgt",
    "attr-dq-strip-lgt-block-script",
    "attr-dq-block-script",
    "url-param-plain",
    "url-param-strip-lgt",
    "url-param-block-script",
    "url-param-block-javascript",
    "url-param-escape-lgt",
    "attr-sq-escape-sq",
    "attr-sq-escape-sq-block-event-handlers",
}

OUT_PATH = ROOT / "data" / "pairs" / "hard_context_payloads.jsonl"
CHECKPOINT_PATH = ROOT / "data" / "pairs" / "hard_mine_checkpoint.json"
PER_CONTEXT_CAP = 30


def _load_checkpoint() -> dict:
    if CHECKPOINT_PATH.exists():
        return json.loads(CHECKPOINT_PATH.read_text())
    return {"done": [], "total_found": 0}


def _save_checkpoint(ckpt: dict) -> None:
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_PATH.write_text(json.dumps(ckpt))


def _append_pair(pair: Pair) -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("a", encoding="utf-8") as f:
        f.write(pair.to_jsonl() + "\n")


def main() -> int:
    print("[overnight-2] Starting hard-context browser mining")
    print(f"[overnight-2] Target contexts: {len(HARD_CONTEXT_IDS)}")

    # Load all contexts, filter to hard ones
    all_contexts = load_contexts(ROOT / "data" / "contexts" / "contexts.yaml")
    hard_contexts = [c for c in all_contexts if c.id in HARD_CONTEXT_IDS]
    print(f"[overnight-2] Loaded {len(hard_contexts)} hard contexts")

    if not hard_contexts:
        print("[overnight-2] ERROR: no hard contexts found in YAML")
        return 1

    # Load full corpus
    payloads = load_all_corpora(ROOT / "data" / "raw")
    print(f"[overnight-2] Loaded {len(payloads)} payloads from corpus")

    # Resume from checkpoint
    ckpt = _load_checkpoint()
    print(f"[overnight-2] Resuming: {len(ckpt['done'])} contexts already done, {ckpt['total_found']} found so far")

    start_time = time.time()

    for ctx in hard_contexts:
        if ctx.id in ckpt["done"]:
            print(f"  [skip] {ctx.id} already done")
            continue

        print(f"\n  [mining] {ctx.id} ({ctx.location}, filters={ctx.filters})")
        found = 0

        for i, payload in enumerate(payloads):
            if found >= PER_CONTEXT_CAP:
                break

            try:
                if check_fires(ctx, payload):
                    import hashlib
                    h = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:8]
                    pair = Pair(
                        id=f"hard-{ctx.id}__pl-{h}",
                        context=ctx,
                        payload=payload,
                        provenance=Provenance(
                            source="browser_oracle",
                            verified_by="playwright",
                        ),
                    )
                    _append_pair(pair)
                    found += 1
                    print(f"    [{found}/{PER_CONTEXT_CAP}] {payload[:60]}")
            except Exception:
                pass  # skip payloads that crash the oracle

            if (i + 1) % 500 == 0:
                print(f"    ...scanned {i+1}/{len(payloads)} payloads, {found} found")

        ckpt["done"].append(ctx.id)
        ckpt["total_found"] += found
        _save_checkpoint(ckpt)
        elapsed = time.time() - start_time
        print(f"  [done] {ctx.id}: {found} payloads in {elapsed:.0f}s")

    # Final summary
    total_pairs = sum(1 for _ in OUT_PATH.read_text().splitlines() if _.strip()) if OUT_PATH.exists() else 0
    elapsed = time.time() - start_time
    print(f"\n[overnight-2] COMPLETE: {total_pairs} hard-context payloads found")
    print(f"[overnight-2] Time: {elapsed/60:.1f} min")
    print(f"[overnight-2] Output: {OUT_PATH}")

    if total_pairs > 0:
        print("\n[overnight-2] NEXT STEPS:")
        print("  1. Merge hard_context_payloads.jsonl into the clean dataset")
        print("  2. Re-run splits: python scripts/04_finalize_splits.py")
        print("  3. Retrain: python scripts/05_train.py")

    return 0


if __name__ == "__main__":
    sys.exit(main())
