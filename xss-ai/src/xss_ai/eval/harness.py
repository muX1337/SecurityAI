"""Evaluation harness: T1 (synthetic) + T2 (held-out combos) + secondary metrics.

Orchestrates the full evaluation using a BatchedOracle (persistent browser)
for throughput. Produces a results dict consumed by the report module.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

from ..can_fire import can_fire
from ..context import ContextSpec, render_description, simulate_reflection
from ..generate import generate
from .batched_oracle import BatchedOracle
from .metrics import diversity_score, refusal_rate, valid_syntax_rate
from .t2_generator import generate_held_out_contexts

T1_TARGET = 0.60
T2_TARGET = 0.30
SYNTAX_TARGET = 0.90
DIVERSITY_TARGET = 0.70


@dataclass
class EvalConfig:
    model_path: str = "models/xss-qwen1.5b-v1/merged"
    test_path: str = "data/pairs/clean/test.jsonl"
    contexts_yaml: str = "data/contexts/contexts.yaml"
    max_t1: int = 0  # 0 = all test pairs
    max_t2: int = 20  # max held-out combos to test
    t2_verify_payloads: int = 20  # payloads to browser-mine per T2 context to verify it's solvable
    diversity_samples: int = 10
    seed: int = 42


def _categorize_failure(ctx: ContextSpec, payload: str | None) -> str:
    """Determine why a payload didn't fire."""
    if payload is None or not payload.strip():
        return "no_payload"
    reflected = simulate_reflection(ctx, payload)
    if not reflected:
        return "filtered_to_empty"
    if not can_fire(reflected, ctx.location):
        return "syntax_invalid"
    return "does_not_execute"


def _run_t1(model, tokenizer, oracle: BatchedOracle, test_pairs: list, config: EvalConfig) -> dict:
    """T1: generate payloads for test-split contexts, browser-test them."""
    rng = random.Random(config.seed)
    pairs = test_pairs
    if config.max_t1 > 0:
        pairs = rng.sample(test_pairs, min(config.max_t1, len(test_pairs)))

    per_context: dict[str, dict] = {}
    failures: list[dict] = []
    all_payloads: list[str] = []
    fired = 0
    tested = 0

    for i, pair in enumerate(pairs):
        ctx = ContextSpec(**pair["context"])
        desc = ctx.description or render_description(ctx)

        payloads = generate(model, tokenizer, desc, strategy="greedy", n=1)
        payload = payloads[0] if payloads else None

        if payload:
            tested += 1
            all_payloads.append(payload)
            fires = oracle.check_fires(ctx, payload)
            if fires:
                fired += 1
            else:
                reason = _categorize_failure(ctx, payload)
                failures.append({
                    "context_id": ctx.id,
                    "payload": payload[:100],
                    "reason": reason,
                })
        else:
            failures.append({
                "context_id": ctx.id,
                "payload": "",
                "reason": "no_payload",
            })

        # Track per-context stats
        cid = ctx.id
        if cid not in per_context:
            per_context[cid] = {"total": 0, "fired": 0}
        per_context[cid]["total"] += 1
        if payload and fires:
            per_context[cid]["fired"] += 1

        if (i + 1) % 50 == 0:
            print(f"  T1: {i+1}/{len(pairs)} checked, {fired} fired")

    # Compute per-context rates
    for cid, stats in per_context.items():
        stats["rate"] = stats["fired"] / stats["total"] if stats["total"] else 0.0

    rate = fired / tested if tested else 0.0
    print(f"[T1] {fired}/{tested} = {rate:.1%} (target {T1_TARGET:.0%})")

    return {
        "total": tested,
        "fired": fired,
        "rate": rate,
        "target": T1_TARGET,
        "passed": rate >= T1_TARGET,
        "per_context": per_context,
        "failures": failures,
        "generated_payloads": all_payloads,
    }


def _run_t2(model, tokenizer, oracle: BatchedOracle, config: EvalConfig) -> dict:
    """T2: generate payloads for held-out filter combinations."""
    from ..corpus_loader import load_all_corpora

    # Generate held-out contexts
    held_out = generate_held_out_contexts(
        Path(config.contexts_yaml), max_combos=config.max_t2
    )
    print(f"[T2] {len(held_out)} held-out contexts generated")

    # Load raw payloads for mining (to verify each context is solvable)
    payloads = load_all_corpora(Path("data/raw"))
    rng = random.Random(config.seed)
    sample_payloads = rng.sample(payloads, min(config.t2_verify_payloads, len(payloads)))

    per_context: dict[str, dict] = {}
    failures: list[dict] = []
    fired = 0
    tested = 0

    for ctx in held_out:
        # Verify this context is solvable (at least one payload fires)
        solvable = any(oracle.check_fires(ctx, p) for p in sample_payloads)
        if not solvable:
            print(f"  T2: {ctx.id} not solvable, skipping")
            continue

        # Test the model
        desc = ctx.description or render_description(ctx)
        payloads_gen = generate(model, tokenizer, desc, strategy="greedy", n=1)
        payload = payloads_gen[0] if payloads_gen else None

        tested += 1
        if payload:
            fires = oracle.check_fires(ctx, payload)
            if fires:
                fired += 1
            else:
                reason = _categorize_failure(ctx, payload)
                failures.append({
                    "context_id": ctx.id,
                    "payload": payload[:100],
                    "reason": reason,
                })
        else:
            failures.append({
                "context_id": ctx.id,
                "payload": "",
                "reason": "no_payload",
            })

        per_context[ctx.id] = {
            "total": 1,
            "fired": 1 if (payload and fires) else 0,
            "rate": 1.0 if (payload and fires) else 0.0,
        }

    rate = fired / tested if tested else 0.0
    print(f"[T2] {fired}/{tested} = {rate:.1%} (target {T2_TARGET:.0%})")

    return {
        "total": tested,
        "fired": fired,
        "rate": rate,
        "target": T2_TARGET,
        "passed": rate >= T2_TARGET,
        "per_context": per_context,
        "failures": failures,
    }


def _run_secondary(model, tokenizer, t1_results: dict, config: EvalConfig) -> dict:
    """Secondary metrics: syntax validity, diversity, refusal."""
    payloads = t1_results.get("generated_payloads", [])

    syntax_rate = valid_syntax_rate(payloads)
    print(f"[syntax] {syntax_rate:.1%} valid (target {SYNTAX_TARGET:.0%})")

    # Diversity: sample 10 contexts, generate N payloads each
    random.Random(config.seed)
    # Use a plain context for diversity sampling
    diversity_desc = "Input is reflected into the HTML body (element content)."
    diversity_payloads = generate(
        model, tokenizer, diversity_desc,
        strategy="sampling", n=config.diversity_samples,
        temperature=0.7, top_p=0.9,
    )
    div_score = diversity_score(diversity_payloads)
    print(f"[diversity] {div_score:.2f} (target {DIVERSITY_TARGET:.2f})")

    # Refusal rate
    ref_rate = refusal_rate(payloads)
    print(f"[refusal] {ref_rate:.1%}")

    return {
        "valid_syntax_rate": syntax_rate,
        "syntax_target": SYNTAX_TARGET,
        "syntax_passed": syntax_rate >= SYNTAX_TARGET,
        "diversity_score": div_score,
        "diversity_target": DIVERSITY_TARGET,
        "diversity_passed": div_score >= DIVERSITY_TARGET,
        "refusal_rate": ref_rate,
    }


def run_evaluation(model, tokenizer, config: EvalConfig) -> dict:
    """Full evaluation: T1 + T2 + secondary metrics.

    Returns a results dict suitable for the report module.
    """
    # Load test pairs
    test_pairs = []
    test_path = Path(config.test_path)
    for line in test_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            test_pairs.append(json.loads(line))
    print(f"[load] {len(test_pairs)} test pairs from {test_path}")

    results = {"model_path": config.model_path}

    with BatchedOracle() as oracle:
        print("[T1] Running synthetic eval...")
        results["t1"] = _run_t1(model, tokenizer, oracle, test_pairs, config)

        print("[T2] Running held-out combo eval...")
        results["t2"] = _run_t2(model, tokenizer, oracle, config)

    print("[secondary] Computing metrics...")
    results["secondary"] = _run_secondary(model, tokenizer, results["t1"], config)

    return results
