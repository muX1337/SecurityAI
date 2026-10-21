"""Open redirect evaluation harness: T1 (synthetic) + T2 (held-out) + metrics.

Uses the URL-parser oracle (check_fires) — pure Python, no callback listener.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

from ..can_fire import can_fire
from ..context import LOCATIONS, ContextSpec, render_description, simulate_reflection
from ..generate import generate
from ..oracle.check_fires import check_fires
from ..splits import normalize_for_dedup

T1_TARGET = 0.60
T2_TARGET = 0.30
VALID_URL_TARGET = 0.90
DIVERSITY_TARGET = 0.70

# Filter universe used to synthesize T2 held-out combinations.
_T2_FILTERS = [
    "block_absolute_url",
    "require_same_domain",
    "block_protocol_relative",
    "block_at_symbol",
    "block_backslash",
    "url_decode",
    "block_dotdot",
    "allowlist_paths",
]
_T2_LOCATIONS = list(LOCATIONS)


@dataclass
class EvalConfig:
    model_path: str = "models/redirect-qwen1.5b-v1/final"
    test_path: str = "data/pairs/test.jsonl"
    contexts_yaml: str = "data/contexts/openredirect_contexts.yaml"
    max_t1: int = 0
    max_t2: int = 10
    diversity_samples: int = 10
    seed: int = 42


def _categorize_failure(ctx: ContextSpec, payload: str | None) -> str:
    if payload is None or not payload.strip():
        return "no_payload"
    filtered = simulate_reflection(ctx, payload)
    if not filtered:
        return "blocked_by_filter"
    if not can_fire(filtered, ctx.location):
        return "invalid_url"
    return "no_redirect"


def _run_t1(model, tokenizer, test_pairs: list, config: EvalConfig) -> dict:
    """T1: generate payloads for test-split contexts, oracle-test them."""
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

        tested += 1
        fires = False
        if payload:
            all_payloads.append(payload)
            fires = check_fires(ctx, payload)
            if fires:
                fired += 1
            else:
                reason = _categorize_failure(ctx, payload)
                failures.append({"context_id": ctx.id, "payload": payload[:100], "reason": reason})
        else:
            failures.append({"context_id": ctx.id, "payload": "", "reason": "no_payload"})

        cid = ctx.id
        if cid not in per_context:
            per_context[cid] = {"total": 0, "fired": 0}
        per_context[cid]["total"] += 1
        if fires:
            per_context[cid]["fired"] += 1

        if (i + 1) % 20 == 0:
            print(f"  T1: {i+1}/{len(pairs)} checked, {fired} fired")

    for cid, stats in per_context.items():
        stats["rate"] = stats["fired"] / stats["total"] if stats["total"] else 0.0

    rate = fired / tested if tested else 0.0
    print(f"[T1] {fired}/{tested} = {rate:.1%} (target {T1_TARGET:.0%})")

    return {
        "total": tested, "fired": fired, "rate": rate,
        "target": T1_TARGET, "passed": rate >= T1_TARGET,
        "per_context": per_context, "failures": failures,
        "generated_payloads": all_payloads,
    }


def _run_t2(model, tokenizer, config: EvalConfig) -> dict:
    """T2: held-out filter combinations not in training."""
    import itertools

    from ..filter_harness import load_contexts

    training = load_contexts(Path(config.contexts_yaml))
    training_keys = {(c.location, tuple(sorted(c.filters))) for c in training}

    held_out = []
    seen = set()
    for location in _T2_LOCATIONS:
        for size in (1, 2):
            for combo in itertools.combinations(_T2_FILTERS, size):
                key = (location, tuple(sorted(combo)))
                if key in training_keys or key in seen:
                    continue
                seen.add(key)
                ctx = ContextSpec(id=f"heldout-{location}-{'-'.join(sorted(combo))}",
                                  location=location, filters=list(combo))
                ctx.description = render_description(ctx)
                held_out.append(ctx)
                if len(held_out) >= config.max_t2:
                    break
            if len(held_out) >= config.max_t2:
                break
        if len(held_out) >= config.max_t2:
            break

    print(f"[T2] {len(held_out)} held-out contexts generated")

    per_context: dict[str, dict] = {}
    failures: list[dict] = []
    fired = 0
    tested = 0

    for ctx in held_out:
        desc = ctx.description or render_description(ctx)
        payloads = generate(model, tokenizer, desc, strategy="greedy", n=1)
        payload = payloads[0] if payloads else None

        tested += 1
        fires = False
        if payload:
            fires = check_fires(ctx, payload)
            if fires:
                fired += 1
            else:
                failures.append({"context_id": ctx.id, "payload": payload[:100], "reason": "no_redirect"})

        per_context[ctx.id] = {"total": 1, "fired": 1 if fires else 0,
                               "rate": 1.0 if fires else 0.0}

    rate = fired / tested if tested else 0.0
    print(f"[T2] {fired}/{tested} = {rate:.1%} (target {T2_TARGET:.0%})")

    return {
        "total": tested, "fired": fired, "rate": rate,
        "target": T2_TARGET, "passed": rate >= T2_TARGET,
        "per_context": per_context, "failures": failures,
    }


def _run_secondary(model, tokenizer, t1_results: dict, config: EvalConfig) -> dict:
    """Secondary metrics: valid URL rate, diversity, refusal."""
    import re
    payloads = t1_results.get("generated_payloads", [])
    # An open redirect payload is "valid" if it is URL-like: has a scheme OR is
    # protocol-relative (//) — i.e. plausibly a redirect target.
    _URL_RE = re.compile(r"^\s*(//|[a-zA-Z][a-zA-Z0-9+.\-]*://)", re.IGNORECASE)
    valid = sum(1 for p in payloads if _URL_RE.match(p))
    syntax_rate = valid / len(payloads) if payloads else 0.0
    print(f"[valid_url] {syntax_rate:.1%} (target {VALID_URL_TARGET:.0%})")

    diversity_desc = "The URL is taken from a query parameter for redirect (e.g. ?redirect=INPUT)."
    diversity_payloads = generate(model, tokenizer, diversity_desc,
                                  strategy="sampling", n=config.diversity_samples)
    if diversity_payloads:
        normalized = [normalize_for_dedup(p) for p in diversity_payloads]
        unique = len(set(normalized))
        div_score = unique / len(diversity_payloads) if len(diversity_payloads) > 1 else 1.0
    else:
        div_score = 0.0
    print(f"[diversity] {div_score:.2f} (target {DIVERSITY_TARGET:.2f})")

    ref_patterns = ["i cannot", "i can't", "i'm sorry", "as an ai"]
    ref_rate = sum(1 for p in payloads if any(r in p.lower() for r in ref_patterns)) / len(payloads) if payloads else 0.0
    print(f"[refusal] {ref_rate:.1%}")

    return {
        "valid_url_rate": syntax_rate, "url_target": VALID_URL_TARGET,
        "url_passed": syntax_rate >= VALID_URL_TARGET,
        "diversity_score": div_score, "diversity_target": DIVERSITY_TARGET,
        "diversity_passed": div_score >= DIVERSITY_TARGET,
        "refusal_rate": ref_rate,
    }


def run_evaluation(model, tokenizer, config: EvalConfig) -> dict:
    """Full evaluation: T1 + T2 + secondary metrics."""
    test_pairs = []
    test_path = Path(config.test_path)
    for line in test_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            test_pairs.append(json.loads(line))
    print(f"[load] {len(test_pairs)} test pairs from {test_path}")

    results = {"model_path": config.model_path}

    print("[T1] Running synthetic eval...")
    results["t1"] = _run_t1(model, tokenizer, test_pairs, config)
    print("[T2] Running held-out combo eval...")
    results["t2"] = _run_t2(model, tokenizer, config)
    print("[secondary] Computing metrics...")
    results["secondary"] = _run_secondary(model, tokenizer, results["t1"], config)

    return results
