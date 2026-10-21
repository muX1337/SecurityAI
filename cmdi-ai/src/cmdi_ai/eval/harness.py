"""CMDi evaluation harness: T1 (synthetic) + T2 (held-out) + metrics."""
from __future__ import annotations

import itertools
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path

from ..can_fire import can_fire
from ..context import ContextSpec, render_description, simulate_reflection
from ..filter_harness import load_contexts
from ..generate import generate
from ..oracle.check_fires import OracleSession
from ..splits import normalize_for_dedup

T1_TARGET = 0.60
T2_TARGET = 0.30
VALID_CMD_TARGET = 0.90
DIVERSITY_TARGET = 0.70

@dataclass
class EvalConfig:
    model_path: str = "models/cmdi-qwen1.5b-v1/final"
    test_path: str = "data/pairs/test.jsonl"
    contexts_yaml: str = "data/contexts/cmdi_contexts.yaml"
    max_t1: int = 0
    max_t2: int = 10
    diversity_samples: int = 10
    seed: int = 42

def _categorize_failure(ctx, payload):
    if not payload or not payload.strip():
        return "no_payload"
    if not simulate_reflection(ctx, payload):
        return "blocked_by_filter"
    if not can_fire(payload, ctx.location):
        return "invalid_cmd"
    return "no_execution"

def _run_t1(model, tokenizer, oracle, test_pairs, config):
    rng = random.Random(config.seed)
    pairs = test_pairs
    if config.max_t1 > 0:
        pairs = rng.sample(test_pairs, min(config.max_t1, len(test_pairs)))
    per_context = {}
    failures = []
    all_payloads = []
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
            fires = oracle.check_fires(ctx, payload)
            if fires:
                fired += 1
            else:
                failures.append({"context_id": ctx.id, "payload": payload[:100], "reason": _categorize_failure(ctx, payload)})
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
    return {"total": tested, "fired": fired, "rate": rate, "target": T1_TARGET,
            "passed": rate >= T1_TARGET, "per_context": per_context, "failures": failures,
            "generated_payloads": all_payloads}

def _run_t2(model, tokenizer, oracle, config):
    training = load_contexts(Path(config.contexts_yaml))
    training_keys = {(c.location, tuple(sorted(c.filters))) for c in training}
    _FILTERS = ["block_semicolon", "block_pipe", "block_ampersand", "block_backtick",
                "block_dollar", "block_redirect", "block_keywords", "alphanumeric_only"]
    _T2_LOCATIONS = ["shell_arg", "shell_command", "filename_arg"]
    held_out = []
    seen = set()
    for location in _T2_LOCATIONS:
        for size in (1, 2):
            for combo in itertools.combinations(_FILTERS, size):
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
    print(f"[T2] {len(held_out)} held-out contexts")
    per_context = {}
    failures = []
    fired = 0
    tested = 0
    for ctx in held_out:
        desc = ctx.description or render_description(ctx)
        payloads = generate(model, tokenizer, desc, strategy="greedy", n=1)
        payload = payloads[0] if payloads else None
        tested += 1
        fires = False
        if payload:
            fires = oracle.check_fires(ctx, payload)
            if fires:
                fired += 1
            else:
                failures.append({"context_id": ctx.id, "payload": payload[:100], "reason": "no_execution"})
        per_context[ctx.id] = {"total": 1, "fired": 1 if fires else 0, "rate": 1.0 if fires else 0.0}
    rate = fired / tested if tested else 0.0
    print(f"[T2] {fired}/{tested} = {rate:.1%} (target {T2_TARGET:.0%})")
    return {"total": tested, "fired": fired, "rate": rate, "target": T2_TARGET,
            "passed": rate >= T2_TARGET, "per_context": per_context, "failures": failures}

def _run_secondary(model, tokenizer, t1_results, config):
    payloads = t1_results.get("generated_payloads", [])
    # A valid command-injection payload contains a shell metacharacter or encoded newline.
    _CMD_RE = re.compile(r"[;|&`$<>]|%0[ad]|\$\(", re.IGNORECASE)
    valid = sum(1 for p in payloads if _CMD_RE.search(p)) if payloads else 0
    syntax_rate = valid / len(payloads) if payloads else 0.0
    print(f"[valid_cmd] {syntax_rate:.1%} (target {VALID_CMD_TARGET:.0%})")
    div_desc = "Input is passed as an argument to a shell command (e.g. ping INPUT)."
    div_payloads = generate(model, tokenizer, div_desc, strategy="sampling", n=config.diversity_samples)
    if div_payloads:
        unique = len({normalize_for_dedup(p) for p in div_payloads})
        div_score = unique / len(div_payloads) if len(div_payloads) > 1 else 1.0
    else:
        div_score = 0.0
    print(f"[diversity] {div_score:.2f} (target {DIVERSITY_TARGET:.2f})")
    ref_patterns = ["i cannot", "i can't", "i'm sorry", "as an ai"]
    ref_rate = sum(1 for p in payloads if any(r in p.lower() for r in ref_patterns)) / len(payloads) if payloads else 0.0
    print(f"[refusal] {ref_rate:.1%}")
    return {"valid_cmd_rate": syntax_rate, "cmd_target": VALID_CMD_TARGET,
            "cmd_passed": syntax_rate >= VALID_CMD_TARGET,
            "diversity_score": div_score, "diversity_target": DIVERSITY_TARGET,
            "diversity_passed": div_score >= DIVERSITY_TARGET, "refusal_rate": ref_rate}

def run_evaluation(model, tokenizer, config):
    test_pairs = [json.loads(l) for l in Path(config.test_path).read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"[load] {len(test_pairs)} test pairs")
    results = {"model_path": config.model_path}
    with OracleSession() as oracle:
        print("[T1] Running synthetic eval...")
        results["t1"] = _run_t1(model, tokenizer, oracle, test_pairs, config)
        print("[T2] Running held-out eval...")
        results["t2"] = _run_t2(model, tokenizer, oracle, config)
    print("[secondary] Computing metrics...")
    results["secondary"] = _run_secondary(model, tokenizer, results["t1"], config)
    return results
