"""Partition pairs into train/val/test with dedup, leakage guards, and quality gates."""
from __future__ import annotations

import collections
import random
import re

from .pair_schema import Pair

SPLIT_RATIOS = {"train": 0.80, "val": 0.10, "test": 0.10}

# Gate thresholds (from spec Section 2).
MAX_CONTEXT_FRACTION = 0.08
MIN_TRAIN_PAIRS = 500
MIN_CONTEXTS = 10


def normalize_for_dedup(payload: str) -> str:
    """Normalize for dedup/leakage: lowercase, strip whitespace."""
    return re.sub(r"\s+", "", payload.strip().lower())


def stratified_split(pairs: list[Pair], seed: int = 0) -> dict[str, list[Pair]]:
    """Split by PAYLOAD, then carry every pair with that payload along.

    Each distinct normalized payload is assigned to exactly one split
    (train/val/test) according to SPLIT_RATIOS. Every pair containing that
    payload goes to the same split. This:
      - preserves all cross-context pairs (no data loss),
      - eliminates train/test leakage by construction (a payload can't be in
        two splits),
      - keeps same-payload-different-context pairs together (they are valuable
        signal, not duplicates).
    """
    rng = random.Random(seed)

    # Collect distinct normalized payloads, preserving first-seen order.
    payload_order: list[str] = []
    seen: set[str] = set()
    for p in pairs:
        n = normalize_for_dedup(p.payload)
        if n not in seen:
            seen.add(n)
            payload_order.append(n)

    # Assign each payload to a split by position (shuffle first for randomness).
    rng.shuffle(payload_order)
    payload_to_split: dict[str, str] = {}
    n = len(payload_order)
    n_test = round(n * SPLIT_RATIOS["test"])
    n_val = round(n * SPLIT_RATIOS["val"])
    for i, pl in enumerate(payload_order):
        if i < n_test:
            payload_to_split[pl] = "test"
        elif i < n_test + n_val:
            payload_to_split[pl] = "val"
        else:
            payload_to_split[pl] = "train"

    out: dict[str, list[Pair]] = {"train": [], "val": [], "test": []}
    for p in pairs:
        n = normalize_for_dedup(p.payload)
        out[payload_to_split[n]].append(p)
    return out


def check_leakage(train: list[Pair], test: list[Pair]) -> list[str]:
    """Return list of normalized payloads appearing in both train and test."""
    train_norm = {normalize_for_dedup(p.payload) for p in train}
    leaked = []
    seen = set()
    for p in test:
        n = normalize_for_dedup(p.payload)
        if n in train_norm and n not in seen:
            leaked.append(n)
            seen.add(n)
    return leaked


def run_quality_gates(
    train: list[Pair],
    test: list[Pair],
    *,
    max_context_fraction: float = MAX_CONTEXT_FRACTION,
    min_train_pairs: int = MIN_TRAIN_PAIRS,
    min_contexts: int = MIN_CONTEXTS,
) -> dict:
    """Run all 5 spec gates. Returns {passed, violations, stats}.

    Thresholds default to the spec values (Section 2). They are exposed as
    keyword args so callers can tune them (e.g. unit tests on small synthetic
    fixtures); production runs use the defaults, which correctly flag the v1
    dataset as needing more data before training.
    """
    violations: list[str] = []
    stats: dict = {}

    # Gate 1: context balance (no single context > max_context_fraction of train)
    counts = collections.Counter(p.context.id for p in train)
    total = len(train)
    stats["context_counts"] = dict(counts)
    for ctx_id, c in counts.items():
        frac = c / total if total else 0
        if frac > max_context_fraction:
            violations.append(
                f"balance: context {ctx_id!r} is {frac:.1%} of train (max {max_context_fraction:.0%})"
            )

    # Gate 2: filter-sim/browser agreement is enforced by scripts/03 (not here).

    # Gate 3: dedup — no exact-duplicate (payload, context) pair within train.
    # Same payload under DIFFERENT contexts is legitimate signal (the model
    # learns context-dependent generation), so only flag a payload repeated
    # under the SAME context.
    pair_keys = [(normalize_for_dedup(p.payload), p.context.id) for p in train]
    dup_keys = {k for k, c in collections.Counter(pair_keys).items() if c > 1}
    if dup_keys:
        violations.append(f"dedup: {len(dup_keys)} duplicate (payload, context) pairs in train")

    # Gate 4: no leakage between train and test
    leaked = check_leakage(train, test)
    if leaked:
        violations.append(f"leakage: {len(leaked)} test payloads also in train")

    # Gate 5: minimum volume + distinct contexts
    if len(train) < min_train_pairs:
        violations.append(f"volume: train has {len(train)} pairs (min {min_train_pairs})")
    if len(counts) < min_contexts:
        violations.append(f"contexts: {len(counts)} distinct contexts (min {min_contexts})")

    return {"passed": len(violations) == 0, "violations": violations, "stats": stats}
