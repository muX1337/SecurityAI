"""Source 1: generate (context, payload) pairs via CRLF filter + oracle simulation.

A pair survives iff the payload actually FIRES under the context (the oracle's
check_fires returns True after applying the context's filters and simulating
HTTP response construction). This makes every pair in the dataset a verified,
ground-truth-positive example — the strongest possible training signal.
"""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

import yaml

from .context import ContextSpec, render_description
from .oracle.check_fires import check_fires
from .pair_schema import Pair, Provenance
from .splits import normalize_for_dedup


def load_contexts(path: Path) -> list[ContextSpec]:
    """Load ContextSpec list from a crlf_contexts.yaml file."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    out: list[ContextSpec] = []
    for raw in data.get("contexts", []):
        ctx = ContextSpec(**raw)
        ctx.description = render_description(ctx)
        out.append(ctx)
    return out


def _pair_id(ctx: ContextSpec, payload: str) -> str:
    h = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:8]
    return f"{ctx.id}__pl-{h}"


def generate_pairs(
    contexts: list[ContextSpec],
    payloads: list[str],
    per_context_cap: int = 300,
    seed: int = 0,
) -> list[Pair]:
    """For each context, keep payloads that FIRE under the oracle. Dedup by
    normalized payload within each context."""
    rng = random.Random(seed)

    pairs: list[Pair] = []
    for ctx in contexts:
        if ctx.description is None:
            ctx.description = render_description(ctx)
        survivors: list[Pair] = []
        seen_norm: set[str] = set()
        for payload in payloads:
            norm = normalize_for_dedup(payload)
            if norm in seen_norm:
                continue
            if not check_fires(ctx, payload):
                continue
            seen_norm.add(norm)
            survivors.append(
                Pair(
                    id=_pair_id(ctx, payload),
                    context=ctx,
                    payload=payload,
                    provenance=Provenance(source="filter_harness", verified_by="filter_sim"),
                )
            )
        rng.shuffle(survivors)
        pairs.extend(survivors[:per_context_cap])
    return pairs


def write_pairs_jsonl(pairs: list[Pair], path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for p in pairs:
            f.write(p.to_jsonl() + "\n")
