"""Source 1: generate (context, payload) pairs via SSTI filter simulation.

For each context, run each payload through the context's filters; keep it as a
pair only if it SURVIVES the filters AND plausibly fires (can_fire) at the
context's location. The oracle is the final arbiter; the harness is the cheap
deterministic pre-filter that produces the bulk training data.
"""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

import yaml

from .can_fire import can_fire
from .context import ContextSpec, render_description, simulate_reflection
from .pair_schema import Pair, Provenance
from .splits import normalize_for_dedup


def load_contexts(path: Path) -> list[ContextSpec]:
    """Load ContextSpec list from a ssti_contexts.yaml file."""
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
    """For each context, run each payload through filters + oracle; keep survivors.

    A pair is kept only if the payload (a) survives the context's filters,
    (b) plausibly fires at the location (cheap can_fire pre-filter), and
    (c) is confirmed to evaluate by the oracle. Grounding the harness in the
    oracle keeps filter-sim/oracle agreement high by construction.
    """
    from .oracle.check_fires import check_fires

    rng = random.Random(seed)

    pairs: list[Pair] = []
    for ctx in contexts:
        if ctx.description is None:
            ctx.description = render_description(ctx)
        survivors: list[Pair] = []
        seen_norm: set[str] = set()
        for payload in payloads:
            filtered = simulate_reflection(ctx, payload)
            if not filtered:
                continue
            if not can_fire(filtered, ctx.location):
                continue
            if not check_fires(ctx, payload):
                continue
            norm = normalize_for_dedup(payload)
            if norm in seen_norm:
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
