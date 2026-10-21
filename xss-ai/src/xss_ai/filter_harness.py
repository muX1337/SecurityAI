"""Source 1: generate (context, payload) pairs via deterministic filter simulation."""
from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from .can_fire import can_fire
from .context import ContextSpec, render_description, simulate_reflection
from .pair_schema import Pair, Provenance


def load_contexts(path: Path) -> list[ContextSpec]:
    """Load ContextSpec list from a contexts.yaml file."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    out: list[ContextSpec] = []
    for raw in data.get("contexts", []):
        ctx = ContextSpec(**raw)
        ctx.description = render_description(ctx)  # materialize
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
    """For each context, run each payload through filters+can-fire; keep survivors.

    Within a context, payloads that normalize to the same form (differing only
    in case/whitespace) are deduped — keeping only the first — so the harness
    never emits near-duplicate pairs like <script>alert(1)</script> and
    <SCRIPT>alert(1)</SCRIPT> under the same context.
    """
    import random
    import re
    rng = random.Random(seed)

    def _norm(s: str) -> str:
        return re.sub(r"\s+", "", s.strip().lower())

    pairs: list[Pair] = []
    for ctx in contexts:
        # Materialize the rendered description so downstream consumers (and the
        # serialized Pair) always carry the natural-language prompt.
        if ctx.description is None:
            ctx.description = render_description(ctx)
        survivors: list[Pair] = []
        seen: set[str] = set()
        for payload in payloads:
            # Server-side pipeline: encode, then filter.
            filtered = simulate_reflection(ctx, payload)
            if not filtered:
                continue
            if not can_fire(filtered, ctx.location):
                continue
            n = _norm(payload)
            if n in seen:
                continue
            seen.add(n)
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
