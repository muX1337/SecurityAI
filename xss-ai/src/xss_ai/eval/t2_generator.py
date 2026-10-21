"""T2: generate held-out filter combinations not in the training taxonomy.

These test model generalization: can it produce payloads for filter combos
it has never seen during training?
"""
from __future__ import annotations

import itertools
from pathlib import Path

from ..context import ContextSpec, render_description
from ..filter_harness import load_contexts

# Filters that make sense as standalone (not just in combos).
_SINGLE_FILTERS = [
    "strip_angle_brackets",
    "block_keyword_script",
    "block_keyword_alert",
    "block_event_handlers",
    "block_keyword_on_prefix",
    "escape_angle_brackets_html",
    "escape_double_quotes_html",
    "escape_single_quotes_html",
    "strip_parentheses",
    "lowercase",
    "strip_backslashes",
]

# Locations where breakout is plausible (skip html_comment, js_string_dq for v1).
_T2_LOCATIONS = ["html_body", "attr_dq", "attr_sq", "js_string_sq", "url_param"]


def generate_held_out_contexts(
    existing_yaml_path: Path,
    max_combos: int = 30,
) -> list[ContextSpec]:
    """Generate filter combinations NOT present in the training taxonomy.

    Args:
        existing_yaml_path: path to contexts.yaml with training contexts.
        max_combos: maximum number of held-out contexts to return.

    Returns:
        List of ContextSpec with descriptions, none overlapping with training.
    """
    training = load_contexts(existing_yaml_path)
    training_keys: set[tuple[str, tuple[str, ...]]] = {
        (c.location, tuple(sorted(c.filters))) for c in training
    }

    # Build candidate combos grouped per location, so we can interleave
    # (round-robin) across locations and guarantee multi-location coverage
    # rather than exhausting max_combos inside a single high-yield location.
    per_location: dict[str, list[ContextSpec]] = {loc: [] for loc in _T2_LOCATIONS}
    seen: set[tuple[str, tuple[str, ...]]] = set()

    for location in _T2_LOCATIONS:
        for size in (1, 2):
            for combo in itertools.combinations(_SINGLE_FILTERS, size):
                key = (location, tuple(sorted(combo)))
                if key in training_keys or key in seen:
                    continue
                seen.add(key)

                encoding = ["url_decode"] if location == "url_param" else []
                ctx = ContextSpec(
                    id=f"heldout-{location}-{'-'.join(sorted(combo))}",
                    location=location,
                    encoding=encoding,
                    filters=list(combo),
                )
                ctx.description = render_description(ctx)
                per_location[location].append(ctx)

    # Round-robin across locations to maximize location diversity.
    held_out: list[ContextSpec] = []
    idx = 0
    active = [loc for loc in _T2_LOCATIONS if per_location[loc]]
    while len(held_out) < max_combos and active:
        progressed = False
        next_active: list[str] = []
        for loc in active:
            buckets = per_location[loc]
            if idx < len(buckets):
                held_out.append(buckets[idx])
                progressed = True
                next_active.append(loc)
                if len(held_out) >= max_combos:
                    break
        idx += 1
        if not progressed:
            break
        active = next_active

    return held_out
