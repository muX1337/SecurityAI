from pathlib import Path

import pytest
from xss_ai.eval.t2_generator import generate_held_out_contexts
from xss_ai.filter_harness import load_contexts


@pytest.fixture
def training_contexts():
    """Load the actual training taxonomy."""
    return load_contexts(Path("data/contexts/contexts.yaml"))

def test_generates_contexts():
    ctxs = generate_held_out_contexts(Path("data/contexts/contexts.yaml"), max_combos=10)
    assert len(ctxs) > 0
    assert len(ctxs) <= 10

def test_no_overlap_with_training(training_contexts):
    """Generated combos must NOT match any existing training context."""
    held_out = generate_held_out_contexts(Path("data/contexts/contexts.yaml"), max_combos=30)
    training_keys = {(c.location, tuple(sorted(c.filters))) for c in training_contexts}
    for ctx in held_out:
        key = (ctx.location, tuple(sorted(ctx.filters)))
        assert key not in training_keys, f"{ctx.id} overlaps with training"

def test_covers_multiple_locations():
    """Held-out contexts should span multiple locations, not just one."""
    held_out = generate_held_out_contexts(Path("data/contexts/contexts.yaml"), max_combos=30)
    locations = {c.location for c in held_out}
    assert len(locations) >= 3

def test_contexts_have_descriptions():
    """Each held-out context must have a rendered description for the model prompt."""
    held_out = generate_held_out_contexts(Path("data/contexts/contexts.yaml"), max_combos=5)
    for ctx in held_out:
        assert ctx.description is not None
        assert len(ctx.description) > 0

def test_contexts_have_valid_ids():
    held_out = generate_held_out_contexts(Path("data/contexts/contexts.yaml"), max_combos=5)
    for ctx in held_out:
        assert ctx.id.startswith("heldout-")
