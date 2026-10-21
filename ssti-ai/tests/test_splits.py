from ssti_ai.context import ContextSpec
from ssti_ai.pair_schema import Pair, Provenance
from ssti_ai.splits import (
    SPLIT_RATIOS,
    normalize_for_dedup,
    run_quality_gates,
    stratified_split,
)


def _pair(ctx_id, loc, payload):
    ctx = ContextSpec(id=ctx_id, location=loc)
    ctx.description = "d"
    return Pair(id=f"{ctx_id}-{payload}", context=ctx, payload=payload,
                provenance=Provenance(source="filter_harness", verified_by="filter_sim"))


def test_normalize_lowercases_and_strips():
    assert normalize_for_dedup("  {{7*7}}  ") == "{{7*7}}"

def test_split_ratios_sum_to_one():
    assert abs(sum(SPLIT_RATIOS.values()) - 1.0) < 1e-9

def test_stratified_split_sizes():
    pairs = []
    for i in range(100):
        pairs.append(_pair("c1", "jinja2_body", f"{{{{7*{i}}}}}"))
    splits = stratified_split(pairs, seed=0)
    total = sum(len(v) for v in splits.values())
    assert total == 100

def test_stratified_split_no_overlap():
    pairs = [_pair("c1", "jinja2_body", f"{{{{p{i}}}}}") for i in range(50)]
    splits = stratified_split(pairs, seed=0)
    payloads_train = {normalize_for_dedup(p.payload) for p in splits["train"]}
    payloads_test = {normalize_for_dedup(p.payload) for p in splits["test"]}
    assert not (payloads_train & payloads_test)

def test_quality_gates_pass_on_clean_split():
    pairs = []
    for ci in range(15):
        for i in range(5):
            pairs.append(_pair(f"ctx{ci}", "jinja2_body", f"{{{{7*{ci}_{i}}}}}"))
    splits = stratified_split(pairs, seed=0)
    report = run_quality_gates(
        splits["train"], splits["test"],
        min_train_pairs=20, min_contexts=5, max_context_fraction=0.12,
    )
    assert report["passed"] is True, report["violations"]

def test_quality_gates_fail_on_few_contexts():
    pairs = [_pair("c1", "jinja2_body", f"{{{{p{i}}}}}") for i in range(100)]
    splits = stratified_split(pairs, seed=0)
    report = run_quality_gates(splits["train"], splits["test"], min_contexts=10)
    assert report["passed"] is False
