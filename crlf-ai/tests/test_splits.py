from crlf_ai.context import ContextSpec
from crlf_ai.pair_schema import Pair, Provenance
from crlf_ai.splits import (
    SPLIT_RATIOS,
    check_leakage,
    normalize_for_dedup,
    run_quality_gates,
    stratified_split,
)


def _pair(ctx_id, loc, payload):
    ctx = ContextSpec(id=ctx_id, location=loc)
    ctx.description = "d"
    return Pair(id=f"{ctx_id}-{payload}", context=ctx, payload=payload,
                provenance=Provenance(source="filter_harness", verified_by="filter_sim"))


def test_normalize_lowercases_and_strips_whitespace():
    # normalize_for_dedup strips ALL whitespace and lowercases
    assert normalize_for_dedup("  %0D%0A Set-Cookie: EVIL=1  ") == "%0d%0aset-cookie:evil=1"


def test_split_ratios_sum_to_one():
    assert abs(sum(SPLIT_RATIOS.values()) - 1.0) < 1e-9


def test_stratified_split_preserves_all_pairs():
    pairs = []
    for i in range(100):
        pairs.append(_pair("c1", "response_header", f"%0d%0aSet-Cookie: evil={i}"))
    splits = stratified_split(pairs, seed=0)
    total = sum(len(v) for v in splits.values())
    assert total == 100
    assert set(splits.keys()) == {"train", "val", "test"}


def test_stratified_split_no_payload_overlap():
    pairs = [_pair("c1", "response_header", f"%0d%0aSet-Cookie: p{i}=1") for i in range(50)]
    splits = stratified_split(pairs, seed=0)
    payloads_train = {normalize_for_dedup(p.payload) for p in splits["train"]}
    payloads_test = {normalize_for_dedup(p.payload) for p in splits["test"]}
    assert not (payloads_train & payloads_test)


def test_stratified_split_same_payload_goes_to_one_split():
    # Two pairs with the same payload (different contexts) -> same split.
    payload = "%0d%0aSet-Cookie: shared=1"
    pairs = [
        _pair("c1", "response_header", payload),
        _pair("c2", "set_cookie", payload),
    ]
    splits = stratified_split(pairs, seed=0)
    locations = []
    for split_name in ("train", "val", "test"):
        if any(normalize_for_dedup(p.payload) == normalize_for_dedup(payload)
               for p in splits[split_name]):
            locations.append(split_name)
    assert len(locations) == 1


def test_check_leakage_empty_on_clean_split():
    train = [_pair("c1", "response_header", "%0d%0aSet-Cookie: a=1")]
    test = [_pair("c1", "response_header", "%0d%0aSet-Cookie: b=2")]
    assert check_leakage(train, test) == []


def test_check_leakage_detects_shared_payload():
    train = [_pair("c1", "response_header", "%0d%0aSet-Cookie: a=1")]
    test = [_pair("c1", "response_header", "%0d%0aSet-Cookie: a=1")]
    leaked = check_leakage(train, test)
    assert len(leaked) == 1


def test_quality_gates_pass_on_clean_split():
    pairs = []
    for ci in range(15):
        for i in range(5):
            pairs.append(_pair(f"ctx{ci}", "response_header",
                               f"%0d%0aSet-Cookie: evil={ci}_{i}"))
    splits = stratified_split(pairs, seed=0)
    report = run_quality_gates(
        splits["train"], splits["test"],
        min_train_pairs=20, min_contexts=5, max_context_fraction=0.12,
    )
    assert report["passed"] is True, report["violations"]


def test_quality_gates_fail_on_few_contexts():
    pairs = [_pair("c1", "response_header", f"%0d%0aSet-Cookie: p{i}=1") for i in range(100)]
    splits = stratified_split(pairs, seed=0)
    report = run_quality_gates(splits["train"], splits["test"], min_contexts=10)
    assert report["passed"] is False


def test_quality_gates_fail_on_too_few_pairs():
    pairs = [_pair(f"c{i}", "response_header", f"%0d%0aSet-Cookie: p{i}=1") for i in range(15)]
    splits = stratified_split(pairs, seed=0)
    report = run_quality_gates(splits["train"], splits["test"], min_train_pairs=500)
    assert report["passed"] is False


def test_quality_gates_fail_on_imbalanced_context():
    # One context dominates -> balance violation.
    pairs = [_pair("big", "response_header", f"%0d%0aSet-Cookie: p{i}=1") for i in range(100)]
    pairs += [_pair(f"c{i}", "response_header", f"%0d%0aSet-Cookie: q{i}=1") for i in range(5)]
    splits = stratified_split(pairs, seed=0)
    report = run_quality_gates(splits["train"], splits["test"], max_context_fraction=0.08)
    assert report["passed"] is False
